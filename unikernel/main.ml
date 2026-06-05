module Blk = struct
  type t = Mkernel.Block.t

  let pagesize = Mkernel.Block.pagesize
  let read = Mkernel.Block.atomic_read
  let write = Mkernel.Block.atomic_write
end

module Fat = Mfat.Make (Blk)
module Bos = Mfat_bos.Make (Blk)
module RNG = Mirage_crypto_rng.Fortuna

let ( let@ ) finally fn = Fun.protect ~finally fn
let ( let* ) = Result.bind
let msg msg = `Msg msg
let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt
let ( / ) = Filename.concat
let inhibit fn = try fn () with _exn -> ()
let rng () = Mirage_crypto_rng_mkernel.initialize (module RNG)
let rng = Mkernel.map rng Mkernel.[]

module Cfg = struct
  type t = { destination: Ipaddr.t; port: int; protocol: [ `HTTP_1_1 | `H2 ] }

  let json =
    let open Jsont in
    let ipaddr = map ~dec:Ipaddr.of_string_exn ~enc:Ipaddr.to_string string in
    let destination =
      Object.mem "destination"
        ~enc:(fun { destination; _ } -> destination)
        ipaddr
    in
    let port = Object.mem "port" ~enc:(fun { port; _ } -> port) int in
    let protocol = enum [ ("http/1.1", `HTTP_1_1); ("h2", `H2) ] in
    let protocol =
      Object.mem "protocol" ~enc:(fun { protocol; _ } -> protocol) protocol
    in
    Object.map (fun destination port protocol ->
        { destination; port; protocol })
    |> destination
    |> port
    |> protocol
    |> Object.finish

  let decode str = Jsont_bytesrw.decode_string json str |> Result.map_error msg
  let encode t = Jsont_bytesrw.encode_string json t |> Result.get_ok

  let pp ppf t =
    match t.protocol with
    | `HTTP_1_1 -> Fmt.pf ppf "http://%a:%d" Ipaddr.pp t.destination t.port
    | `H2 -> Fmt.pf ppf "h2://%a:%d" Ipaddr.pp t.destination t.port
end

let fat ~name =
  let fn blk () =
    let v = Fat.create blk in
    let v = Result.map_error (fun (`Msg msg) -> msg) v in
    Result.error_to_failure v
  in
  Mkernel.map fn [ Mkernel.block name ]

let _5s = 5_000_000_000

let rec clean_up orphans =
  match Miou.care orphans with
  | Some None | None -> ()
  | Some (Some prm) ->
      let on_error exn =
        Logs.err (fun m ->
            m "Unexpected exception from a promise: %s" (Printexc.to_string exn))
      in
      let result = Miou.await prm in
      Result.iter_error on_error result;
      clean_up orphans

let must_exist fs name =
  if Fat.exists fs name then Ok () else error_msgf "%s does not exist" name

let entries_of_fs fs =
  let entries = Fat.ls fs "" in
  let fn = function
    | { Mfat.name; is_dir= true; _ } ->
        let* hostname = Domain_name.of_string name in
        let* hostname = Domain_name.host hostname in
        let* () = must_exist fs (name / "pk.pem") in
        let* pk = Fat.read fs (name / "pk.pem") in
        let* pk = X509.Private_key.decode_pem pk in
        let* () = must_exist fs (name / "certs.pem") in
        let* certs = Fat.read fs (name / "certs.pem") in
        let* certs = X509.Certificate.decode_pem_multiple certs in
        Ok (hostname, (certs, pk))
    | _ -> error_msgf "Not a directory"
  in
  let entries = Result.value ~default:[] entries in
  let entries = List.map fn entries in
  let entries = List.map Result.to_option entries in
  List.filter_map Fun.id entries

let cfgs_of_fs ?(has_an_entry = Fun.const true) fs =
  let entries = Fat.ls fs "" in
  let fn = function
    | { Mfat.name; is_dir= true; _ } ->
        let* hostname = Domain_name.of_string name in
        let* hostname = Domain_name.host hostname in
        let* () = must_exist fs (name / "cfg.json") in
        let* str = Fat.read fs (name / "cfg.json") in
        let* cfg = Cfg.decode str in
        Logs.debug (fun m ->
            m "discover a configuration for %a" Domain_name.pp hostname);
        Ok (hostname, cfg)
    | _ -> error_msgf "Not a directory"
  in
  let cfgs = Result.value ~default:[] entries in
  let cfgs = List.map fn cfgs in
  let cfgs = List.map Result.to_option cfgs in
  let cfgs = List.filter_map Fun.id cfgs in
  Logs.debug (fun m -> m "found %d hostname(s)" (List.length cfgs));
  let t = Art.make () in
  let fn (hostname, cfg) =
    let key = Domain_name.to_string hostname in
    Art.insert t (Art.unsafe_key key) cfg;
    if has_an_entry hostname then None else Some hostname
  in
  let without_certs = List.filter_map fn cfgs in
  (t, without_certs)

let add cfgs fs hostname (certs, pk) =
  let name = Domain_name.to_string hostname in
  let _ = Fat.mkdir fs name in
  let _ = Fat.remove fs (name / "pk.pem") in
  let _ = Fat.remove fs (name / "certs.pem") in
  let pk = X509.Private_key.encode_pem pk in
  let certs = X509.Certificate.encode_pem_multiple certs in
  let run () =
    let* () = must_exist fs name in
    let* () = Fat.write fs (name / "pk.pem") pk in
    let* () = Fat.write fs (name / "certs.pem") certs in
    let* str = Fat.read fs (name / "cfg.json") in
    Cfg.decode str
  in
  match run () with
  | Ok cfg ->
      let key = Domain_name.to_string hostname in
      Art.insert cfgs (Art.unsafe_key key) cfg
  | Error (`Msg msg) ->
      Logs.err (fun m ->
          m "Impossible to write a new entry (%a): %s" Domain_name.pp hostname
            msg)

let is_connection_specific = function
  | "connection" | "proxy-connection" | "keep-alive" | "transfer-encoding"
  | "upgrade" ->
      true
  | _ -> false

let v1v1 _cfg reqd flow =
  let request = H1.Reqd.request reqd in
  let hdrs = request.H1.Request.headers in
  let hdrs = H1.Headers.add_unless_exists hdrs "X-Forwarded-Proto" "https" in
  let request = { request with H1.Request.headers= hdrs } in
  let pipe src dst =
    let rec on_eof () = H1.Body.Writer.close dst
    and on_read buf ~off ~len =
      H1.Body.Writer.write_bigstring dst ~off ~len buf;
      H1.Body.Reader.schedule_read src ~on_eof ~on_read
    in
    H1.Body.Reader.schedule_read src ~on_eof ~on_read
  in
  let handler reqd resp src =
    let dst = H1.Reqd.respond_with_streaming reqd resp in
    pipe src dst
  in
  let dst, conn =
    H1.Client_connection.request ~error_handler:ignore
      ~response_handler:(handler reqd) request
  in
  let cfg = H1.Config.default in
  let read_buffer_size = cfg.H1.Config.read_buffer_size in
  let prm0 = HTTP.C.run conn ~read_buffer_size flow in
  let prm1 = Miou.async @@ fun () -> pipe (H1.Reqd.request_body reqd) dst in
  match Miou.await_all [ prm0; prm1 ] with
  | [ Error exn; _ ] | [ _; Error exn ] ->
      let _, (peer, port) = Mnet.TCP.peers flow in
      Logs.err (fun m ->
          m "Unexpected exception from %a:%d: %s" Ipaddr.pp peer port
            (Printexc.to_string exn))
  | _ -> ()

let v2v2 _cfg reqd flow =
  let request = H2.Reqd.request reqd in
  let hdrs = request.H2.Request.headers in
  let hdrs = H2.Headers.add_unless_exists hdrs "X-Forwarded-Proto" "https" in
  let request = { request with H2.Request.headers= hdrs } in
  let pipe src dst =
    let rec on_eof () = H2.Body.Writer.close dst
    and on_read buf ~off ~len =
      H2.Body.Writer.write_bigstring dst ~off ~len buf;
      H2.Body.Reader.schedule_read src ~on_eof ~on_read
    in
    H2.Body.Reader.schedule_read src ~on_eof ~on_read
  in
  let handler reqd resp src =
    let dst = H2.Reqd.respond_with_streaming reqd resp in
    pipe src dst
  in
  let conn = H2.Client_connection.create ~error_handler:ignore () in
  let dst =
    H2.Client_connection.request conn request ~error_handler:ignore
      ~response_handler:(handler reqd)
  in
  let cfg = H2.Config.default in
  let read_buffer_size = cfg.H2.Config.read_buffer_size in
  let prm0 = HTTP.D.run conn ~read_buffer_size flow in
  let prm1 = Miou.async @@ fun () -> pipe (H2.Reqd.request_body reqd) dst in
  match Miou.await_all [ prm0; prm1 ] with
  | [ Error exn; _ ] | [ _; Error exn ] ->
      let _, (peer, port) = Mnet.TCP.peers flow in
      Logs.err (fun m ->
          m "Unexpected exception from %a:%d: %s" Ipaddr.pp peer port
            (Printexc.to_string exn))
  | _ -> ()

let v2v1 (host : Art.key) _cfg reqd flow =
  let request = H2.Reqd.request reqd in
  let hdrs =
    let fn name value acc =
      if String.length name > 0 && name.[0] = ':' then acc
      else H1.Headers.add acc name value
    in
    H2.Headers.fold ~f:fn ~init:H1.Headers.empty request.H2.Request.headers
  in
  let hdrs = H1.Headers.add_unless_exists hdrs "host" (host :> string) in
  let hdrs = H1.Headers.add_unless_exists hdrs "X-Forwarded-Proto" "https" in
  let pipe src dst =
    let rec on_eof () = H1.Body.Writer.close dst
    and on_read buf ~off ~len =
      H1.Body.Writer.write_bigstring dst ~off ~len buf;
      H2.Body.Reader.schedule_read src ~on_eof ~on_read
    in
    H2.Body.Reader.schedule_read src ~on_eof ~on_read
  in
  let handler reqd (resp : H1.Response.t) src =
    let hdrs =
      let fn name value acc =
        let name = String.lowercase_ascii name in
        (* NOTE(dinosaure): on [h2], some headers (about connection) are
           forbidden. We filter them here. *)
        if is_connection_specific name then acc
        else H2.Headers.add acc name value
      in
      H1.Headers.fold ~f:fn ~init:H2.Headers.empty resp.headers
    in
    let resp = H2.Response.create ~headers:hdrs (resp.status :> H2.Status.t) in
    begin try
      let dst = H2.Reqd.respond_with_streaming reqd resp in
      let rec on_eof () =
        H2.Body.Writer.close dst;
        H2.Body.Writer.flush dst ignore
      and on_read buf ~off ~len =
        H2.Body.Writer.write_bigstring dst ~off ~len buf;
        H1.Body.Reader.schedule_read src ~on_eof ~on_read
      in
      H1.Body.Reader.schedule_read src ~on_eof ~on_read
    with exn ->
      Logs.warn (fun m ->
          m "H2 stream closed before response: %s" (Printexc.to_string exn))
    end
  in
  let request =
    H1.Request.create ~headers:hdrs
      (request.H2.Request.meth :> H1.Method.t)
      request.H2.Request.target
  in
  let dst, conn =
    H1.Client_connection.request ~error_handler:ignore
      ~response_handler:(handler reqd) request
  in
  let cfg = H1.Config.default in
  let read_buffer_size = cfg.H1.Config.read_buffer_size in
  let prm0 = HTTP.C.run conn ~read_buffer_size flow in
  let prm1 = Miou.async @@ fun () -> pipe (H2.Reqd.request_body reqd) dst in
  begin match Miou.await_all [ prm0; prm1 ] with
  | [ Error exn; _ ] | [ _; Error exn ] ->
      let _, (peer, port) = Mnet.TCP.peers flow in
      Logs.err (fun m ->
          m "Unexpected exception from %a:%d: %s" Ipaddr.pp peer port
            (Printexc.to_string exn))
  | _ -> ()
  end

let transmit host cfg reqd flow =
  match reqd with
  | `V1 reqd -> v1v1 cfg reqd flow
  | `V2 reqd when cfg.Cfg.protocol = `H2 -> v2v2 cfg reqd flow
  | `V2 reqd -> v2v1 host cfg reqd flow

let protocols_match cfg = function
  | `V1 _ -> cfg.Cfg.protocol = `HTTP_1_1
  | `V2 _ -> true

let respondf reqd ?(status : H1.Status.t = `OK) fmt =
  let k txt =
    let len = String.length txt in
    let hdrs =
      [
        ("content-type", "text/plain; charset=utf-8")
      ; ("content-length", string_of_int len)
      ]
    in
    match reqd with
    | `V1 reqd ->
        let hdrs = H1.Headers.of_list hdrs in
        let resp = H1.Response.create ~headers:hdrs status in
        H1.Reqd.respond_with_string reqd resp txt
    | `V2 reqd ->
        let hdrs = H2.Headers.of_list hdrs in
        let resp = H2.Response.create ~headers:hdrs (status :> H2.Status.t) in
        H2.Reqd.respond_with_string reqd resp txt
  in
  Fmt.kstr k fmt

let invalid_request reqd =
  respondf reqd ~status:`Bad_request "Invalid request\n"

let not_found reqd = respondf reqd ~status:`Not_found "Host not found\n"

let internal_server_error reqd =
  respondf reqd ~status:`Internal_server_error "Interval server error\n"

let protocols_mismatch reqd =
  respondf reqd ~status:`Bad_request "Protocols mismatch\n"

let handler he cfgs _ reqd =
  let host =
    match reqd with
    | `V1 reqd ->
        let req = H1.Reqd.request reqd in
        let hdrs = req.H1.Request.headers in
        let host = H1.Headers.get hdrs "Host" in
        let fn host = try Some (Art.key host) with _ -> None in
        Option.bind host fn
    | `V2 reqd ->
        let req = H2.Reqd.request reqd in
        let hdrs = req.H2.Request.headers in
        let host =
          match H2.Headers.get hdrs ":authority" with
          | Some _ as v -> v
          | None -> H2.Headers.get hdrs "Host"
        in
        let fn host = try Some (Art.key host) with _ -> None in
        Option.bind host fn
  in
  let cfg = Option.map (fun host -> (host, Art.find_opt cfgs host)) host in
  Logs.debug (fun m ->
      m "Asking for %a" Fmt.(option (using snd (option Cfg.pp))) cfg);
  match cfg with
  | None -> invalid_request reqd
  | Some (_, None) -> not_found reqd
  | Some (host, Some cfg) when protocols_match cfg reqd ->
      let result =
        Mnet_happy_eyeballs.connect_ip he
          [ (cfg.Cfg.destination, cfg.Cfg.port) ]
      in
      begin match result with
      | Ok (_, flow) ->
          let finally = Mnet.TCP.close in
          let res = Miou.Ownership.create ~finally flow in
          Miou.Ownership.own res;
          transmit host cfg reqd flow;
          Miou.Ownership.release res
      | Error _ -> internal_server_error reqd
      end
  | Some (_, Some _) -> protocols_mismatch reqd

let getaddrinfo dns record domain_name =
  let v4tov (_, ipv4s) =
    Ipaddr.V4.Set.fold
      (fun ipv4 -> Ipaddr.Set.add (Ipaddr.V4 ipv4))
      ipv4s Ipaddr.Set.empty
  in
  let v6tov (_, ipv6s) =
    Ipaddr.V6.Set.fold
      (fun ipv6 -> Ipaddr.Set.add (Ipaddr.V6 ipv6))
      ipv6s Ipaddr.Set.empty
  in
  match record with
  | `A -> Result.map v4tov (Mnet_dns.getaddrinfo dns Dns.Rr_map.A domain_name)
  | `AAAA ->
      Result.map v6tov (Mnet_dns.getaddrinfo dns Dns.Rr_map.Aaaa domain_name)

let run _quiet (cidrv4, gateway, ipv6) cfg production nameservers admin_password
    =
  let devices =
    let open Mkernel in
    [ rng; Mnet.stack ~name:"service" ?gateway ~ipv6 cidrv4; fat ~name:"certs" ]
  in
  Mkernel.(run devices) @@ fun rng (stack, tcp, udp) fs () ->
  let@ () = fun () -> Mirage_crypto_rng_mkernel.kill rng in
  let@ () = fun () -> Mnet.kill stack in
  let hed, he = Mnet_happy_eyeballs.create tcp in
  let@ () = fun () -> Mnet_happy_eyeballs.kill hed in
  let dns = Mnet_dns.create ~nameservers (udp, he) in
  Mnet_happy_eyeballs.inject he (getaddrinfo dns);
  let entries = entries_of_fs fs in
  Logs.debug (fun m ->
      m "hostnames: @[<hov>%a@]"
        Fmt.(list ~sep:(any ",") (using fst Domain_name.pp))
        entries);
  let has_an_entry hostname =
    let fn (hostname', _) = Domain_name.equal hostname hostname' in
    List.exists fn entries
  in
  let cfgs, without_certs = cfgs_of_fs ~has_an_entry fs in
  Logs.debug (fun m ->
      m "hostnames without certificates: @[<hov>%a@]"
        Fmt.(list ~sep:(any ",") Domain_name.pp)
        without_certs);
  let t, daemon =
    Contruno.create ~entries ~add:(add cfgs fs) cfg ~production he
  in
  let@ () = fun () -> Contruno.kill daemon in
  List.iter (Contruno.add t) without_certs;
  let add_domain hostname destination port protocol =
    let name = Domain_name.to_string hostname in
    let cfg_value = { Cfg.destination; port; protocol } in
    let _ = Fat.mkdir fs name in
    begin match Fat.write fs (name / "cfg.json") (Cfg.encode cfg_value) with
    | Ok () -> Contruno.add t hostname
    | Error (`Msg msg) ->
        Logs.err (fun m -> m "Impossible to write cfg.json for %s: %s" name msg)
    end
  in
  let remove_domain name =
    let key = Art.unsafe_key name in
    inhibit (fun () -> Art.remove cfgs key);
    match Bos.Dir.delete ~recurse:true fs (Fpath.v name) with
    | Ok () -> ()
    | Error (`Msg msg) ->
        Logs.err (fun m -> m "Impossible to delete %s: %s" name msg)
  in
  let admin_env =
    { Admin.contruno= t; add_domain; remove_domain; password= admin_password }
  in
  let _prm0 = Miou.async @@ fun () -> Admin.run tcp admin_env in
  let rec go orphans listen =
    clean_up orphans;
    let flow = Mnet.TCP.accept tcp listen in
    match Contruno.tls t with
    | Some tls ->
        let _ =
          Miou.async ~orphans @@ fun () ->
          HTTP.with_tls tls flow ~handler:(handler he cfgs)
        in
        go orphans listen
    | None ->
        let _, (peer, port) = Mnet.TCP.peers flow in
        Logs.warn (fun m ->
            m
              "No TLS configuration available, closing incoming connection \
               (%a:%d)"
              Ipaddr.pp peer port);
        Mnet.TCP.close flow;
        Mkernel.sleep _5s;
        go orphans listen
  in
  go (Miou.orphans ()) (Mnet.TCP.listen tcp 443)

open Cmdliner

let output_options = "OUTPUT OPTIONS"
let verbosity = Logs_cli.level ~docs:output_options ()
let renderer = Fmt_cli.style_renderer ~docs:output_options ()

let utf_8 =
  let doc = "Allow binaries to emit UTF-8 characters." in
  Arg.(value & opt bool true & info [ "with-utf-8" ] ~doc)

let t0 = Mkernel.clock_monotonic ()
let neg fn = fun x -> not (fn x)

let reporter sources ppf =
  let re = Option.map Re.compile sources in
  let print src =
    let some re = (neg List.is_empty) (Re.matches re (Logs.Src.name src)) in
    Option.fold ~none:true ~some re
  in
  let report src level ~over k msgf =
    let k _ = over (); k () in
    let pp header _tags k ppf fmt =
      let t1 = Mkernel.clock_monotonic () in
      let delta = Float.of_int (t1 - t0) in
      let delta = delta /. 1_000_000_000. in
      Fmt.kpf k ppf
        ("[+%a][%a]%a[%a]: " ^^ fmt ^^ "\n%!")
        Fmt.(styled `Blue (fmt "%04.04f"))
        delta
        Fmt.(styled `Cyan int)
        (Stdlib.Domain.self () :> int)
        Logs_fmt.pp_header (level, header)
        Fmt.(styled `Magenta string)
        (Logs.Src.name src)
    in
    match (level, print src) with
    | Logs.Debug, false -> k ()
    | _, true | _ -> msgf @@ fun ?header ?tags fmt -> pp header tags k ppf fmt
  in
  { Logs.report }

let regexp =
  let parser str =
    match Re.Pcre.re str with
    | re -> Ok (str, `Re re)
    | exception _ -> error_msgf "Invalid PCRegexp: %S" str
  in
  let pp ppf (str, _) = Fmt.string ppf str in
  Arg.conv (parser, pp)

let sources =
  let doc = "A regexp (PCRE syntax) to identify which log we print." in
  let open Arg in
  value & opt_all regexp [ ("", `None) ] & info [ "l" ] ~doc ~docv:"REGEXP"

let setup_sources = function
  | [ (_, `None) ] -> None
  | res ->
      let res = List.map snd res in
      let res =
        List.fold_left
          (fun acc -> function `Re re -> re :: acc | _ -> acc)
          [] res
      in
      Some (Re.alt res)

let setup_sources = Term.(const setup_sources $ sources)

let setup_logs utf_8 style_renderer sources level =
  Option.iter (Fmt.set_style_renderer Fmt.stdout) style_renderer;
  Fmt.set_utf_8 Fmt.stdout utf_8;
  Logs.set_level level;
  Logs.set_reporter (reporter sources Fmt.stdout);
  Option.is_none level

let setup_logs =
  Term.(const setup_logs $ utf_8 $ renderer $ setup_sources $ verbosity)

let seed =
  let parser str = Base64.decode str in
  let pp = Fmt.(using Base64.encode_string string) in
  Arg.conv (parser, pp)

let key_type =
  let parser str =
    match String.lowercase_ascii str with
    | "ed25519" -> Ok `ED25519
    | "p256" -> Ok `P256
    | "p384" -> Ok `P384
    | "p521" -> Ok `P521
    | "rsa" -> Ok `RSA
    | _ -> error_msgf "Invalid key type: %S" str
  in
  let pp ppf = function
    | `RSA -> Fmt.string ppf "rsa"
    | `P256 -> Fmt.string ppf "P256"
    | `P384 -> Fmt.string ppf "P384"
    | `P521 -> Fmt.string ppf "P521"
    | `ED25519 -> Fmt.string ppf "ED25519"
  in
  Arg.conv (parser, pp)

let bits =
  let parser str =
    match int_of_string_opt str with
    | Some 0 -> error_msgf "0 is an invalid value for bits"
    | Some n when n land (lnot n + 1) = n -> Ok n
    | Some n -> error_msgf "%d is not a power of two" n
    | None -> error_msgf "Invalid bits number: %S" str
  in
  let pp = Fmt.int in
  Arg.conv (parser, pp)

let email =
  let parser str =
    match Emile.of_string str with
    | Ok { Emile.local; domain= domain, _; _ } ->
        Ok { Emile.local; domain= (domain, []); name= None }
    | Error _ -> error_msgf "Invalid email address: %S" str
  in
  let pp = Fmt.(using Emile.to_string string) in
  Arg.conv (parser, pp)

let docs_acme = "ACME"

let email =
  let doc = "Email address to associate to hostnames." in
  let open Arg in
  value
  & opt (some email) None
  & info [ "email" ] ~doc ~docs:docs_acme ~docv:"EMAIL"

let certificate_seed =
  let doc = "The seed (base64 encoded) used for certificates." in
  let open Arg in
  value
  & opt (some seed) None
  & info [ "cert-seed" ] ~doc ~docs:docs_acme ~docv:"SEED"

let certificate_key_type =
  let doc = "The key type for the private key of certificates." in
  let open Arg in
  required
  & opt (some key_type) None
  & info [ "cert-key-type" ] ~doc ~docs:docs_acme ~docv:"KEY-TYPE"

let certificate_key_bits =
  let doc = "The number of bits for the private key of certificates." in
  let open Arg in
  value
  & opt (some bits) None
  & info [ "cert-bits" ] ~doc ~docs:docs_acme ~docv:"BITS"

let account_seed =
  let doc = "The seed (base64 encoded) used for account." in
  let open Arg in
  value
  & opt (some seed) None
  & info [ "account-seed" ] ~doc ~docs:docs_acme ~docv:"SEED"

let account_key_type =
  let doc = "The key type for the acount's private key." in
  let open Arg in
  required
  & opt (some key_type) None
  & info [ "account-key-type" ] ~doc ~docs:docs_acme ~docv:"KEY-TYPE"

let account_key_bits =
  let doc = "The number of bits for the account's private key." in
  let open Arg in
  value
  & opt (some bits) None
  & info [ "account-bits" ] ~doc ~docs:docs_acme ~docv:"BITS"

let setup_cfg email certificate_seed certificate_key_type certificate_key_bits
    account_seed account_key_type account_key_bits =
  {
    Ask.email= Option.map Emile.to_string email
  ; certificate_seed
  ; certificate_key_type
  ; certificate_key_bits
  ; account_seed
  ; account_key_type
  ; account_key_bits
  ; hostnames= []
  }

let setup_cfg =
  let open Term in
  const setup_cfg
  $ email
  $ certificate_seed
  $ certificate_key_type
  $ certificate_key_bits
  $ account_seed
  $ account_key_type
  $ account_key_bits

let production =
  let doc = "Produce production-ready certificates or not" in
  let open Arg in
  value & flag & info [ "production" ] ~doc ~docs:docs_acme

let admin_password =
  let doc = "Password for the admin panel (HTTP Basic Auth)." in
  let open Arg in
  required
  & opt (some string) None
  & info [ "admin-password" ] ~doc ~docv:"PASSWORD"

let term =
  let open Term in
  const run
  $ setup_logs
  $ Mnet_cli.setup
  $ setup_cfg
  $ production
  $ Mnet_cli.setup_nameservers ()
  $ admin_password

let cmd =
  let info =
    Cmd.info "contruno" ~doc:"A TLS termination proxy as an unikernel"
  in
  Cmd.v info term

let () = Cmd.(exit @@ eval cmd)
