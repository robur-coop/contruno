let ( let* ) = Result.bind
let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt
let src = Logs.Src.create "contruno"

module Log = (val Logs.src_log src : Logs.LOG)

type t = {
    mutable entries: entry list
  ; mutable challenges: chain list
  ; pending: [ `host ] Domain_name.t Queue.t
  ; m0: Miou.Mutex.t
  ; m1: Miou.Mutex.t
  ; condition: Miou.Condition.t
  ; cfg: Ask.cfg
  ; add: [ `host ] Domain_name.t -> chain -> unit
}

and chain = X509.Certificate.t list * X509.Private_key.t
and entry = { hostname: [ `host ] Domain_name.t; mutable chain: chain }

let tls t =
  let certs = List.map (fun entry -> entry.chain) t.entries in
  let all = t.challenges @ certs in
  let alpn_protocols = [ "h2"; "http/1.1"; "acme-tls/1" ] in
  match all with
  | [] -> None
  | [ single ] ->
      let certificates = `Single single in
      let tls = Tls.Config.server ~alpn_protocols ~certificates () in
      Result.to_option tls
  | default :: _ ->
      let certificates = `Multiple_default (default, all) in
      let tls = Tls.Config.server ~alpn_protocols ~certificates () in
      Result.to_option tls

let known t hostname =
  let fn value = Domain_name.(equal (raw hostname) (raw value)) in
  let in_initial = List.exists fn t.cfg.Ask.hostnames in
  let in_entries = List.exists (fun entry -> fn entry.hostname) t.entries in
  let in_pending =
    let fn acc v = acc || fn v in
    Queue.fold fn false t.pending
  in
  in_initial || in_entries || in_pending

let add t hostname =
  Miou.Mutex.protect t.m0 @@ fun () ->
  if not (known t hostname) then begin
    Log.debug (fun m -> m "Add %a" Domain_name.pp hostname);
    Queue.push hostname t.pending;
    Miou.Condition.signal t.condition
  end

let id_pe_acme = Asn.OID.(base 1 3 <| 6 <| 1 <| 5 <| 5 <| 7 <| 1 <| 31)

let make_challenge_cert ~key_authorization domain =
  let solution =
    let open Digestif.SHA256 in
    digest_string key_authorization |> to_raw_string
  in
  let priv = X509.Private_key.generate ~bits:2048 `RSA in
  let name = Domain_name.to_string domain in
  let dn =
    let open X509.Distinguished_name in
    [ Relative_distinguished_name.singleton (CN name) ]
  in
  let san = X509.General_name.(singleton DNS [ name ]) in
  let full = Asn.(encode (codec der S.octet_string)) solution in
  let ext =
    let open X509.Extension in
    add Subject_alt_name (false, san)
      (singleton (Unsupported id_pe_acme) (true, full))
  in
  let now = Mirage_ptime.now () in
  let valid_from =
    Option.value ~default:now (Ptime.sub_span now (Ptime.Span.of_int_s 3600))
  in
  let valid_until =
    Option.value ~default:now (Ptime.add_span now (Ptime.Span.of_int_s 86_400))
  in
  let* csr = X509.Signing_request.create dn priv in
  match
    X509.Signing_request.sign csr ~valid_from ~valid_until ~extensions:ext priv
      dn
  with
  | Ok cert -> Ok ([ cert ], priv)
  | Error err -> error_msgf "%a" X509.Validation.pp_signature_error err

let make_alpn_solver t =
  {
    Ask.Acme.challenge= ALPN
  ; solve_challenge=
      (fun ~token:_ ~key_authorization domain ->
        match make_challenge_cert ~key_authorization domain with
        | Error _ as err -> err
        | Ok entry ->
            let dominated (certs, _) =
              match certs with
              | [] -> false
              | cert :: _ ->
                  let hostnames = X509.Certificate.hostnames cert in
                  X509.Host.Set.mem (`Strict, domain) hostnames
            in
            t.challenges <-
              entry :: List.filter (Fun.negate dominated) t.challenges;
            Ok ())
  }

let ask t he ~production hostname =
  Miou.Mutex.protect t.m1 @@ fun () ->
  let solver = make_alpn_solver t in
  let cfg = { t.cfg with Ask.hostnames= [ hostname ] } in
  match Ask.ask ~production solver cfg he with
  | Error _ as err ->
      t.challenges <- [];
      err
  | Ok (`Single chain) ->
      t.entries <- { hostname; chain } :: t.entries;
      t.add hostname chain;
      t.challenges <- [];
      Ok ()
  | Ok (`Multiple chains) ->
      let fn { hostname; chain } = t.add hostname chain; { hostname; chain } in
      let entries = List.rev_map fn chains in
      t.entries <- List.rev_append entries t.entries;
      t.challenges <- [];
      Ok ()
  | Ok (`Multiple_default (chain, chains)) ->
      let fn { hostname; chain } = t.add hostname chain; { hostname; chain } in
      let entries = List.rev_map fn chains in
      t.entries <- List.rev_append entries t.entries;
      t.entries <- { hostname; chain } :: t.entries;
      t.add hostname chain;
      t.challenges <- [];
      Ok ()
  | Ok `None ->
      t.challenges <- [];
      error_msgf "No certificate for %a" Domain_name.pp hostname

let provisioner t ~production he =
  let rec go () =
    let hostname =
      Miou.Mutex.protect t.m0 @@ fun () ->
      while Queue.is_empty t.pending do
        Miou.Condition.wait t.condition t.m0
      done;
      Queue.pop t.pending
    in
    let on_error = function
      | `Msg msg ->
          Log.err (fun m ->
              m "Provisioning failed for %a: %s" Domain_name.pp hostname msg)
      | `HTTP err ->
          Log.err (fun m ->
              m "Provisioning failed for %a: %a" Domain_name.pp hostname
                Mhttp_client.pp_error err)
    in
    let on_ok () =
      Log.info (fun m ->
          m "Certificate provisioned for %a" Domain_name.pp hostname)
    in
    Log.debug (fun m -> m "Ask for %a" Domain_name.pp hostname);
    let value = ask t he ~production hostname in
    Result.iter on_ok value;
    Result.iter_error on_error value;
    go ()
  in
  go

let earliest_expiry entries =
  let fn acc { chain= chain, _; _ } =
    match chain with
    | [] -> acc
    | cert :: _ -> (
        let _, not_after = X509.Certificate.validity cert in
        match acc with
        | None -> Some not_after
        | Some than when Ptime.is_earlier not_after ~than -> Some not_after
        | _ -> acc)
  in
  List.fold_left fn None entries

let _1d = 86_400_000_000_000
let _1h = 3_600_000_000_000
let _5d = Option.get (Ptime.Span.of_d_ps (5, 0L))

let sleep_until_renewal entries =
  match earliest_expiry entries with
  | None -> Mkernel.sleep _1d
  | Some expiry -> begin
      let now = Mirage_ptime.now () in
      let target =
        match Ptime.sub_span expiry _5d with Some t -> t | None -> expiry
      in
      if Ptime.is_later target ~than:now
      then Mkernel.wakeup ~at:target
      else Mkernel.sleep _1h
    end

let needs_renewal entry =
  match entry.chain with
  | [], _ -> true
  | cert :: _, _ -> begin
      let _, not_after = X509.Certificate.validity cert in
      let now = Mirage_ptime.now () in
      match Ptime.sub_span not_after _5d with
      | Some deadline -> Ptime.is_later now ~than:deadline
      | None -> true
    end

let renew_domains t ~production he =
  let fn entry =
    if needs_renewal entry then begin
      Miou.Mutex.protect t.m1 @@ fun () ->
      Log.info (fun m ->
          m "Renewing certificate for %a" Domain_name.pp entry.hostname);
      let solver = make_alpn_solver t in
      let cfg = { t.cfg with Ask.hostnames= [ entry.hostname ] } in
      match Ask.ask ~production solver cfg he with
      | Ok (`Single chain) ->
          t.challenges <- [];
          t.add entry.hostname chain;
          entry.chain <- chain
      | Ok (`Multiple (chain :: _)) ->
          t.challenges <- [];
          t.add entry.hostname chain;
          entry.chain <- chain
      | Ok (`Multiple_default (chain, _)) ->
          t.challenges <- [];
          t.add entry.hostname chain;
          entry.chain <- chain
      | Ok (`Multiple [] | `None) ->
          t.challenges <- [];
          Log.err (fun m ->
              m "Renewal returned no certificate for %a" Domain_name.pp
                entry.hostname)
      | Error (`Msg msg) ->
          t.challenges <- [];
          Log.err (fun m ->
              m "Renewal failed for %a: %s" Domain_name.pp entry.hostname msg)
      | Error (`HTTP err) ->
          t.challenges <- [];
          Log.err (fun m ->
              m "Renewal failed for %a: %a" Domain_name.pp entry.hostname
                Mhttp_client.pp_error err)
    end
  in
  List.iter fn t.entries

let renewer t ~production he =
  let rec go () =
    sleep_until_renewal t.entries;
    renew_domains t ~production he;
    go ()
  in
  go

type daemon = { renewer: unit Miou.t; provisioner: unit Miou.t }

let ignore _ _ = ()

let create ?(entries = []) ?(add = ignore) cfg ~production he =
  let fn (hostname, chain) = { hostname; chain } in
  let entries = List.map fn entries in
  let challenges = [] in
  let pending = Queue.create () in
  let m0 = Miou.Mutex.create () in
  let m1 = Miou.Mutex.create () in
  let condition = Miou.Condition.create () in
  let t = { entries; challenges; pending; m0; m1; condition; cfg; add } in
  let renewer = Miou.async (renewer t ~production he) in
  let provisioner = Miou.async (provisioner t ~production he) in
  (t, { renewer; provisioner })

let kill { renewer; provisioner } = Miou.cancel renewer; Miou.cancel provisioner

let entries t =
  Miou.Mutex.protect t.m0 @@ fun () ->
  List.map (fun entry -> (entry.hostname, entry.chain)) t.entries

let remove t hostname =
  Miou.Mutex.protect t.m0 @@ fun () ->
  t.entries <-
    List.filter
      (fun entry -> not (Domain_name.equal entry.hostname hostname))
      t.entries
