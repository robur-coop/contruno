let ( let* ) = Result.bind
let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt
let src = Logs.Src.create "contruno.ask"

module Log = (val Logs.src_log src : Logs.LOG)

module Id = struct
  type 'a t = 'a

  let bind x fn = fn x
  let return x = x
end

module C :
  Letsencrypt.Client.Client
    with type 'a t = 'a
     and type ctx = Mnet_happy_eyeballs.t
     and type error = Mhttp_client.error = struct
  type 'a t = 'a
  type ctx = Mnet_happy_eyeballs.t
  type error = Mhttp_client.error
  type meth = [ `HEAD | `GET | `POST ]
  type response = { headers: (string * string) list; status: int }

  let request ?ctx ?meth ?headers ?body uri =
    let happy_eyeballs =
      match ctx with
      | Some happy_eyeballs -> happy_eyeballs
      | None ->
          invalid_arg "Happy-eyeballs value missing for Letsencrypt client"
    in
    Log.debug (fun m ->
        let str = Option.value ~default:"" body in
        let hash = Digestif.SHA256.digest_string str in
        m "Do %s: %a" uri Digestif.SHA256.pp hash);
    let body = Option.map Mhttp_client.string body in
    let fn _meta _req _resp buf str =
      Option.iter (Buffer.add_string buf) str;
      buf
    in
    let results =
      Mhttp_client.request ~happy_eyeballs
        ?meth:(meth :> H1.Method.t option)
        ?headers ?body ~follow_redirect:false ~fn ~uri (Buffer.create 0x7ff)
    in
    match results with
    | Ok (resp, buf) ->
        let str = Buffer.contents buf in
        Log.debug (fun m ->
            let hash = Digestif.SHA256.digest_string str in
            m "Get a response from %s: %a" uri Digestif.SHA256.pp hash);
        let status = H2.Status.to_code resp.Mhttp_client.status in
        let hdrs = H2.Headers.to_list resp.Mhttp_client.headers in
        let hdrs =
          let fn (key, value) = (String.lowercase_ascii key, value) in
          List.map fn hdrs
        in
        Ok ({ headers= hdrs; status }, str)
    | Error _ as err -> err
end

type cfg = {
    email: string option
  ; certificate_seed: string option
  ; certificate_key_type: X509.Key_type.t
  ; certificate_key_bits: int option
  ; hostnames: [ `host ] Domain_name.t list
  ; account_seed: string option
  ; account_key_type: X509.Key_type.t
  ; account_key_bits: int option
}

module Acme = Letsencrypt.Client.Make (Id) (C)

let gen ?seed ?bits t = X509.Private_key.generate ?seed ?bits t

let csr key hostnames =
  match hostnames with
  | [] -> invalid_arg "We need, at least, one hostname"
  | hostname :: _ ->
      let host = Domain_name.to_string hostname in
      let dn =
        let open X509.Distinguished_name in
        [ Relative_distinguished_name.singleton (CN host) ]
      in
      let san =
        let open X509.General_name in
        singleton DNS (List.map Domain_name.to_string hostnames)
      in
      let ext = X509.Extension.(add Subject_alt_name (false, san) empty) in
      let ext = X509.Signing_request.Ext.(singleton Extensions ext) in
      X509.Signing_request.create dn ~extensions:ext key

let ask ?(tries = 10) ~production solver cfg he =
  let edn =
    if production then Letsencrypt.letsencrypt_production_url
    else Letsencrypt.letsencrypt_staging_url
  in
  let pk =
    gen ?seed:cfg.certificate_seed ?bits:cfg.certificate_key_bits
      cfg.certificate_key_type
  in
  let* csr = csr pk cfg.hostnames in
  let account_key =
    gen ?seed:cfg.account_seed ?bits:cfg.account_key_bits cfg.account_key_type
  in
  Log.debug (fun m -> m "Initialize");
  match Acme.initialise ~ctx:he ~endpoint:edn ?email:cfg.email account_key with
  | Ok le ->
      let sleep sec = Mkernel.sleep (sec * 1_000_000_000) in
      let rec go tries =
        match Acme.sign_certificate ~ctx:he solver le sleep csr with
        | Ok certs -> Ok (`Single (certs, pk))
        | Error (`Msg msg) when tries > 0 ->
            Log.warn (fun m ->
                m "Error getting certificate: %s (tries: %d)" msg tries);
            go (tries - 1)
        | Error (`Msg _) as err -> err
        | Error (`HTTP err) ->
            error_msgf "HTTP error: %a" Mhttp_client.pp_error err
      in
      go tries
  | Error _ as err -> err
