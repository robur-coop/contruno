type env = {
    contruno: Contruno.t
  ; add_domain:
      [ `host ] Domain_name.t -> Ipaddr.t -> int -> [ `HTTP_1_1 | `H2 ] -> unit
  ; remove_domain: string -> unit
  ; password: string
}

let basic_auth =
  Vifu.Middlewares.v ~name:"basic-auth" @@ fun req _target _server env ->
  let hdrs = Vifu.Request.headers_of_request req in
  match Vifu.Headers.get hdrs "authorization" with
  | Some v ->
      let credentials = Fmt.str "admin:%s" env.password in
      let expected = Fmt.str "Basic %s" (Base64.encode_string credentials) in
      if String.equal v expected then Some `Authenticated else None
  | None -> None

let unauthorized req =
  let open Vifu.Response.Syntax in
  let field = "www-authenticate" in
  let* () = Vifu.Response.set ~field "Basic realm=\"contruno\"" in
  let* () = Vifu.Response.with_string req "Unauthorized\n" in
  Vifu.Response.respond `Unauthorized

let validity_of_chain = function
  | [], _ -> None
  | cert :: _, _ ->
      let not_before, not_after = X509.Certificate.validity cert in
      Some (not_before, not_after)

let pp_ptime ppf t =
  let (y, m, d), ((hh, mm, ss), _tz) = Ptime.to_date_time t in
  Fmt.pf ppf "%04d-%02d-%02d %02d:%02d:%02d" y m d hh mm ss

let if_match req hash =
  let hdrs = Vifu.Request.headers req in
  match Vifu.Headers.get hdrs "if-none-match" with
  | Some hash' -> String.equal hash hash'
  | None -> false

let document contents =
  let ctx = Digestif.SHA256.empty in
  let fn ctx str = Digestif.SHA256.feed_string ctx str in
  let ctx = List.fold_left fn ctx contents in
  let hash = Digestif.SHA256.get ctx in
  let etag = Digestif.SHA256.to_hex hash in
  ();
  fun req _server _env ->
    let open Vifu.Response.Syntax in
    if if_match req etag then
      let* () = Vifu.Response.with_string req "" in
      Vifu.Response.respond `Not_modified
    else
      let field = "content-length" in
      let value =
        List.fold_left (fun acc str -> acc + String.length str) 0 contents
      in
      let value = string_of_int value in
      let* () = Vifu.Response.add ~field value in
      let field = "etag" in
      let* () = Vifu.Response.add ~field etag in
      let field = "cache-control" in
      let* () = Vifu.Response.add ~field "public, max-age=3600" in
      let src = Flux.Source.list contents in
      let* () = Vifu.Response.with_source req src in
      Vifu.Response.respond `OK

let dashboard_html entries =
  let buf = Buffer.create 4096 in
  Buffer.add_string buf
    {|<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>contruno - admin</title>
  <link rel="stylesheet" href="/style.css">
  <script type="text/javascript" defer src="/script.js"></script>
</head>
<body>
  <h1>contruno <small>admin</small></h1>
  <h2>Certificates</h2>
|};
  let now = Mirage_ptime.now () in
  if entries = [] then Buffer.add_string buf {|  <p>No certificates.</p>
|}
  else
    List.iter
      (fun (hostname, chain) ->
        let name = Domain_name.to_string hostname in
        let meta, cls =
          match validity_of_chain chain with
          | Some (nb, na) ->
              let expired = Ptime.is_later now ~than:na in
              ( Fmt.str "%a — %a%s" pp_ptime nb pp_ptime na
                  (if expired then " (expired)" else "")
              , if expired then "expired" else "valid" )
          | None -> ("no certificate", "expired")
        in
        Buffer.add_string buf
          (Fmt.str
             {|  <div class="domain">
    <span class="domain-name">%s</span>
    <span class="delete" onclick="deleteDomain('%s')">[delete]</span><br>
    <span class="domain-meta %s">%s</span>
  </div>
|}
             name name cls meta))
      entries;
  Buffer.add_string buf
    {|
  <h2>Add domain</h2>

  <form onsubmit="addDomain(event)">
    <input type="text" id="add-hostname" placeholder="example.com" required><br>
    <input type="text" id="add-destination" placeholder="10.0.0.1" required>
    <input type="text" id="add-port" placeholder="80" style="width: 4em;">
    <select id="add-protocol" style="font-family: monospace; font-size: 1em; border: none; border-bottom: 1px solid #333; background: transparent; color: #333;">
      <option value="http/1.1">http/1.1</option>
      <option value="h2">h2</option>
    </select><br>
    <input type="submit" value="add">
  </form>

  <hr>
  <p><small style="color: #888;">contruno is a <a href="https://robur.coop" style="color: #888;">robur</a> unikernel</small></p>
</body>
</html>
|};
  Buffer.contents buf

let domain_name_jsont =
  let dec str =
    match Result.bind (Domain_name.of_string str) Domain_name.host with
    | Ok value -> value
    | Error _ -> Fmt.failwith "Invalid hostname"
  in
  let enc = Domain_name.to_string in
  Jsont.map ~enc ~dec Jsont.string

let ipaddr_jsont =
  let dec str =
    match Ipaddr.of_string str with
    | Ok v -> v
    | Error _ -> Fmt.failwith "Invalid IP address"
  in
  Jsont.map ~enc:Ipaddr.to_string ~dec Jsont.string

let protocol_jsont = Jsont.enum [ ("http/1.1", `HTTP_1_1); ("h2", `H2) ]

type add_input = {
    hostname: [ `host ] Domain_name.t
  ; destination: Ipaddr.t
  ; port: int
  ; protocol: [ `HTTP_1_1 | `H2 ]
}

let add_input_json =
  let open Jsont in
  let hostname =
    Object.mem "hostname" ~enc:(fun t -> t.hostname) domain_name_jsont
  in
  let destination =
    Object.mem "destination" ~enc:(fun t -> t.destination) ipaddr_jsont
  in
  let port =
    Object.mem "port"
      ~enc:(fun t -> t.port)
      ~dec_absent:80 ~enc_omit:(( = ) 80) int
  in
  let protocol =
    Object.mem "protocol"
      ~enc:(fun t -> t.protocol)
      ~dec_absent:`HTTP_1_1 ~enc_omit:(( = ) `HTTP_1_1) protocol_jsont
  in
  Object.map (fun hostname destination port protocol ->
      { hostname; destination; port; protocol })
  |> hostname
  |> destination
  |> port
  |> protocol
  |> Object.finish

type delete_input = { hostname: [ `host ] Domain_name.t }

let delete_input_json =
  let open Jsont in
  let hostname =
    Object.mem "hostname" ~enc:(fun t -> t.hostname) domain_name_jsont
  in
  Object.map (fun hostname -> { hostname }) |> hostname |> Object.finish

let dashboard req _server env =
  let open Vifu.Response.Syntax in
  match Vifu.Request.get basic_auth req with
  | None -> unauthorized req
  | Some `Authenticated ->
      let entries = Contruno.entries env.contruno in
      let html = dashboard_html entries in
      let* () =
        Vifu.Response.set ~field:"content-type" "text/html; charset=utf-8"
      in
      let* () = Vifu.Response.with_string req html in
      Vifu.Response.respond `OK

let add_domain req _server env =
  let open Vifu.Response.Syntax in
  match Vifu.Request.get basic_auth req with
  | None -> unauthorized req
  | Some `Authenticated ->
      begin match Vifu.Request.of_json req with
      | Error (`Msg msg) ->
          let* () =
            Vifu.Response.with_string req (Fmt.str "Bad JSON: %s\n" msg)
          in
          Vifu.Response.respond `Bad_request
      | Ok { hostname; destination; port; protocol } ->
          env.add_domain hostname destination port protocol;
          let* () = Vifu.Response.empty in
          Vifu.Response.redirect_to req Vifu.Uri.(rel / "admin" /?? nil)
      end

let delete_domain req _server env =
  let open Vifu.Response.Syntax in
  match Vifu.Request.get basic_auth req with
  | None -> unauthorized req
  | Some `Authenticated ->
      begin match Vifu.Request.of_json req with
      | Error (`Msg msg) ->
          let* () =
            Vifu.Response.with_string req (Fmt.str "Bad JSON: %s\n" msg)
          in
          Vifu.Response.respond `Bad_request
      | Ok { hostname } ->
          Contruno.remove env.contruno hostname;
          let name = Domain_name.to_string hostname in
          env.remove_domain name;
          let* () = Vifu.Response.empty in
          Vifu.Response.redirect_to req Vifu.Uri.(rel / "admin" /?? nil)
      end

let redirect req target _server _env =
  let host = Vifu.Headers.get (Vifu.Request.headers req) "host" in
  match host with
  | Some host ->
      let location = Printf.sprintf "https://%s%s" host target in
      let open Vifu.Response.Syntax in
      Some
        (let* () = Vifu.Response.set ~field:"location" location in
         let* () = Vifu.Response.with_string req "Moved Permanently\n" in
         Vifu.Response.respond `Moved_permanently)
  | None ->
      let open Vifu.Response.Syntax in
      Some
        (let* () = Vifu.Response.with_string req "Bad Request\n" in
         Vifu.Response.respond `Bad_request)

let routes =
  let open Vifu.Uri in
  let open Vifu.Route in
  let open Vifu.Type in
  [
    get (rel / "admin" /?? nil) --> dashboard
  ; get (rel / "style.css" /?? nil) --> document Documents.style_css
  ; get (rel / "scrupt.js" /?? nil) --> document Documents.script_js
  ; post (json_encoding add_input_json) (rel / "admin" / "add" /?? nil)
    --> add_domain
  ; post (json_encoding delete_input_json) (rel / "admin" / "delete" /?? nil)
    --> delete_domain
  ]

let run tcp env =
  let cfg = Vifu.Config.v 80 in
  let middlewares = Vifu.Middlewares.[ basic_auth ] in
  let handlers = [ redirect ] in
  Vifu.run ~cfg ~middlewares ~handlers tcp routes env
