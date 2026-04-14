let src = Logs.Src.create "contruno.http"

let peer ~secure =
  let scheme = if secure then "https" else "http" in
  let pp ppf (ipaddr, port) =
    Fmt.pf ppf "%s%a:%d" scheme Ipaddr.pp ipaddr port
  in
  Logs.Tag.def ~doc:"HTTP (unikernel) peer" "contruno.http.peer" pp

let secure_peer = peer ~secure:true
let inhibit fn v = try fn v with _exn -> ()

module TCP = struct
  type t = Mnet.TCP.flow

  let read = Mnet.TCP.read

  let write flow ?(off = 0) ?len str =
    let default = String.length str - off in
    let len = Option.value ~default len in
    let tmp = Bytes.create len in
    Bytes.blit_string str 0 tmp 0 len;
    Mnet.TCP.write flow ~off:0 ~len (Bytes.unsafe_to_string tmp)

  let close = Mnet.TCP.close
  let shutdown = Mnet.TCP.shutdown
end

module TLS = struct
  include Mnet_tls

  let write fd ?off ?len str =
    try write fd ?off ?len str with
    | Mnet_tls.Closed_by_peer -> raise Runtime.Flow.Closed_by_peer
    | exn -> raise exn
end

module H2_Server_connection = struct
  include H2.Server_connection

  let next_read_operation t =
    (next_read_operation t :> [ `Close | `Read | `Yield | `Upgrade ])

  let next_write_operation t =
    (next_write_operation t
      :> [ `Close of int
         | `Write of Bstr.t Faraday.iovec list
         | `Yield
         | `Upgrade ])
end

module H1_Client_connection = struct
  include H1.Client_connection

  let yield_reader _ = assert false

  let next_read_operation t =
    (next_read_operation t :> [ `Close | `Read | `Yield | `Upgrade ])

  let next_write_operation t =
    (next_write_operation t
      :> [ `Close of int
         | `Write of Bstr.t Faraday.iovec list
         | `Yield
         | `Upgrade ])
end

module H2_Client_connection = struct
  include H2.Client_connection

  let next_read_operation t =
    (next_read_operation t :> [ `Close | `Read | `Yield | `Upgrade ])

  let next_write_operation t =
    (next_write_operation t
      :> [ `Close of int
         | `Write of Bstr.t Faraday.iovec list
         | `Yield
         | `Upgrade ])
end

module TCP_no_half_close = struct
  include TCP

  let shutdown _flow _cmd = ()
end

module A = Runtime.Make (TLS) (H1.Server_connection)
module B = Runtime.Make (TLS) (H2_Server_connection)
module C = Runtime.Make (TCP_no_half_close) (H1_Client_connection)
module D = Runtime.Make (TCP) (H2_Client_connection)
module Log = (val Logs.src_log src : Logs.LOG)
module Method = H2.Method
module Headers = H2.Headers

type request = {
    meth: Method.t
  ; target: string
  ; scheme: string
  ; headers: Headers.t
}

type body = [ `V1 of H1.Body.Writer.t | `V2 of H2.Body.Writer.t ]
type reqd = [ `V1 of H1.Reqd.t | `V2 of H2.Reqd.t ]

let pp_error ppf = function
  | `V1 `Bad_request -> Fmt.string ppf "Bad HTTP/1.1 request"
  | `V1 `Bad_gateway -> Fmt.string ppf "Bad HTTP/1.1 gateway"
  | `V1 `Internal_server_error | `V2 `Internal_server_error ->
      Fmt.string ppf "Internal server error"
  | `V1 (`Exn exn) | `V2 (`Exn exn) ->
      Fmt.pf ppf "Unknown exception: %s" (Printexc.to_string exn)
  | `V2 `Bad_request -> Fmt.string ppf "Bad H2 request"
  | `Protocol msg -> Fmt.string ppf msg

let request_from_h1 ~scheme { H1.Request.meth; target; headers; _ } =
  let headers = Headers.of_list (H1.Headers.to_list headers) in
  { meth; target; scheme; headers }

let request_from_h2 { H2.Request.meth; target; scheme; headers } =
  { meth; target; scheme; headers }

let https_1_1_server_connection ~config ~user's_error_handler ?upgrade
    ~user's_handler flow =
  let scheme = "https" in
  let read_buffer_size = config.H1.Config.read_buffer_size in
  let error_handler ?request err respond =
    let request = Option.map (request_from_h1 ~scheme) request in
    let err = `V1 err in
    let respond hdrs =
      let hdrs = H1.Headers.of_list (Headers.to_list hdrs) in
      let body = respond hdrs in
      `V1 body
    in
    user's_error_handler `V1 ?request err respond
  in
  let request_handler reqd = user's_handler (`Tls flow) (`V1 reqd) in
  let conn =
    H1.Server_connection.create ~config ~error_handler request_handler
  in
  let tags =
    let flow = Mnet_tls.file_descr flow in
    let (ipaddr, port), _ = Mnet.TCP.peers flow in
    let tags = Mnet.TCP.tags flow in
    Logs.Tag.add secure_peer (ipaddr, port) tags
  in
  let finally = inhibit Mnet_tls.close in
  let res = Miou.Ownership.create ~finally flow in
  Miou.Ownership.own res;
  Miou.await_exn (A.run conn ~tags ~read_buffer_size ?upgrade flow);
  Miou.Ownership.release res

let rec clean_up orphans =
  match Miou.care orphans with
  | None | Some None -> ()
  | Some (Some prm) ->
      let result = Miou.await prm in
      let on_error exn =
        Log.err (fun m ->
            m "Unexpected exception from promise (during h2+tls connection): %s"
              (Printexc.to_string exn))
      in
      Result.iter_error on_error result;
      clean_up orphans

let rec terminate orphans =
  match Miou.care orphans with
  | None -> ()
  | Some None -> Miou.yield (); terminate orphans
  | Some (Some prm) ->
      let result = Miou.await prm in
      let on_error exn =
        Log.err (fun m ->
            m "Unexpected exception from promise (during h2+tls connection): %s"
              (Printexc.to_string exn))
      in
      Result.iter_error on_error result;
      terminate orphans

let h2s_server_connection ~config ~user's_error_handler ?upgrade ~user's_handler
    flow =
  let read_buffer_size = config.H2.Config.read_buffer_size in
  let error_handler ?request err respond =
    let request = Option.map request_from_h2 request in
    let err = `V2 err in
    let respond hdrs = `V2 (respond hdrs) in
    user's_error_handler `V2 ?request err respond
  in
  let queue = Queue.create () in
  let mutex = Miou.Mutex.create () in
  let condition = Miou.Condition.create () in
  let stop = ref false in
  let request_handler reqd =
    Miou.Mutex.protect mutex @@ fun () ->
    Queue.push reqd queue;
    Miou.Condition.signal condition
  in
  let conn =
    H2.Server_connection.create ~config ~error_handler request_handler
  in
  let tags =
    let flow = Mnet_tls.file_descr flow in
    let (ipaddr, port), _ = Mnet.TCP.peers flow in
    let tags = Mnet.TCP.tags flow in
    Logs.Tag.add secure_peer (ipaddr, port) tags
  in
  let finally = inhibit Mnet_tls.close in
  let res = Miou.Ownership.create ~finally flow in
  Miou.Ownership.own res;
  let rec go orphans =
    let reqd =
      Miou.Mutex.protect mutex @@ fun () ->
      while Queue.is_empty queue && not !stop do
        Miou.Condition.wait condition mutex
      done;
      if !stop then None else Some (Queue.pop queue)
    in
    clean_up orphans;
    match reqd with
    | None -> terminate orphans
    | Some reqd ->
        let _ =
          Miou.async ~orphans @@ fun () -> user's_handler (`Tls flow) (`V2 reqd)
        in
        go orphans
  in
  let prm0 = Miou.async @@ fun () -> go (Miou.orphans ()) in
  let prm1 = B.run conn ~tags ~read_buffer_size ?upgrade flow in
  Miou.await_exn prm1;
  stop := true;
  Miou.Mutex.protect mutex (fun () -> Miou.Condition.signal condition);
  Miou.await_exn prm0;
  Miou.Ownership.release res

let errf err =
  Fmt.str "<h1>500 Internal error</h1><p>Error: %a</p>" pp_error err

let default_error_handler version ?request:_ err respond =
  let str = errf err in
  let hdrs =
    match version with
    | `V1 ->
        [
          ("content-type", "text/html; charset=utf-8")
        ; ("content-length", string_of_int (String.length str))
        ; ("connection", "close")
        ]
    | `V2 ->
        [
          ("content-type", "text/html; charset=utf-8")
        ; ("content-length", string_of_int (String.length str))
        ]
  in
  let hdrs = H2.Headers.of_list hdrs in
  match respond hdrs with
  | `V1 body ->
      H1.Body.Writer.write_string body str;
      let fn () =
        if H1.Body.Writer.is_closed body = false then H1.Body.Writer.close body
      in
      H1.Body.Writer.flush body fn
  | `V2 body ->
      H2.Body.Writer.write_string body str;
      let fn = function
        | `Closed -> ()
        | `Written -> H2.Body.Writer.close body
      in
      H2.Body.Writer.flush body fn

let alpn tls =
  match Mnet_tls.epoch tls with
  | Some { Tls.Core.alpn_protocol= protocol; _ } -> protocol
  | None -> None

let with_tls tls ?(config = `Both (H1.Config.default, H2.Config.default))
    ?error_handler:(user's_error_handler = default_error_handler) ?upgrade
    ~handler:user's_handler flow =
  try
    let flow = Mnet_tls.server_of_fd tls flow in
    begin match (config, alpn flow) with
    | `Both (_, config), Some "h2" | `H2 config, (Some "h2" | None) ->
        h2s_server_connection ~config ~user's_error_handler ?upgrade
          ~user's_handler flow
    | `Both (config, _), Some "http/1.1"
    | `HTTP_1_1 config, (Some "http/1.1" | None) ->
        https_1_1_server_connection ~config ~user's_error_handler ?upgrade
          ~user's_handler flow
    | `Both _, None ->
        failwith "No protocol specified during the ALPN negotiation"
    | _, Some "acme-tls/1" -> Mnet_tls.close flow
    | _, Some protocol -> Fmt.failwith "Unrecognized protocol: %S" protocol
    end
  with exn ->
    Logs.err (fun m ->
        m "Got a TLS error during the handshake: %s" (Printexc.to_string exn));
    Mnet.TCP.close flow
