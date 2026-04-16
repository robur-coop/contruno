(*
function postJson(url, data) {
  fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  }).then(function() { window.location.href = '/admin/'; });
}
function addDomain(e) {
  e.preventDefault();
  var h = document.getElementById('add-hostname').value;
  var d = document.getElementById('add-destination').value;
  var p = parseInt(document.getElementById('add-port').value) || 80;
  var pr = document.getElementById('add-protocol').value;
  if (h && d) {
    var data = { hostname: h, destination: d, port: p };
    if (pr !== 'http/1.1') data.protocol = pr;
    postJson('/admin/add', data);
  }
}
function deleteDomain(name) {
  if (confirm('Delete ' + name + '?'))
    postJson('/admin/delete', { hostname: name });
}
*)

let jstrf fmt = Fmt.kstr Jstr.of_string fmt
let jstr = Jstr.of_string

let postJson uri data =
  let open Brr_io in
  let open Fut.Result_syntax in
  let req =
    let headers =
      Fetch.Headers.of_assoc
        [ (jstrf "Content-Type", jstrf "application/json") ]
    in
    let body = Fetch.Body.of_jstr (Brr.Json.encode data) in
    let init = Fetch.Request.init ~method':(jstrf "POST") ~headers ~body () in
    Fetch.Request.v ~init uri
  in
  let* _resp = Brr_io.Fetch.request req in
  let uri = Brr.Uri.v (jstrf "/admin/") in
  Brr.Window.set_location Brr.G.window uri;
  Fut.ok ()

let getById fmt =
  let fn str =
    Brr.Document.find_el_by_id Brr.G.document (jstr str) |> Option.get
  in
  Fmt.kstr fn fmt

let add_hostname = getById "add-hostname"
let add_destination = getById "add-destination"
let add_port = getById "add-port"
let add_protocol = getById "add-protocol"
let confirm = Jv.get Jv.global "confirm"

let confirmf fmt =
  let fn str = Jv.to_bool @@ Jv.apply confirm Jv.[| of_string str |] in
  Fmt.kstr fn fmt

let addDomain ev_submit =
  let _ = Jv.call (Brr.Ev.to_jv ev_submit) "preventDefault" [||] in
  let h = Brr.El.prop Brr.El.Prop.value add_hostname in
  let d = Brr.El.prop Brr.El.Prop.value add_destination in
  let p = Brr.El.prop Brr.El.Prop.value add_port in
  let p =
    let fn = Fun.compose int_of_string_opt Jstr.to_string in
    Option.value ~default:80 (fn p)
  in
  let pr = Brr.El.prop Brr.El.Prop.value add_protocol in
  let data =
    Jv.obj
      [|
         ("hostname", Jv.of_jstr h); ("destination", Jv.of_jstr d)
       ; ("port", Jv.of_int p); ("protocol", Jv.of_jstr pr)
      |]
  in
  if Jstr.is_empty h = false && Jstr.is_empty d = false then
    postJson (jstrf "/admin/add") data
  else Fut.ok ()

let deleteDomain name =
  if confirmf "Delete %s?" (Jstr.to_string name) then
    postJson (jstrf "/admin/delete")
      (Jv.obj [| ("hostname", Jv.of_jstr name) |])
  else Fut.ok ()

let () = Jv.set Jv.global "addDomain" (Jv.callback ~arity:1 addDomain)
let () = Jv.set Jv.global "deleteDomain" (Jv.callback ~arity:1 deleteDomain)
