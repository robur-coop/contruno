open Brr
open Brr_webcrypto

let jstr = Jstr.of_string

let meta name =
  let selector = jstr (Fmt.str "meta[name=%S]" name) in
  let fn el = El.at (jstr "content") el in
  Option.bind (El.find_first_by_selector selector) fn
  |> Option.map Jstr.to_string

let status fmt =
  let fn str =
    Document.find_el_by_id G.document (jstr "contruno-status")
    |> Option.iter (fun el -> El.set_children el [ El.txt' str ])
  in
  Fmt.kstr fn fmt

let batch = 512
let subtle = Crypto.subtle Crypto.crypto
let sha256 = Crypto_algo.v Crypto_algo.sha_256

let hash challenge nonce =
  let data = Tarray.of_jstr (jstr (challenge ^ string_of_int nonce)) in
  let fn buf =
    let hex = Tarray.to_hex_jstr (Tarray.uint8_of_buffer buf) in
    (nonce, Jstr.to_string hex)
  in
  Fut.map (Result.map fn) (Subtle_crypto.digest subtle sha256 data)

let rec search ~prefix challenge start =
  let open Fut.Syntax in
  let fn idx = hash challenge (start + idx) in
  let* results = Fut.of_list (List.init batch fn) in
  let fn = function
    | Ok (nonce, hex) when String.starts_with ~prefix hex -> Some (Ok nonce)
    | Error err -> Some (Error err)
    | Ok _ -> None
  in
  match List.find_map fn results with
  | Some result -> Fut.return result
  | None ->
      status "%d hashes computed..." (start + batch);
      search ~prefix challenge (start + batch)

let location field = Jv.to_string (Jv.get (Jv.get Jv.global "location") field)

let redirect nonce =
  let redir = location "pathname" ^ location "search" in
  let redir =
    match Uri.encode_component (jstr redir) with
    | Ok redir -> Jstr.to_string redir
    | Error _ -> "%2F"
  in
  let uri = Fmt.str "/.contruno/pass?nonce=%d&redir=%s" nonce redir in
  Jv.set (Jv.get Jv.global "location") "href" (Jv.of_string uri)

(* Our [challenge.ml] generates:
   - <meta name="contruno-challenge"
   - <meta name="contruno-difficulty"
*)

let run () =
  let challenge = meta "contruno-challenge" in
  let difficulty = meta "contruno-difficulty" in
  let difficulty = Option.bind difficulty int_of_string_opt in
  match (challenge, difficulty) with
  | Some challenge, Some difficulty ->
      status "Computing...";
      let prefix = String.make difficulty '0' in
      let fn = function
        | Ok nonce -> status "Done!"; redirect nonce
        | Error err ->
            let msg = Jstr.to_string (Jv.Error.message err) in
            status "Error: %s" msg
      in
      Fut.await (search ~prefix challenge 0) fn
  | _ -> status "Invalid challenge page"

let () = run ()
