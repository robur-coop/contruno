let src = Logs.Src.create "contruno.challenge"

module Log = (val Logs.src_log src : Logs.LOG)

type t = { secret: Jws.Pk.t; difficulty: int; ttl: float }

let _7d = 7. *. 24. *. 60. *. 60.
let v ?(ttl = _7d) ~difficulty secret = { secret= `Oct secret; difficulty; ttl }
let cookie = "contruno-auth"
let prefix = "/.contruno/"
let now () = Ptime.to_float_s (Mirage_ptime.now ())

(* NOTE(dinosaure): see Anubis/data/bots/ai-robots-txt.yaml | sed 's/^/"/; s/$/"/; s/|/";"/g' *)
let ai_bots =
  [
    "AddSearchBot"; "AgentTimes"; "AI2Bot"; "AI2Bot-DeepResearchEval"
  ; "Ai2Bot-Dolma"; "aiHitBot"; "AIWebIndex"; "amazon-kendra"
  ; "amazon-QBusiness"; "Amazonbot"; "AmazonBuyForMe"; "Amzn-SearchBot"
  ; "Amzn-User"; "Andibot"; "Anomura"; "anthropic-ai"; "ApifyBot"
  ; "ApifyWebsiteContentCrawler"; "Applebot"; "Applebot-Extended"
  ; "Aranet-SearchBot"; "atlassian-bot"; "Awario"; "AzureAI-SearchBot"
  ; "bedrockbot"; "bigsur.ai"; "Bravebot"; "Brightbot"; "Brightbot 1.0"
  ; "BuddyBot"; "Bytespider"; "Channel3Bot"; "ChatGLM-Spider"; "ChatGPT Agent"
  ; "ChatGPT-User"; "Claude-Code"; "Claude-SearchBot"; "Claude-User"
  ; "Claude-Web"; "ClaudeBot"; "Cloudflare-AutoRAG"; "CloudVertexBot"; "Code"
  ; "cohere-ai"; "cohere-training-data-crawler"; "Cotoyogi"; "CragCrawler"
  ; "Crawl4AI"; "Crawlspace"; "Cursor"; "Datenbank Crawler"; "DeepSeekBot"
  ; "Devin"; "Diffbot"; "DuckAssistBot"; "Echobot Bot"; "EchoboxBot"; "ExaBot"
  ; "FacebookBot"; "facebookexternalhit"; "Factset_spyderbot"; "FirecrawlAgent"
  ; "FriendlyCrawler"; "GeistHaus-PageFetcher"; "Gemini-Deep-Research"
  ; "Google-Agent"; "Google-CloudVertexBot"; "Google-Extended"
  ; "Google-Firebase"; "Google-Gemini-CLI"; "Google-NotebookLM"
  ; "GoogleAgent-Mariner"; "GoogleAgent-URLContext"; "GoogleOther"
  ; "GoogleOther-Image"; "GoogleOther-Video"; "GPTBot"; "HenkBot"; "iAskBot"
  ; "iaskspider"; "iaskspider/2.0"; "IbouBot"; "ICC-Crawler"; "ImagesiftBot"
  ; "imageSpider"; "img2dataset"; "ISSCyberRiskCrawler"; "kagi-fetcher"
  ; "Kangaroo Bot"; "Kimi-User"; "KlaviyoAIBot"; "KunatoCrawler"
  ; "laion-huggingface-processor"; "LAIONDownloader"; "LCC"; "LinerBot"
  ; "Linguee Bot"; "LinkupBot"; "Manus-User"; "meta-externalagent"
  ; "Meta-ExternalAgent"; "meta-externalfetcher"; "Meta-ExternalFetcher"
  ; "meta-webindexer"; "MistralAI-User"; "MistralAI-User/1.0"
  ; "Mozilla-Tabstack"; "MyCentralAIScraperBot"; "NagetBot"
  ; "netEstate Imprint Crawler"; "newsai"; "NotebookLM"; "NovaAct"
  ; "OAI-SearchBot"; "omgili"; "omgilibot"; "OpenAI"; "opencode"; "Operator"
  ; "PanguBot"; "Panscient"; "panscient.com"; "Perplexity-User"; "PerplexityBot"
  ; "PetalBot"; "PhindBot"; "Poggio-Citations"; "Poseidon Research Crawler"
  ; "QualifiedBot"; "Querit-SearchBot"; "QueritBot"; "QuillBot"; "quillbot.com"
  ; "SBIntuitionsBot"; "Scrapy"; "SemrushBot-OCOB"; "SemrushBot-SWA"
  ; "Shap-User"; "ShapBot"; "Sidetrade indexer bot"; "Spider"; "TavilyBot"
  ; "Terra Cotta"; "TerraCotta"; "Thinkbot"; "TikTokSpider"; "Timpibot"
  ; "TongyiBot"; "Trae"; "TwinAgent"; "UseAI"; "VelenPublicWebCrawler"
  ; "WARDBot"; "Webzio-Extended"; "webzio-extended"; "wpbot"; "WRTNBot"; "YaK"
  ; "YandexAdditional"; "YandexAdditionalBot"; "YiyanBot"; "YouBot"
  ; "ZanistaBot"
  ]

let contains ~sub str =
  let len = String.length sub and max = String.length str in
  let rec go idx =
    if idx + len > max then false
    else if String.sub str idx len = sub then true
    else go (idx + 1)
  in
  len = 0 || go 0

let is_ai_bot user_agent =
  let user_agent = String.lowercase_ascii user_agent in
  let fn ai_bot =
    let sub = String.lowercase_ascii ai_bot in
    contains ~sub user_agent
  in
  List.exists fn ai_bots

let path_of_target target =
  match String.index_opt target '?' with
  | Some idx ->
      let len = String.length target in
      let path = String.sub target 0 idx
      and queries = String.sub target (idx + 1) (len - idx - 1) in
      (path, queries)
  | None -> (target, "")

type request = {
    meth: H2.Method.t
  ; path: string
  ; query: string
  ; headers: H2.Headers.t
  ; ip: string
}

let request_of_reqd ip = function
  | `V1 reqd ->
      let req = H1.Reqd.request reqd in
      let headers = H1.Headers.to_list req.H1.Request.headers in
      let headers = H2.Headers.of_list headers in
      let path, query = path_of_target req.H1.Request.target in
      { meth= req.H1.Request.meth; path; query; headers; ip }
  | `V2 reqd ->
      let req = H2.Reqd.request reqd in
      let path, query = path_of_target req.H2.Request.target in
      {
        meth= req.H2.Request.meth
      ; path
      ; query
      ; headers= req.H2.Request.headers
      ; ip
      }

let header req name = Option.value ~default:"" (H2.Headers.get req.headers name)

module Cookie = struct
  let get req =
    let values = H2.Headers.get_multi req.headers "cookie" in
    let values = List.concat_map (String.split_on_char ';') values in
    let values = List.map String.trim values in
    let prefix = Fmt.str "%s=" cookie in
    let fn str =
      if String.starts_with ~prefix str then
        let len = String.length prefix in
        Some (String.sub str len (String.length str - len))
      else None
    in
    List.find_map fn values

  let set ?(max_age = int_of_float _7d) key value =
    let value =
      Fmt.str "%s=%s; Path=/; Max-Age=%d; Secure; HttpOnly; SameSite= Lax" key
        value max_age
    in
    ("set-cookie", value)
end

let hmac t parts =
  let data = String.concat "\x00" parts in
  Digestif.SHA256.digest_string (Jws.Pk.sign t.secret data)

let challenge_of t ~host req bucket =
  let user_agent = header req "user-agent" in
  let accept_language = header req "accept-language" in
  let bucket = string_of_int (int_of_float bucket) in
  let parts = [ "c"; host; req.ip; user_agent; accept_language; bucket ] in
  Digestif.SHA256.to_hex (hmac t parts)

let bucket () = now () /. _7d

let jwt t ~host req expiry =
  let cl =
    let open Jwt.Claims in
    empty
    |> exp expiry
    |> aud [ host ]
       (* TODO(dinosaure): should we include all hosts given by [contruno]? *)
    |> add "user-agent" Jsont.string (header req "user-agent")
  in
  Jwt.encode ~kid:"contruno" t.secret cl
(* NOTE(dinosaure): For a symmetric key (which is the case), we should use
   [kid]. Otherwise, we leak our key. *)

let has_valid_cookie t ~host:aud req =
  let public = Jws.Pk.public t.secret in
  let now = now () in
  let fn cookie = Jwt.decode ~now ~aud ~public cookie |> Result.to_option in
  (* NOTE(dinosaure): [Jwt] verifies [aud] and [exp] (only if it exists) also.
     To be sure sure, we also check if [exp] exists (and if [Jwt] did a
     verification on it). *)
  match Option.bind (Cookie.get req) fn with
  | None -> false
  | Some jwt ->
      let user_agent = Some (header req "user-agent") in
      Jwt.value jwt ~key:"user-agent" Jsont.string = user_agent
      && Option.is_some (Jwt.exp jwt)

let is_solution t challenge nonce =
  let hash = Digestif.SHA256.digest_string (challenge ^ nonce) in
  let hex = Digestif.SHA256.to_hex hash in
  String.starts_with ~prefix:(String.make t.difficulty '0') hex

let respond reqd ~(status : H1.Status.t) ?(headers = []) body =
  let length = string_of_int (String.length body) in
  let headers = ("content-length", length) :: headers in
  match reqd with
  | `V1 reqd ->
      let headers = H1.Headers.of_list headers in
      let resp = H1.Response.create ~headers status in
      H1.Reqd.respond_with_string reqd resp body
  | `V2 reqd ->
      let headers = H2.Headers.of_list headers in
      let resp = H2.Response.create ~headers (status :> H2.Status.t) in
      H2.Reqd.respond_with_string reqd resp body

let text = ("content-type", "text/plain; charset=utf-8")
let no_store = ("cache-control", "no-store")

let deny reqd =
  respond reqd ~status:`Forbidden ~headers:[ text; no_store ] "Forbidden\n"

let page t challenge =
  Fmt.str
    {|<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="contruno-challenge" content="%s">
  <meta name="contruno-difficulty" content="%d">
  <title>Checking your browser...</title>
  <style>body{font-family:monospace;max-width:40em;margin:4em auto;padding:0 1em;color:#333}</style>
  <script type="text/javascript" defer src="%schallenge.js"></script>
</head>
<body>
  <h1>Checking your browser...</h1>
  <p>This website is protected against AI scrapers. Your browser is computing a
  small proof-of-work, you will be redirected in a few seconds.</p>
  <p id="contruno-status"></p>
  <noscript><p>JavaScript is required to pass this check.</p></noscript>
</body>
</html>
|}
    challenge t.difficulty prefix

let serve_challenge t ~host req reqd =
  let challenge = challenge_of t ~host req (bucket ()) in
  let headers = [ ("content-type", "text/html; charset=utf-8"); no_store ] in
  respond reqd ~status:`OK ~headers (page t challenge)

let serve_script reqd =
  let headers =
    [
      ("content-type", "text/javascript; charset=utf-8")
    ; ("cache-control", "public, max-age=86400")
    ]
  in
  respond reqd ~status:`OK ~headers Documents.challenge_js

let int_of_hex chr =
  let code = int_of_char (Char.uppercase_ascii chr) - 48 in
  if code > 9 then
    if code > 16 && code < 23 then code - 7 else failwith "int_of_hex"
  else if code >= 0 then code
  else failwith "int_of_hex"

(* NOTE(dinosaure): from lib/vif/pct.ml *)
let pct_decode str =
  let len = String.length str in
  let buf = Buffer.create len in
  let rec go start cur =
    if cur >= len then Buffer.add_substring buf str start (cur - start)
    else if str.[cur] = '%' then begin
      Buffer.add_substring buf str start (cur - start);
      let cur = cur + 1 in
      if cur >= len then Buffer.add_char buf '%'
      else
        match int_of_hex str.[cur] with
        | exception _ -> Buffer.add_char buf '%'; go cur cur
        | hi ->
            let cur = cur + 1 in
            if cur >= len then begin
              Buffer.add_char buf '%';
              Buffer.add_char buf str.[cur - 1]
            end
            else
              let start_at =
                match int_of_hex str.[cur] with
                | exception _ ->
                    Buffer.add_char buf '%';
                    Buffer.add_char buf str.[cur - 1];
                    cur
                | lo ->
                    Buffer.add_char buf (Char.chr ((hi lsl 4) + lo));
                    cur + 1
              in
              go start_at start_at
    end
    else go start (cur + 1)
  in
  go 0 0; Buffer.contents buf

let query_params query =
  let fn param =
    match String.index_opt param '=' with
    | Some idx ->
        let k = String.sub param 0 idx in
        let v = String.sub param (idx + 1) (String.length param - idx - 1) in
        Some (pct_decode k, pct_decode v)
    | None -> None
  in
  List.filter_map fn (String.split_on_char '&' query)

let is_safe_redirection = function
  | "" -> false
  | str ->
      str.[0] = '/'
      && (String.length str = 1 || (str.[1] <> '/' && str.[1] <> '\\'))
      && not (String.exists (fun chr -> chr = '\r' || chr = '\n') str)

let is_nonce str =
  String.length str > 0
  && String.length str <= 20
  && String.for_all (function '0' .. '9' -> true | _ -> false) str

let pass t ~host req reqd =
  let params = query_params req.query in
  let nonce = List.assoc_opt "nonce" params in
  let redir = Option.value ~default:"/" (List.assoc_opt "redir" params) in
  let redir = if is_safe_redirection redir then redir else "/" in
  let bucket = bucket () in
  let solved nonce =
    is_nonce nonce
    && (is_solution t (challenge_of t ~host req bucket) nonce
       || is_solution t (challenge_of t ~host req (bucket -. 1.)) nonce)
  in
  match nonce with
  | Some nonce when solved nonce ->
      let expiry = now () +. t.ttl in
      let signature = jwt t ~host req expiry in
      let max_age = int_of_float t.ttl in
      let cookie = Cookie.set ~max_age cookie signature in
      let headers = [ text; no_store; cookie; ("location", redir) ] in
      respond reqd ~status:`Found ~headers "Found\n"
  | _ ->
      Log.warn (fun m -> m "Invalid proof-of-work from %s" req.ip);
      respond reqd ~status:`Forbidden ~headers:[ text; no_store ]
        "Invalid proof-of-work\n"

(* NOTE(dinosaure): allow some robots... *)
let is_allowed path = path = "/robots.txt" || path = "/favicon.ico"

let intercept t ~host ~ip reqd =
  let req = request_of_reqd ip reqd in
  let user_agent = header req "user-agent" in
  if req.path = prefix ^ "challenge.js" then (serve_script reqd; `Responded)
  else if req.path = prefix ^ "pass" then (pass t ~host req reqd; `Responded)
  else if is_allowed req.path then `Forward
  else if is_ai_bot user_agent then (deny reqd; `Responded)
  else if
    not (contains ~sub:"Mozilla" user_agent)
    (* NOTE(dinosaure): I'm a web browser? *)
  then `Forward
  else if has_valid_cookie t ~host req then `Forward
  else
    match req.meth with
    | `GET | `HEAD ->
        serve_challenge t ~host req reqd;
        `Responded
    | _ -> deny reqd; `Responded
