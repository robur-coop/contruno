type t
type daemon
type chain = X509.Certificate.t list * X509.Private_key.t

val tls : t -> Tls.Config.server option
val add : t -> [ `host ] Domain_name.t -> unit

val create :
     ?entries:([ `host ] Domain_name.t * chain) list
  -> ?add:([ `host ] Domain_name.t -> chain -> unit)
  -> Ask.cfg
  -> production:bool
  -> Mnet_happy_eyeballs.t
  -> t * daemon

val kill : daemon -> unit
