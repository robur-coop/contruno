#!/bin/bash

[ ! -d "vendors" ] && mkdir vendors
[ ! -d "vendors/bstr" ] && opam source bstr --dir vendors/bstr
[ ! -d "vendors/digestif" ] && opam source digestif --dir vendors/digestif
[ ! -d "vendors/gmp" ] && opam source gmp --dir vendors/gmp
[ ! -d "vendors/kdf" ] && opam source kdf --dir vendors/kdf
[ ! -d "vendors/mirage-crypto-rng-mkernel" ] && opam source mirage-crypto-rng-mkernel --dir vendors/mirage-crypto-rng-mkernel
[ ! -d "vendors/mkernel" ] && opam source mkernel --dir vendors/mkernel
[ ! -d "vendors/mnet" ] && opam source mnet --dir vendors/mnet
[ ! -d "vendors/h1" ] && opam source h1 --dir vendors/h1
[ ! -d "vendors/mhttp" ] && opam source mhttp --dir vendors/mhttp
[ ! -d "vendors/httpcats" ] && opam source httpcats --dir vendors/httpcats
[ ! -d "vendors/utcp" ] && opam source utcp --dir vendors/utcp
[ ! -d "vendors/tls" ] && opam source tls --dir vendors/tls
[ ! -d "vendors/x509" ] && opam source x509 --dir vendors/x509
[ ! -d "vendors/ca-certs-nss" ] && opam source ca-certs-nss --dir vendors/ca-certs-nss
[ ! -d "vendors/zarith" ] && opam source zarith --dir vendors/zarith
[ ! -d "vendors/mirage-ptime" ] && opam source mirage-ptime --dir vendors/mirage-ptime
[ ! -d "vendors/cattery" ] && opam source cattery --dir vendors/cattery
[ ! -d "vendors/mfat" ] && opam source mfat --dir vendors/mfat
[ ! -d "vendors/cachet" ] && opam source cachet --dir vendors/cachet
[ ! -d "vendors/jws" ] && opam source jws --dir vendors/jws
[ ! -d "vendors/letsencrypt" ] && opam source letsencrypt --dir vendors/letsencrypt
[ ! -d "vendors/vif" ] && opam source vif --dir vendors/vif
[ ! -d "vendors/prettym" ] && opam source prettym --dir vendors/prettym
[ ! -d "vendors/multipart_form" ] && opam source multipart_form --dir vendors/multipart_form
[ ! -d "vendors/flux" ] && opam source flux --dir vendors/flux
[ ! -d "vendors/mkernel-memtrace" ] && opam source mkernel-memtrace --dir vendors/mkernel-memtrace
