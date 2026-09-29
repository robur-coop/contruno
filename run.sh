!/bin/bash

albatross-client create --destination localhost contruno contruno.hvt \
	--arg="--ipv4=10.0.0.2/24" --arg="--ipv4-gateway=10.0.0.1" \
	--arg="--account-key-type=p256"  \
	--arg="--cert-key-type=p256" \
	--arg="--email=foo@bar.com" \
	--arg="--admin-password=MON_SUPER_PASSWORD" \
	--arg="--production" \
	--net service --net metrics --block certs:certs --mem 512 \
	--force --restart-on-fail --no-add-name
