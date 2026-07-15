#!/bin/sh
# installs kamailio (+ msrp/outbound/tls modules) on the pinned debian base at first
# start (mirrors the dropbear/ldap-seed apt-at-runtime pattern in compose.yml), then
# execs kamailio in the foreground so it is PID 1 and docker owns its lifecycle.
set -eu

export DEBIAN_FRONTEND=noninteractive

if ! command -v kamailio >/dev/null 2>&1; then
	apt-get update
	apt-get install -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold \
		kamailio \
		kamailio-extra-modules \
		kamailio-outbound-modules \
		kamailio-tls-modules \
		openssl
	rm -rf /var/lib/apt/lists/*
fi

# -DD: do not daemonize the creator (stay PID 1 in the foreground) but DO fork the full
# worker set incl. the tcp receivers that bind the sockets. -D alone is single-process
# "no fork" mode and never binds the listeners. -E logs to stderr for docker.
# config is mounted read-only at /sip/kamailio.cfg (NOT over the package conffile at
# /etc/kamailio/kamailio.cfg, which would break dpkg's conffile prompt on install).
KAM_ARGS="-DD -E -f /sip/kamailio.cfg"

# optional SIP-over-TLS on 5061: set SIP_TLS=1 to generate a self-signed cert and
# enable the tls listener (WITH_TLS). off by default so plain TCP 5060 is guaranteed.
if [ "${SIP_TLS:-0}" = "1" ]; then
	if [ ! -f /etc/kamailio/tls-cert.pem ]; then
		openssl req -x509 -newkey rsa:2048 -nodes \
			-keyout /etc/kamailio/tls-key.pem \
			-out /etc/kamailio/tls-cert.pem \
			-days 3650 -subj "/CN=edgeport.test" >/dev/null 2>&1
	fi
	cat > /etc/kamailio/tls.cfg <<-EOF
	[server:default]
	method = TLSv1.2+
	private_key = /etc/kamailio/tls-key.pem
	certificate = /etc/kamailio/tls-cert.pem
	verify_certificate = no
	require_certificate = no
	EOF
	KAM_ARGS="$KAM_ARGS -A WITH_TLS"
fi

exec kamailio $KAM_ARGS
