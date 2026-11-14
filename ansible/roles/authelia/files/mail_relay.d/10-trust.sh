# Sourced by the mail relay image at start, after it has applied the
# POSTFIX_* variables.
#
# The image lowercases the names of those variables, and Postfix parameter
# names are case-sensitive: POSTFIX_smtp_tls_CAfile arrived as
# smtp_tls_cafile, which Postfix ignores. A relay told to verify the external
# server but given no CA file trusts nothing, so every message waited in the
# queue as "Server certificate not verified". Names with capitals are set
# here instead.
postconf -e 'smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt'
