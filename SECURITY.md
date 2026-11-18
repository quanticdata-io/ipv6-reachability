# Security policy

## Supported versions

Security fixes are released for the latest minor version.

## Reporting a vulnerability

Please do not open a public issue for security problems. Email **hello@quanticdata.io** with "ipv6-reachability security" in the subject, a description of the issue and, if possible, steps to reproduce. You will get an answer within 3 working days, and we will agree on a disclosure date with you once a fix is ready.

## Credentials

Proxy passwords given with `--via` are masked in every output. The QuanticData flags read the API key only from `QUANTICDATA_API_KEY` and send it only to the API host (`QUANTICDATA_API_BASE`, default `https://api.quanticdata.io/v1`). DNS-over-HTTPS queries (`--doh`) send the target host names to the server you choose. Report any path where a credential is printed, logged or sent elsewhere.
