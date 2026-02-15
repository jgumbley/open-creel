OpenClaw Host Monitoring

Local security data lake for a single Ubuntu machine running OpenClaw.
Provisioning in this repo installs OpenCreel (the monitor), not OpenClaw itself.

Thin slice:
- Bronze: unmodified Zeek JSON logs under `/var/lib/open-creel/data/bronze/zeek`.
- Silver: OCSF `network_activity` from `conn.log`, enriched from sibling `dns.log` into `dst_endpoint.hostname` when a DNS answer matches destination IP within TTL.
- Run: `make silver` (inspect latest record with `make silver-proof`).
- Databricks-ready interface: `stub_worker.py --bronze-uri <uri> --silver-uri <uri>`.
