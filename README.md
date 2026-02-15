OpenClaw Host Monitoring

Local security data lake for a single Ubuntu machine running OpenClaw.
Provisioning in this repo installs OpenCreel (the monitor), not OpenClaw itself.

Thin slice:
- Bronze: unmodified Zeek JSON logs under `/var/lib/open-creel/data/bronze/zeek`.
- Silver: OCSF `network_activity` events from Zeek `conn.log`, enriched with DNS query names from `dns.log` into `dst_endpoint.hostname`, via `stub_worker.py`.
- Entry point: `make silver`.
- Databricks-ready interface: `stub_worker.py --bronze-uri <uri> --silver-uri <uri>`.
