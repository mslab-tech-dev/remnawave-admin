# CDN Policy plugin

Plugin API v1 wheel for per-inbound CDN shaping/drop policies.

## Build and install

Build the package from this directory:

```bash
python -m pip wheel --no-deps . -w dist/
```

Install the wheel through **Plugins → Upload wheel** in Remnawave Admin and restart the backend. The plugin adds the **CDN Policy** page. Select a node and its `::1` CDN inbound, then choose `shape` with one shared download/upload rate or `drop`.

The backend must include this fork's Plugin API additions. Build and publish the updated node-agent image from this fork, then install it on the selected nodes. Set `AGENT_COMMAND_ENABLED=true` and `AGENT_CDN_SHAPING_ENABLED=true` in the agent environment. The CDN Policy plugin only targets selected loopback inbound tags and IPv4 clients.

## Behavior

Only IPs classified as non-mobile are sent to the agent policy map. Mobile, unknown, and IPv6 CDN clients bypass the per-inbound general policy. Existing personal speed limits remain independent. GeoIP unknowns are retried; confirmed results are cached in backend memory for one day.

The agent needs the nginx/Xray loopback label setup described in `node-agent/README.md`. Before production, run the live-node acceptance checks for `lo`, `tc`, the BPF verifier, throughput, and agent restart behavior. This package cannot prove those host/kernel-specific properties by itself.
