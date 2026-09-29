# ADR 0040: Validate bounded inventory parts before enabling inventory sync

Status: candidate protocol and pure assembly implemented; producer/receiver
composition and activation remain required under MCP-018.

Call activity cannot establish a server's complete tool inventory. Treating absent
events as absent tools would mislead customers during startup, opt-out, overload,
network failure or retention expiry. Uploading local inventory exports would also
send labels and definition details outside the approved privacy boundary.

Define a separate closed version-two `mcp_inventory_snapshot` candidate, with
independent random runtime/server/tool/revision/snapshot references and fixed
classification facts only. Four tools per part fit the existing 4 KiB limit even
with every taxonomy value. The current local 512-tool bound yields at most 128
parts; zero tools is represented by one explicit empty part. No names, content
hashes, arbitrary fields or larger transport limits are added.

Pure assembly requires all indices, consistent scope/time/counts, distinct events
and globally reference-sorted unique tools. Incomplete and conflicting uploads
never produce a complete snapshot. The caller remains responsible for verified
enrollment/tenant scope, exact retry deduplication, capacity and retention. A
complete observation is not a heartbeat, current installation or fleet coverage.

Keep the checked candidate type distinct from the admitted decision event until
producer, egress diagnostics, consent, signing and hosted ingest are composed.
Existing queues and the inspector continue to accept/report only their actual
supported decision contract. This avoids activating unsupported uploads against
the existing receiver or falsely reporting candidate validation as delivery.
Unknown future vocabulary remains rejected; expanding either protocol requires
an explicit reviewed version/receiver change.
