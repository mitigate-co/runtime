# ADR 0032: Bind event transport to confirmed native enrollment

Status: accepted for MCP-018 transport implementation.

The pure event signature contract deliberately does not confer local enrollment
or consent. The explicit network API must not accept a caller-supplied key and
destination as if they were the native enrollment.

`EnrollmentStore::sign_event` therefore requires the confirmed persisted phase,
uses its original key/identity/pinned origin and checks the lease partition. Failed
confirmation consumes the session; reopening must reconcile actual native state
before signing. The HTTPS API borrows that locked store through the whole exchange
and returns only an authenticated, exactly bound receipt. Neither method mutates
consent or queue state.

Bootstrap and event exchange now share one private TLS configuration and bounded
JSON reader. These are concrete repeated requirements for two fixed protocols,
not a public generic networking layer. Public errors retain protocol-specific
meaning; event authority refusal is distinct from a permanent event refusal.
The existing rustls/ureq feature and reviewed dependencies suffice. No new package,
feature, license exception, insecure option or native permission is added.

Keep transport separate from queue completion: only the owning sender knows if a
lease and consent are still current. Bounded synchronous requests are suitable
for that dedicated worker but provide no mid-flight cancellation handle. A later
opt-out operation must coordinate the in-flight request and confirm shutdown;
do not expose continuous sync or claim immediate retraction before that works.
Receiver deduplication, revocation and tenant authority remain independent gates.

Tests use real checked SQLite leases, synthetic native records and ephemeral
loopback TLS. They cover interrupted confirmation, pending refusal, exact key
recovery, wrong queues, certificate/proxy/redirect failures, HTTP classifications,
bound acknowledgments, framing limits and deadlines. The bootstrap suite verifies
the shared reader/configuration too. Native demonstrations preserve OS ACLs and
delete only their own synthetic entries. No hosted deployment is introduced.
