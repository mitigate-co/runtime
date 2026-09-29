# ADR 0039: Run optional delivery as an explicit foreground process

Status: implemented; inventory/fleet composition and release gates remain open.

Per-event manual delivery cannot keep up with a long-running gateway. Starting
network work from enrollment or local protection would conflate those actions
with consent and couple MCP availability to an optional hosted service.

Add `mitigate sync run --profile PROFILE`. It never enrolls, enables, resumes,
installs a daemon or changes the destination. A separate blocking worker uses the
existing immutable sync profile, native owner, budgeted lease and signed HTTPS
composition. The real synthetic admission/storage privacy probe must pass before
delivery starts; a ready manual send also applies this gate. Failure stops with
a closed diagnostic rather than retrying the privacy probe.

Read-only readiness keeps an empty or backing-off sender away from native
credentials. Only due local maintenance writes the queue. Every ready attempt
still rechecks authority through the original owner and exact committed lease;
readiness is never authorization. Per-process pacing adds no global quota or
new persisted state. Retry identity/backoff and permanent-refusal handling stay
with the existing outbox. Undocumented storage or native errors are fatal.

Install signal handling before starting the worker. Ctrl-C, and SIGTERM on Unix,
request stop through a bounded local channel. Stop is checked before native
access; an already-started operation is awaited. Reporting stopped is not a
claim to have retracted transmitted data. Native prompts, blocked output and OS
suspension are not falsely bounded by the HTTP deadline. Force termination may
leave an ordinary lease needing recovery.

Process interruption leaves durable consent unchanged. `sync pause` remains
the operation that withdraws and certifies drain across cooperating senders.
The worker exits on observed pause or remote authorization/redirect pause and
never resumes itself. A quick explicit pause/resume between readiness polls may
leave it running; per-attempt consent and capture generation checks remain in
force. No fleet health or coverage claims are inferred from running this process.

Progress has a separate closed JSON Lines contract; existing single-operation
reports do not change. No wire, profile, SQLite or dependency version changes.
Driver tests cover interrupted work, backoff and fatal errors; actual executable
fixtures cover failed privacy probes, empty parallel senders, pause and Unix
signals. Existing private TLS fixtures verify signed delivery/receipt behavior
without exposing insecure transport overrides in production.
