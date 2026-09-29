# ADR 0034: Bind explicit sync consent to the original native owner

Status: implemented local controls and single-attempt CLI; no background producer.

A paused queue alone cannot prove an already active HTTPS request has finished.
Opt-out must also work when the native credential store is unavailable. Requiring
the key to pause would make a failed unlock prompt prevent withdrawal.

Create one bounded immutable local profile after confirming native enrollment.
It pins the queue partition, original canonical Platform, original enrollment
anchor and its opaque native reference. Secret values remain exclusively in the
native broker. Profile creation is explicit consent; enrollment never creates it.
Existing files are never overwritten, and interrupted setup is not auto-repaired.

Every send and resume restores the exact confirmed native record under its
existing operation lock. Pause first commits withdrawal to SQLite without that
lock, then waits for the anchor owner to drain. It verifies the bound anchor and
reasserts pause under the lock before reporting completion or purging. The drain
does not read native credentials. A bounded timeout reports incomplete shutdown,
while keeping new sends paused. Closing a connection cannot retract sent bytes.

The existing local-file, trusted-parent and same-user threat assumptions apply.
No new lock file, database schema, dependency, wire field, cloud authority or key
storage is introduced. Status is a local observation and never claims active
delivery has drained. Future background senders must use the same ownership path.

Enrollment CLI output advances to version 2: it reports sync as not checked,
because its previous unconditional disabled flag becomes false after independent
sync setup. The enrollment wire protocol stays version 1. Sync commands have
their own version-one closed reports and one explicit send at a time. The egress
inspector also advances to report version 2, with delivery not checked rather than
an unconditional unconfigured claim. Event/outbox/privacy-test schemas stay intact.
