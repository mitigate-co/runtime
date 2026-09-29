# ADR 0036: Bind local references during explicit sync setup

Status: implemented; gateway production remains separate.

Stable random wire identifiers require their original customer-local catalog.
Creating a replacement implicitly after file loss would silently split hosted
identity, while requiring another setup argument would add avoidable work.

New sync setup creates `<outbox filename>.references.sqlite` beside the queue and
pins its absolute path in an immutable version-two profile. Profile, queue and
catalog must be new and distinct. Setup holds the original confirmed native
owner until the complete binding is durable. Partial state is preserved for
inspection; preexisting files are never adopted or replaced.

Resume validates the exact original catalog and enrollment scope before
unpausing. Pause, purge and status do not require the catalog or native secrets.
Purge retains mappings so resumed events keep their identity. Complete retirement
requires shutdown, queued-data purge and native enrollment deletion before the
explicit local files are removed. No automatic catalog reset is introduced.

Version-one profiles keep their closed six-field contract and controls without
migration. Version two requires the seventh field; omitted/null/version-mixed
fields and catalog paths equal to queue/anchor paths are rejected. Wire events, queue schemas and CLI reports
do not change. No producer, sender or additional consent is activated.
