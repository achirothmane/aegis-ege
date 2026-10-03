# Frozen native proof and reference runtime extension

The original `governedaction_tree` remains pinned to
`ce855f44eedf0525e37c001c2c3027c057207308`. Every original executable source,
test, fixture, file type and mode must remain exactly the same. Removing a
frozen file or adding an unregistered file fails verification.

Fenced takeover is an explicitly registered extension: three new files and
an append-only runtime README section. Their exact blobs are recorded in the
cross-domain and Terraform registrations. Any subsequent change to these
blobs fails until a new registration is reviewed. The README must preserve
every byte of its frozen version as a prefix.

The native GitHub, Kubernetes, PostgreSQL and Terraform jobs exercise their
existing frozen contract paths. Their success does not prove native fencing
for `RunFenced`, `ExecuteReservedFenced` or `TakeoverReserved`. The extension
is tested separately by the reference adapter tests, including race checks.

Proof results state that zero semantic delta applies to frozen contract
source. Terraform reports the raw repository core-file delta separately
from the unchanged frozen sources and identifies registered extension files.
An unchanged whole `governedaction` tree is not claimed for this head.
