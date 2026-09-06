# Runtime Storage

The initial SIH implementation uses protected local filesystem storage.

Directories:

- artifacts/ — uploaded raw evidence
- reports/ — generated reports

Runtime evidence and generated reports must not be committed to Git.

Later application code must access these locations through a storage abstraction
rather than scattering direct filesystem paths throughout domain code.

Raw artifact bytes live outside PostgreSQL. The current backend stores them on the
local filesystem through `ArtifactStorage`; callers persist only a logical reference
of the form `organizations/<organization UUID>/artifacts/<artifact UUID>`.
Original filenames are metadata only and never influence physical placement.

Local writes are immutable and atomically published: an existing reference is never
silently overwritten. Reads and existence checks validate the logical format,
resolved-root containment, and symlink destination. A future object-storage backend
can implement the same small write/read/exists abstraction. Upload, hashing,
validation, and Artifact-row creation remain Step 4 responsibilities.
