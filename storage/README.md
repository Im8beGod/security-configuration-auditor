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
can implement the same small abstraction. Deletion exists only for compensation
when persistence fails after a successful write; raw bytes belonging to a
persisted Artifact remain immutable.

Step 4A accepts authenticated single and bulk uploads through `/api/v1/artifacts`.
Files are read in bounded chunks, validated before storage, and persisted with a
canonical Artifact row. Bulk validation failures are isolated per file.
