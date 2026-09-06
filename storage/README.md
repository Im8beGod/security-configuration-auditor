# Runtime Storage

The initial SIH implementation uses protected local filesystem storage.

Directories:

- artifacts/ — uploaded raw evidence
- reports/ — generated reports

Runtime evidence and generated reports must not be committed to Git.

Later application code must access these locations through a storage abstraction
rather than scattering direct filesystem paths throughout domain code.
