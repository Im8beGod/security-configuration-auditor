# Architecture Documentation

SIH 26155 uses the following baseline architecture:

React + TypeScript
→ FastAPI modular monolith
→ PostgreSQL + JSONB
→ protected artifact storage
→ one background worker system

The trusted processing path is:

Raw Configuration
→ Structural IR
→ Semantic Interpretation
→ Canonical Security Facts
→ Effective Security State
→ Deterministic Compliance
→ Findings
→ Reports

AI remains outside the trusted compliance verdict path.

Implementation must preserve these architectural boundaries.
