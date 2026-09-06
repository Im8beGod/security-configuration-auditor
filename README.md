# SIH 26155 — AI-Driven Multi-Vendor Network Security Compliance Auditor

Smart India Hackathon Problem Statement 26155.

## Purpose

A centralized, AI-augmented, vendor-agnostic network security compliance
auditor for heterogeneous network-device configuration evidence.

The system will normalize vendor-specific configuration meaning, resolve
effective security state, deterministically evaluate compliance requirements,
preserve evidence and provenance, provide remediation guidance, and generate
auditable reports.

## Architecture

The SIH prototype uses a modular monolith with one background worker system.

Technology baseline:

- React + TypeScript
- Python + FastAPI
- PostgreSQL + JSONB
- protected filesystem artifact storage
- Docker
- Docker Compose

Trusted future processing pipeline:

Raw Configuration
→ Structural IR
→ Semantic Interpretation
→ Canonical Security Facts
→ Effective Security State
→ Deterministic Compliance
→ Findings
→ Reports

AI assists interpretation and adaptation but does not make trusted final
compliance decisions.

## Repository Structure

- backend/ — FastAPI application and domain modules
- frontend/ — React + TypeScript application
- worker/ — background worker deployment boundary
- database/ — migration and initialization structure
- storage/ — runtime artifacts and reports
- docs/ — architecture, contracts and development documentation
- tests/ — future repository-wide tests
- scripts/ — development automation
- .github/ — GitHub Actions workflows

## Prerequisites

- Python 3.13+
- Node.js
- npm
- Git
- Docker Desktop
- Docker Compose
- GitHub CLI

## Backend

From the backend directory:

    python -m venv .venv
    .\.venv\Scripts\Activate.ps1
    pip install -r requirements.txt
    python -m pytest -v
    uvicorn app.main:app --reload

Health endpoint:

    http://localhost:8000/health

## Frontend

From the frontend directory:

    npm install
    npm run dev

Development URL:

    http://localhost:5173

## Docker

Validate:

    docker compose config

Build:

    docker compose build

Start:

    docker compose up -d

Inspect:

    docker compose ps -a

Stop:

    docker compose down

PostgreSQL uses container port 5432 and host port 5433 by default.

## Environment

Use `.env.example` as the environment template.

Real `.env` files, secrets, uploaded artifacts and generated reports must
never be committed.

## Current Status

- Step 1 — Implementation Contracts: COMPLETE / FROZEN
- Step 2 — Repository Setup: IN PROGRESS
- Step 3 — Basic Platform Skeleton: NOT STARTED

No production auditing functionality has been implemented yet.
