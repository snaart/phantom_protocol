# OpenTelemetry Observability Refactor — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans`
> to drive this plan task-by-task. Atomic-commit checkboxes live in the
> canonical plan file (see below).

**Goal:** Replace Phantom Core's hand-rolled Prometheus metrics with a full
OpenTelemetry (metrics + traces) pipeline, behind an opt-in `telemetry-otel`
Cargo feature, with cutting-edge perf techniques (cache-line padding,
pre-interned attribute sets, exponential histograms, exemplars, zstd-OTLP).

**Architecture:** Hybrid hot-path/event-path split — lock-free atomics for
per-packet recording feeding OTel observable instruments via `with_callback`,
synchronous OTel labeled instruments + exponential histograms for low-frequency
events. New module `core/src/observability/`; legacy `transport/metrics.rs`
deleted. Server installs OTLP/gRPC exporter with zstd and Delta temporality.

**Tech Stack:** `opentelemetry` 0.27+, `opentelemetry_sdk`, `opentelemetry-otlp`,
`tracing-opentelemetry` 0.28+, `crossbeam-utils::CachePadded`, `tonic` (via OTLP).

---

## Canonical plan location

This plan is a **pointer**. The full design, instrument catalog, performance
techniques, ENV reference, testing plan, and the live atomic-commit rollout
all live in:

**`docs/observability/refactor-plan.md`** — committed in `5db2fbc`.

That file is the single source of truth and the live progress tracker.
The atomic-commit rollout (20 steps) in its §12 is the task list to execute,
with `[ ]` → `[x]` and `SHA` columns updated as each commit lands.

## Why a pointer and not a duplicate

The user requested "Напиши этот план в файл … и делай все до конца" — singular
file, then execute. Duplicating 647 lines of design + rollout into a second
plan file would split the source of truth. The canonical file already
provides:

- Bite-sized atomic commits (each ≤ a single coherent change with clear
  `Files Modified` / `Files Created` implicit in its commit subject)
- A live progress table with checkbox + SHA columns
- Full design context per step (referenced inline in the rollout)
- Open-questions and risk section
- References to upstream OTel specs / OTEPs

## Execution methodology

Each rollout step in §12 of the canonical plan is one atomic commit. For
every step:

1. Make code changes for that step only.
2. Run `cargo check --manifest-path core/Cargo.toml` (and
   `cargo check --features telemetry-otel` from step 6 onward).
3. Run `cargo test --manifest-path core/Cargo.toml --lib` (and
   `cargo clippy --lib` where the step touches public API).
4. Stage only the files for this step.
5. Commit with the subject from the rollout table (no AI-coauthor trailer
   — project convention).
6. Tick `[x]` in the rollout table and paste the short SHA, in a follow-up
   commit if convenient (or as part of the next functional commit's
   tick-update).

For cross-target sanity at intermediate points (after steps 3, 5, 6, 8, 12):
also run `cargo check --target wasm32-unknown-unknown` and
`cargo check --no-default-features --features embedded,no-std --target
thumbv7em-none-eabihf` to keep the hard CI gates green.

## What is NOT in this stub

- Per-commit code listings — those live in the canonical plan inline with
  each rollout row, plus the design sections.
- Test code — covered in §10 of the canonical plan.
- Documentation deliverables — covered in §9.

## Self-review

Spec coverage, placeholder scan, and type-consistency were performed against
`docs/observability/refactor-plan.md` before its commit (`5db2fbc`).

---

## Execution choice

Proceeding with **Inline Execution** per the user's "делай все до конца"
directive — this session has full codebase context that fresh subagents would
have to re-discover. Atomic commits + checkpoint reviews at the end of each
step provide the same safety with less overhead.
