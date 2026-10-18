# <Feature> contract

Status: <implemented | static-only | runtime-accepted | superseded>

Last updated: <YYYY-MM-DD>

## Purpose and scope

<What problem this owns, what is in scope, what is explicitly out of scope.>

## User-visible behavior

<Configuration, defaults, restart/live behavior, disabled fallback.>

## Evidence

- Runtime evidence: <paths>
- Binary proof: <executable identity and analysis paths>
- Static observation: <what follows from code but was not executed>
- Unresolved: <what direct evidence does not prove>

## Native contract

<Addresses, signatures, layouts, calling conventions, caller coverage,
intervention point. Reverify before reuse.>

## Ownership and lifecycle

<Allocator, refcounts, vtables, thread ownership, install/remove order,
startup phase, teardown.>

## Failure behavior

<What happens on invalid input, missing resource, ownership conflict, OOM,
or unsupported engine state. What valid behavior is preserved.>

## Performance

<Work avoided, work added, bounded costs, hot-path constraints, measured
offline budgets. Never claim an FPS result without runtime evidence.>

## Configuration and compatibility

<Schema, defaults, migration, MCM/dashboard ownership, compatibility policy.>

## Validation

<Focused tests, affected suite, release build, formatting, diff check,
game-only behavior not run.>

## Unresolved

<Only facts that remain genuinely unknown. Do not fill them with inference.>
