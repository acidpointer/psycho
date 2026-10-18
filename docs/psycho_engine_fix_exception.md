# Reporter-only Psycho engine-fix exception

Status: active exception.

Last updated: 2026-10-18.

This exception applies only to `psycho-engine-fixes`. It permits an unreleased
defensive candidate when a supplied real-runtime report proves the faulting
native consumer and invalid input contract, but neither the reporter's workload
nor a local reproduction is available. An explicit user authorization is
required for the named incident.

The authorization overrides only the fail-first, same-test, and
no-production-edit rules for that incident. It does not relax no-guessing,
binary-contract, scope, safety, compatibility, or reporting.

Before editing, prove the shared intervention point, complete native caller
coverage, ABI, every field or callback inspected, and a fail-closed result
callers already tolerate. Keep the invalidating owner, exact race, allocator
attribution, and mod attribution unresolved unless direct evidence proves them.

The candidate must be allocator-mode and mod agnostic. Do not classify
ownership, identify modules, allowlist vtables or code, mutate ownership or
reference counts, hook destructors, or patch another mod. Valid inputs chain the
installed provider unchanged; invalid inputs take only the proven fail-closed
result.

Static qualification requires focused tests, the supported 32-bit release
build, formatting, `git diff --check`, final diff review, and a durable contract
that separates runtime evidence, binary proof, and unresolved facts.

Hand off only as a reporter-validation candidate. Do not release, package,
commit, or describe runtime behavior as accepted until the reporter confirms at
least one guard rejection and continued gameplay. If the change affects the
pre-deferred startup footprint, the startup document's Proton load-to-gameplay
gate still applies to release.
