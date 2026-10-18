# <Date> <incident> crash containment

Status: <unreleased candidate | released | rejected>

## Report and evidence

- Supplied report: <path or "owner report">
- Crash Logger: <path>
- Psycho/OMV/Atom log: <path>
- Reproduction: <available | unavailable | game-only>
- Authorization: <exact user instruction, if any>

## Executable identity

<Path, SHA-256, PE class, image base. State whether relocations were applied.>

## Fault

<Exception, faulting instruction, module/RVA, stack/caller chain. State what is
proven and what is only the topmost stack frame.>

## Root cause

<Proven invalid input, ownership, lifetime, race, or allocation contract.
Separate direct proof from inference.>

## Scope and non-goals

<What is contained. What is not proven: owner, race, allocator, mod attribution.
What is explicitly not patched or detected.>

## Intervention

<Failing consumer, caller coverage, layout, ABI, concurrency, safe point.
Why this boundary is the narrowest correct one. Valid-input pass-through.>

## Validation

<Focused tests, affected suite, release build, formatting, diff check. What was
not run.>

## Unresolved

<Attribution, exact race, allocator ownership, mod workload, runtime acceptance.>
