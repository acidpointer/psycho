# Ghidra Jython Script Rules

These scripts run in Ghidra's Jython (Python 2.7) environment.
Jython has quirks that break standard Python patterns. Follow these
rules exactly or the script will fail with cryptic SyntaxError messages.

## Indentation

Use TABS only. Never spaces. Never mix tabs and spaces. Jython's parser
rejects mixed indentation silently or with misleading errors.

## No tuple unpacking in top-level for loops

This BREAKS:

```python
calls = [(1, 2), (3, 4)]
for src, tgt in calls:
    write("  0x%08x -> 0x%08x" % (src, tgt))
write("done")  # SyntaxError here, pointing at this line
```

The error message is misleading -- it points at the line AFTER the loop,
not at the loop itself. Jython cannot parse tuple unpacking in for loops
at the module's top level after certain preceding statements.

This WORKS -- put the loop inside a function:

```python
def print_calls(calls):
    for src, tgt in calls:
        write("  0x%08x -> 0x%08x" % (src, tgt))
    write("done")

print_calls(my_list)
```

Also works -- iterate without unpacking:

```python
for item in calls:
    write("  0x%08x -> 0x%08x" % (item[0], item[1]))
```

General rule: keep the top-level body simple. Only call helper functions.
Never put complex loops or tuple unpacking at the top level.

## Top-level for loops that DO work

Simple iteration over a single variable is fine at the top level:

```python
for ref in refs:
    from_func = fm.getFunctionContaining(ref.getFromAddress())
    write("  %s" % from_func.getName())
```

But even these are safer inside a function. When in doubt, wrap it.

## While loops with hasNext/next at top level

`while iter.hasNext()` loops at the top level break the same way as
tuple-unpacking for loops. The parser fails on the NEXT statement after
the loop, not on the loop itself.

This BREAKS:

```python
refs = ref_mgr.getReferencesTo(toAddr(0x011dea10))
count = 0
while refs.hasNext():
    refs.next()
    count += 1
write("Total: %d" % count)  # SyntaxError here
```

This WORKS -- wrap in a function:

```python
def count_refs(addr_int):
    refs = ref_mgr.getReferencesTo(toAddr(addr_int))
    c = 0
    while refs.hasNext():
        refs.next()
        c += 1
    return c

result = count_refs(0x011dea10)
write("Total: %d" % result)
```

General rule: ANY loop (for or while) at the top level is risky.
Always wrap loops in helper functions.

## ReferenceIterator usage

`ref_mgr.getReferencesTo()` returns a ReferenceIterator. Use the
hasNext/next pattern inside a function:

```python
def find_refs_to(addr_int, label):
    refs = ref_mgr.getReferencesTo(toAddr(addr_int))
    count = 0
    while refs.hasNext():
        ref = refs.next()
        # ... process ref ...
        count += 1
    write("  Total: %d refs" % count)
```

Do NOT use `for ref in refs` on a ReferenceIterator at the top level.
It sometimes works inside functions but is unreliable at module scope.

## Standard script structure

Every script follows this pattern:

```python
# @category Analysis
# @description One-line description of what this script analyzes

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def write(msg):
    output.append(msg)
    print(msg)

def decompile_at(addr_int, label, max_len=8000):
    # ... standard decompile helper ...

def find_refs_to(addr_int, label):
    # ... standard refs helper using while hasNext ...

def find_and_print_calls_from(addr_int, label):
    # ... standard calls helper, iterates+prints internally ...

# --- Main body: only simple statements and function calls ---

write("TITLE")
decompile_at(0x00AABBCC, "SomeFunction")
find_refs_to(0x00DDEEFF, "SomeGlobal")

# --- Output ---

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/filename.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
```

## Standard helper functions

Copy these into every script. Do not reinvent them.

### decompile_at

Decompiles the function at or containing the given address. Handles
the case where the address is inside a function (not at the entry).

```python
def decompile_at(addr_int, label, max_len=8000):
    addr = toAddr(addr_int)
    func = fm.getFunctionAt(addr)
    if func is None:
        func = fm.getFunctionContaining(addr)
    write("")
    write("=" * 70)
    write("%s @ 0x%08x" % (label, addr_int))
    write("=" * 70)
    if func is None:
        write("  [function not found]")
        return
    faddr = func.getEntryPoint().getOffset()
    write("  Function: %s @ 0x%08x, Size: %d bytes" % (func.getName(), faddr, func.getBody().getNumAddresses()))
    if faddr != addr_int:
        write("  NOTE: Requested 0x%08x is inside %s (entry at 0x%08x)" % (addr_int, func.getName(), faddr))
    result = decomp.decompileFunction(func, 120, monitor)
    if result and result.decompileCompleted():
        code = result.getDecompiledFunction().getC()
        write(code[:max_len])
    else:
        write("  [decompilation failed]")
```

### find_refs_to

Prints all references to a given address. Uses hasNext/next iterator.

```python
def find_refs_to(addr_int, label):
    write("")
    write("-" * 70)
    write("References TO 0x%08x (%s)" % (addr_int, label))
    write("-" * 70)
    refs = ref_mgr.getReferencesTo(toAddr(addr_int))
    count = 0
    while refs.hasNext():
        ref = refs.next()
        from_func = fm.getFunctionContaining(ref.getFromAddress())
        fname = from_func.getName() if from_func else "???"
        write("  %s @ 0x%08x (in %s)" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname))
        count += 1
        if count > 40:
            write("  ... (truncated)")
            break
    write("  Total: %d refs" % count)
```

### find_and_print_calls_from

Finds all call targets from a function and prints them. Iteration
happens inside the function, avoiding top-level tuple unpacking.

```python
def find_and_print_calls_from(addr_int, label):
    func = fm.getFunctionAt(toAddr(addr_int))
    if func is None:
        func = fm.getFunctionContaining(toAddr(addr_int))
    if func is None:
        write("  [function not found at 0x%08x]" % addr_int)
        return
    body = func.getBody()
    inst_iter = currentProgram.getListing().getInstructions(body, True)
    write("")
    write("--- Calls FROM %s (0x%08x) ---" % (label, addr_int))
    count = 0
    while inst_iter.hasNext():
        inst = inst_iter.next()
        refs = inst.getReferencesFrom()
        for ref in refs:
            if ref.getReferenceType().isCall():
                tgt = ref.getToAddress().getOffset()
                tgt_func = fm.getFunctionAt(toAddr(tgt))
                name = tgt_func.getName() if tgt_func else "???"
                write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, name))
                count += 1
    write("  Total: %d calls" % count)
```

### find_callers_in_range

Finds callers of a function that are within an address range. Useful
for finding which subsystem (Havok, game code, etc.) calls a function.

```python
def find_callers_in_range(target_addr, range_start, range_end, label):
    write("")
    write("-" * 70)
    write("%s callers from 0x%08x-0x%08x" % (label, range_start, range_end))
    write("-" * 70)
    refs = ref_mgr.getReferencesTo(toAddr(target_addr))
    count = 0
    while refs.hasNext():
        ref = refs.next()
        src = ref.getFromAddress().getOffset()
        if range_start <= src <= range_end and ref.getReferenceType().isCall():
            func = fm.getFunctionContaining(ref.getFromAddress())
            name = func.getName() if func else "???"
            write("  0x%08x in %s" % (src, name))
            count += 1
    write("  Total: %d callers" % count)
```

## Output path

Always write to the analysis output directory:

```
/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/
/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/
/data/storage0/Workspace/psycho/analysis/ghidra/output/perf/
```

Pick the subdirectory that matches the analysis topic.

## Cleanup

Always call `decomp.dispose()` at the end of the script. Ghidra leaks
memory if you don't.
