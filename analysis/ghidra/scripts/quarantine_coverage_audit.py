# @category Analysis
# @description Audit ALL paths that call GameHeap::Free vs CRT _free.

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def decompile_at(addr_int, label, max_len=6000):
	addr = toAddr(addr_int)
	func = fm.getFunctionAt(addr)
	if func is None:
		func = fm.getFunctionContaining(addr)
	output.append("")
	output.append("=" * 70)
	output.append("%s @ 0x%08x" % (label, addr_int))
	output.append("=" * 70)
	if func is None:
		output.append("  [function not found]")
		return
	output.append("  Function: %s, Size: %d bytes" % (func.getName(), func.getBody().getNumAddresses()))
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		output.append(code[:max_len])
	else:
		output.append("  [decompilation failed]")

def collect_callers(addr_int):
	addr = toAddr(addr_int)
	callers = []
	refs = getReferencesTo(addr)
	for ref in refs:
		from_addr = ref.getFromAddress()
		func = fm.getFunctionContaining(from_addr)
		fname = func.getName() if func else "???"
		faddr = str(func.getEntryPoint()) if func else str(from_addr)
		output.append("  %s @ %s (in %s @ %s)" % (ref.getReferenceType(), from_addr, fname, faddr))
		callers.append((from_addr, fname))
	output.append("  Total: %d callers" % len(callers))
	return callers

def collect_limited(addr_int, limit):
	addr = toAddr(addr_int)
	refs = getReferencesTo(addr)
	count = 0
	for ref in refs:
		from_addr = ref.getFromAddress()
		func = fm.getFunctionContaining(from_addr)
		fname = func.getName() if func else "???"
		output.append("  %s @ %s (in %s)" % (ref.getReferenceType(), from_addr, fname))
		count += 1
		if count >= limit:
			output.append("  ... (truncated)")
			break
	output.append("  Total: %d refs" % count)

def decompile_callers(callers, limit):
	count = 0
	for from_addr, fname in callers:
		if count >= limit:
			break
		func = fm.getFunctionContaining(from_addr)
		if func:
			decompile_at(func.getEntryPoint().getOffset(), "Caller: %s" % fname)
		count += 1

# === SECTION 1 ===
output.append("### SECTION 1: GameHeap::Free callers (quarantine SAFE)")
gheap_callers = collect_callers(0x00AA4060)

# === SECTION 2 ===
output.append("\n### SECTION 2: FallbackFree callers (BYPASSES quarantine)")
fallback_callers = collect_callers(0x00AA42C0)
decompile_callers(fallback_callers, 10)

# === SECTION 3 ===
output.append("\n### SECTION 3: CRT _free callers")
collect_limited(0x00ECD291, 50)

# === SECTION 4 ===
output.append("\n### SECTION 4: Havok allocator")
decompile_at(0x00C3E0D0, "hkAllocate_GameHeap")
decompile_at(0x00C3E170, "hkDeallocate_GameHeap")

# === SECTION 5 ===
output.append("\n### SECTION 5: NiObject delete + common delete")
decompile_at(0x00401030, "CommonDelete_FUN_00401030")
decompile_at(0x0040FA60, "NiObject_delete_helper")

# === SECTION 6 ===
output.append("\n### SECTION 6: GameHeap::Free internals")
decompile_at(0x00AA4060, "GameHeap_Free")
decompile_at(0x00AA42C0, "FallbackFree")

# === WRITE ===
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/quarantine_coverage_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
print("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
