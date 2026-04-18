# @category Analysis
# @description Decompile FUN_008324e0 (HavokStopStart) and identify what mode=0 vs mode=1 do internally.
#
# Questions this answers:
#  Q1. Is mode=0 a transient drain (wait-for-idle) or a persistent disable?
#  Q2. What does mode=1 do (our start_havok() call)?
#  Q3. Are the modes symmetrical (stop/start) or asymmetrical?
#  Q4. Are there more modes (2, 3, ...) we haven't discovered?
#
# Why this matters:
#  We plan to call stop_havok_drain() before our periodic Stage 4 to fix
#  the AI Linear Task Thread crash at 0x00C94DA5. Need to confirm mode=0
#  is safe to call mid-gameplay -- if it permanently disables PPL we'd
#  silently break AI Linear Task Thread dispatch after the first Stage 4
#  call.

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

# --- Main body ---

write("######################################################################")
write("# FUN_008324e0 HavokStopStart mode analysis")
write("######################################################################")
write("")
write("Purpose: understand mode=0 (drain/stop) and mode=1 (start) branches")
write("so we can safely call stop_havok_drain(0) before our Stage 4 without")
write("permanently disabling PPL AI Linear Task Thread dispatch.")

# The target function itself.
decompile_at(0x008324e0, "HavokStopStart entry", max_len=10000)

# Its direct callees. These implement the actual drain / start logic.
find_and_print_calls_from(0x008324e0, "HavokStopStart")

# Who calls it? Vanilla callsites tell us the established protocol.
find_refs_to(0x008324e0, "HavokStopStart")

# Decompile a few likely internal functions that implement mode-specific
# behaviour. We don't know their exact addresses yet, so write a header
# placeholder to fill after examining the call list above.
write("")
write("######################################################################")
write("# Internal worker functions -- fill these in after inspecting the")
write("# Calls FROM block above. Expected pattern: one function per mode")
write("# (stop_ppl_drain, start_ppl_resume, ...). Re-run script with")
write("# addresses filled in, or manually decompile in Ghidra UI.")
write("######################################################################")
write("")
write("Candidates to decompile on a second pass:")
write("  - the function called ONLY in the mode=0 branch (drain worker)")
write("  - the function called ONLY in the mode=1 branch (resume worker)")
write("  - any shared helper (PPL task-group accessor)")

# --- Output ---

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/stop_havok_drain_mode_analysis.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
