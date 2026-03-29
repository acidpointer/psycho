# @category Analysis
# @description Research the vanilla game's cleanup flow — how it manages memory
#   WITHOUT HeapCompact signaling, and what condition triggers FUN_008782b0
#
# Key finding: vanilla game NEVER signals HeapCompact during normal gameplay.
# HeapCompact is OOM-only. The game has its own cleanup via FUN_008782b0
# (conditional DeferredCleanupSmall) that we may be interfering with.
#
# Questions:
#   1. What is condition "cVar2 == 3" that gates FUN_008782b0?
#   2. FUN_00424940 returns a state — what states exist?
#   3. FUN_004b7210 — what object does this return?
#   4. FUN_00878160/FUN_00878200 — pre/post destruction — same as our hooks?
#   5. FUN_00878340 — what does this check after DeferredCleanupSmall?
#   6. The 5 callers of DeferredCleanupSmall — what are FUN_004556d0,
#      FUN_0093cdf0, FUN_0093d500, FUN_005b6cd0? When do they run?
#   7. What does the vanilla alloc (FUN_00aa3e40/5e30/5ec0) do on failure?
#   8. How does the vanilla game free memory — SBM pool recycling?

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def write(msg):
	output.append(msg)
	print(msg)

def decompile_at(addr_int, label, max_len=12000):
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
	fsize = func.getBody().getNumAddresses()
	write("  Function: %s @ 0x%08x, Size: %d bytes" % (func.getName(), faddr, fsize))
	if faddr != addr_int:
		write("  NOTE: Requested 0x%08x is inside %s (entry at 0x%08x)" % (addr_int, func.getName(), faddr))
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		if len(code) > max_len:
			write(code[:max_len])
			write("  ... [truncated at %d chars]" % max_len)
		else:
			write(code)
	else:
		write("  [decompilation failed]")

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
		if count > 50:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)


write("Vanilla Cleanup Flow Research")
write("=" * 70)

# ===================================================================
# PART 1: The gating condition for FUN_008782b0
# ===================================================================
write("")
write("#" * 70)
write("# PART 1: FUN_008782b0 Gating Condition")
write("#" * 70)
write("# Main loop code:")
write("#   iVar6 = FUN_004b7210();")
write("#   cVar2 = FUN_00424940(iVar6);")
write("#   if ((cVar2 == 3) && (!bVar1)) { FUN_008782b0(); }")
write("# What is state 3? When is it true?")

decompile_at(0x004b7210, "State object getter (FUN_004b7210)")
find_refs_to(0x004b7210, "State getter callers")

decompile_at(0x00424940, "State value checker (FUN_00424940)")
find_refs_to(0x00424940, "State checker callers")

# ===================================================================
# PART 2: FUN_00878160/FUN_00878200 — pre/post destruction
# ===================================================================
write("")
write("#" * 70)
write("# PART 2: Pre/Post Destruction (used by vanilla cleanup)")
write("#" * 70)

decompile_at(0x00878160, "Pre-destruction setup (FUN_00878160)")
find_and_print_calls_from(0x00878160, "Pre-destruction setup")

decompile_at(0x00878200, "Post-destruction restore (FUN_00878200)")
find_and_print_calls_from(0x00878200, "Post-destruction restore")

# FUN_00878340 — called after DeferredCleanupSmall in vanilla cleanup
decompile_at(0x00878340, "Post-cleanup check (FUN_00878340)")

# ===================================================================
# PART 3: Other DeferredCleanupSmall callers — WHEN do they run?
# ===================================================================
write("")
write("#" * 70)
write("# PART 3: All DeferredCleanupSmall Callers")
write("#" * 70)

decompile_at(0x004556d0, "DCS caller 1 (FUN_004556d0)")
find_and_print_calls_from(0x004556d0, "DCS caller 1")
find_refs_to(0x004556d0, "DCS caller 1 — who calls it?")

decompile_at(0x0093cdf0, "DCS caller 2 (FUN_0093cdf0)")
find_and_print_calls_from(0x0093cdf0, "DCS caller 2")

decompile_at(0x0093d500, "DCS caller 3 (FUN_0093d500)")
find_and_print_calls_from(0x0093d500, "DCS caller 3")

decompile_at(0x005b6cd0, "DCS caller 4 (FUN_005b6cd0)")
find_and_print_calls_from(0x005b6cd0, "DCS caller 4")

# ===================================================================
# PART 4: Vanilla alloc failure paths
# ===================================================================
write("")
write("#" * 70)
write("# PART 4: Vanilla Alloc Failure (FUN_00aa3e40, FUN_00aa5e30)")
write("#" * 70)

decompile_at(0x00aa3e40, "Vanilla alloc 1 (calls OOM executor)")
find_and_print_calls_from(0x00aa3e40, "Vanilla alloc 1")

decompile_at(0x00aa5e30, "Vanilla alloc 2 (calls OOM executor)")
find_and_print_calls_from(0x00aa5e30, "Vanilla alloc 2")

decompile_at(0x00aa5ec0, "Vanilla alloc 3 (calls OOM executor)")
find_and_print_calls_from(0x00aa5ec0, "Vanilla alloc 3")

# ===================================================================
# PART 5: FUN_008782b0 callers — who runs the vanilla cleanup?
# ===================================================================
write("")
write("#" * 70)
write("# PART 5: FUN_008782b0 Callers (vanilla per-frame cleanup)")
write("#" * 70)

find_refs_to(0x008782b0, "Vanilla per-frame cleanup callers")


write("")
write("=" * 70)
write("ANALYSIS COMPLETE")
write("=" * 70)

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/bulletproof_vanilla_cleanup.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
