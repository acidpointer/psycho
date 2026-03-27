# @category Analysis
# @description Trace NVSE ScriptAnalyzer crash — is script bytecode allocated
#   through our hooked path or through FUN_00aa13e0 (unverified path)?
#
# Crash: ScriptAnalyzer.cpp:162, eax=0, during kNVSE animation callback
# Script FormID 6E0B2AC4 from "Titans of The New West.esp" (INITIALIZED)
# ScriptTokenCacheFormExtraData on stack
#
# Questions:
#   1. How are Script objects allocated? Through FUN_00401000 (hooked)?
#   2. How is script bytecode data allocated? Same path or different?
#   3. Does ScriptTokenCacheFormExtraData use FUN_00aa13e0?
#   4. What is FUN_00aa13e0 actually? Does it go through our hooks?
#   5. What does ScriptAnalyzer access at the crash point?
#   6. Can a Script be INITIALIZED but have freed bytecode data?
#   7. Is this crash reproducible without our mod (vanilla + same mods)?

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


write("NVSE Script Crash Research")
write("=" * 70)

# ===================================================================
# PART 1: FUN_00aa13e0 — the 61-caller alternative alloc
# ===================================================================
write("")
write("#" * 70)
write("# PART 1: FUN_00aa13e0 Deep Dive")
write("#" * 70)
write("# DAT_011f6080 → *DAT_011f6080 → vtable[1] called with 7 params")
write("# Does this go through our MemoryHeap hooks?")
write("# FUN_00aa2020 sets: DAT_011f6080 = alloc(4)")
write("#   *DAT_011f6080 = FUN_009fd0f0(DAT_011f6118) = *DAT_011f6118")
write("# So *DAT_011f6080 = *DAT_011f6118. What is at DAT_011f6118?")

decompile_at(0x00aa13e0, "Alternative alloc (61 callers)")
find_and_print_calls_from(0x00aa13e0, "Alternative alloc")

# What does vtable[1] of *DAT_011f6080 point to?
# DAT_011f6118 is set during init. Let's trace.
decompile_at(0x00aa20b0, "Init function that writes DAT_011f6118")
find_and_print_calls_from(0x00aa20b0, "Init DAT_011f6118")

# FUN_00aa2170 reads DAT_011f6118
decompile_at(0x00aa2170, "Reader of DAT_011f6118")

# ===================================================================
# PART 2: FUN_00aa4060 — does it handle FUN_00aa13e0 allocations?
# ===================================================================
write("")
write("#" * 70)
write("# PART 2: Free Path for FUN_00aa13e0 Allocations")
write("#" * 70)
write("# If objects are allocated via FUN_00aa13e0 (vtable[1] of *DAT_011f6080)")
write("# but freed via FUN_00aa4060 (our hooked free path)...")
write("# Does FUN_00aa4060 know about these allocations?")

# FUN_00aa4060 checks: is pointer in a pool? If not, lookup via FUN_00aa45a0.
# FUN_00aa45a0 searches for the correct heap. If FUN_00aa13e0 allocates from
# a DIFFERENT heap that FUN_00aa45a0 doesn't know about → mismatch.

decompile_at(0x00aa45a0, "Heap lookup for free (FUN_00aa45a0)")
find_and_print_calls_from(0x00aa45a0, "Heap lookup")

# FUN_00aa42c0 — fallback free (CRT free?)
decompile_at(0x00aa42c0, "Fallback free (FUN_00aa42c0)")
find_and_print_calls_from(0x00aa42c0, "Fallback free")

# ===================================================================
# PART 3: Script object structure — where is bytecode stored?
# ===================================================================
write("")
write("#" * 70)
write("# PART 3: Script Object Layout")
write("#" * 70)
write("# Script vtable at 0x01037094")
write("# Need: where is bytecode data pointer? What offset?")

# Script::Execute or similar — accesses bytecode
# The animation callback chain goes:
# kNVSE → CallFunctionScript → UserFunctionManager::Call → GetFunctionInfo → ScriptAnalyzer
# ScriptAnalyzer parses script data. What field does it read?

# FUN_00494980 area — animation/script system
decompile_at(0x0049498E, "Animation callback entry (from crash stack)")

decompile_at(0x0049484B, "Animation callback inner")

# ===================================================================
# PART 4: FUN_00aa1070 — another DAT_011f6080 user
# ===================================================================
write("")
write("#" * 70)
write("# PART 4: Other DAT_011f6080 Users")
write("#" * 70)
write("# Multiple functions use DAT_011f6080 for alloc/realloc/free")

decompile_at(0x00aa1070, "DAT_011f6080 user 1 (free?)")
decompile_at(0x00aa10f0, "DAT_011f6080 user 2 (realloc?)")
decompile_at(0x00aa1420, "DAT_011f6080 user 3")
decompile_at(0x00aa1460, "DAT_011f6080 user 4")

# ===================================================================
# PART 5: Who allocates Script bytecode?
# ===================================================================
write("")
write("#" * 70)
write("# PART 5: Script Bytecode Allocation")
write("#" * 70)
write("# Script forms have bytecode at some offset. Who allocates it?")
write("# NVSE runtime scripts (FormID 6E...) are created dynamically.")

# Script constructor or data setter
# Script vtable 0x01037094 — find constructor
find_refs_to(0x01037094, "Script vtable (who constructs Scripts?)")

# FUN_005aa670 — Script-related (compile/load?)
decompile_at(0x005aa670, "Script compile/load area")

# ===================================================================
# PART 6: The freeze — what stalls after watchdog signal?
# ===================================================================
write("")
write("#" * 70)
write("# PART 6: Freeze Analysis (separate from script crash)")
write("#" * 70)
write("# Freeze at commit=1.7GB, quarantine=512MB.")
write("# Last activity: evictions, then watchdog, then silence.")
write("# Same pattern as HeapCompact stage 4 freeze but NO stage 4 signaled!")
write("# What runs between Phase 7 (eviction) and next frame?")

# FUN_0086FA31 from crash stack — what is this?
decompile_at(0x0086FA31, "Main loop at freeze (FUN_0086FA31)")

# FUN_0086E765 from crash stack
decompile_at(0x0086E765, "Main loop outer at freeze")

# FUN_009426B3 — process manager?
decompile_at(0x009426B3, "Process/AI at freeze")

# FUN_00897392 — AI processing?
decompile_at(0x00897392, "AI at freeze")


write("")
write("=" * 70)
write("ANALYSIS COMPLETE")
write("=" * 70)

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/bulletproof_script_crash.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
