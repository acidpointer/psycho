# @category Analysis
# @description Trace OOM_STAGE_EXEC (FUN_00866a90) for stage=4 to confirm it frees Havok data.
#
# Questions this answers:
#  Q1. Does the game's stage=4 branch in FUN_00866a90 actually free Havok
#      collision shapes / entities?
#  Q2. Does it call havok_gc (FUN_00c459d0) directly, or via an intermediate?
#  Q3. Are there paths from stage=4 into Havok internals (0x00C9xxxx region)
#      that could be racing with AI Linear Task Threads?
#
# Why this matters:
#  We see a 10-second cadence of "[OOM] Stage 4 freed=..." immediately
#  preceding the 0x00C94DA5 crash on AI Linear Task Thread 1. The diagnosis
#  is that stage 4 frees Havok data without draining PPL first. This script
#  verifies that the stage=4 branch in FUN_00866a90 actually reaches Havok
#  cleanup code (rather than e.g. only touching NiNode PDD queues).

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
	write("  Function: %s @ 0x%08x, Size: %d bytes" % (func.getName(), faddr, func.getBody().getNumAddresses()))
	if faddr != addr_int:
		write("  NOTE: Requested 0x%08x is inside %s (entry at 0x%08x)" % (addr_int, func.getName(), faddr))
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		write(code[:max_len])
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
	havok_hits = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				tgt_func = fm.getFunctionAt(toAddr(tgt))
				name = tgt_func.getName() if tgt_func else "???"
				marker = ""
				# Havok code region is roughly 0x00C00000-0x00D0FFFF based
				# on observed addresses (FUN_00c459d0 havok_gc,
				# FUN_00c94bd0 AddEntities, FUN_00c3dd8e caller chain).
				if 0x00C00000 <= tgt <= 0x00D10000:
					marker = "  [HAVOK]"
					havok_hits += 1
				elif tgt == 0x00C459D0:
					marker = "  [HAVOK_GC]"
					havok_hits += 1
				write("  0x%08x -> 0x%08x %s%s" % (inst.getAddress().getOffset(), tgt, name, marker))
				count += 1
	write("  Total: %d calls (%d into Havok range)" % (count, havok_hits))

def find_stage4_branch_callees(addr_int, label):
	# Decompile OOM_STAGE_EXEC and look for the stage=4 case. Then show
	# what that case calls.
	#
	# The full function is a switch-on-stage. Decompilation already shows
	# the structure. Human-readable output helps us identify which callees
	# belong to stage=4.
	write("")
	write("######################################################################")
	write("# %s @ 0x%08x -- look for the 'case 4' branch in the decompile" % (label, addr_int))
	write("######################################################################")
	decompile_at(addr_int, label, max_len=16000)

# --- Main body ---

write("######################################################################")
write("# OOM_STAGE_EXEC stage=4 Havok trace")
write("######################################################################")
write("")
write("Confirming that FUN_00866a90 with stage=4 reaches Havok cleanup code.")
write("If yes, our periodic maybe_drain_pdd() trigger needs a stop_havok_drain")
write("call before it. If no, the 0x00C94DA5 crash has a different trigger we")
write("need to hunt for.")

# Decompile OOM_STAGE_EXEC. Large function; reader identifies the stage 4
# branch in the switch.
find_stage4_branch_callees(0x00866a90, "OOM_STAGE_EXEC")

# Direct callees -- anything in the Havok address range is flagged.
find_and_print_calls_from(0x00866a90, "OOM_STAGE_EXEC")

# Related Havok-adjacent functions we already know about.
decompile_at(0x00C459D0, "havok_gc / HavokGC_AsyncFlush", max_len=3000)

# Also show AddEntities which is where the crash lands, for cross-reference
# with what stage 4 frees.
decompile_at(0x00C94BD0, "Havok AddEntities (crash site function entry)", max_len=4000)

# --- Output ---

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/oom_stage4_havok_trace.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
