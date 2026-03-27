# @category Analysis
# @description Research NPC crash during stress flying — FUN_0086f6a0 post-AI chain
#
# Crash: C0000005 at 0x0047047C during stress flying
# Character "Chapel" with NEED_TO_CHANGE_PROCESS flag
# Callstack: main_loop → 0x0086EE67 → FUN_0086f6a0 → FUN_0096C7AF →
#   FUN_008F64FE → FUN_0047047C (crash, eax=0 ecx=0)
#
# Questions:
#   1. What does FUN_0086f6a0 do? Full decompile.
#   2. What does FUN_0096C7AF do? NPC process transition?
#   3. What does FUN_008F64FE do? What object is NULL?
#   4. What does FUN_0047047C access that's NULL?
#   5. Is this crash related to our quarantine or HeapCompact, or
#      is it a game/mod bug unrelated to our code?
#   6. Does the NEED_TO_CHANGE_PROCESS flag relate to our cleanup?

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


write("NPC Crash Research — Stress Flying")
write("=" * 70)

# ===================================================================
# PART 1: The crash callstack — every function
# ===================================================================
write("")
write("#" * 70)
write("# PART 1: Full Crash Callstack")
write("#" * 70)

decompile_at(0x0086f6a0, "Post-AI function (called from main loop at 0x0086ee62)")
find_and_print_calls_from(0x0086f6a0, "Post-AI function")

decompile_at(0x0096C7AF, "NPC chain 1 (from crash stack)")
find_and_print_calls_from(0x0096C7AF, "NPC chain 1")

decompile_at(0x008F64FE, "NPC chain 2 (from crash stack)")
find_and_print_calls_from(0x008F64FE, "NPC chain 2")

decompile_at(0x0047047C, "CRASH SITE (eax=0, ecx=0)")
find_and_print_calls_from(0x0047047C, "Crash site")

# FUN_00978ACF from stack
decompile_at(0x00978ACF, "Stack entry FUN_00978ACF")

# ===================================================================
# PART 2: What is NEED_TO_CHANGE_PROCESS?
# ===================================================================
write("")
write("#" * 70)
write("# PART 2: NEED_TO_CHANGE_PROCESS Flag")
write("#" * 70)
write("# Character has this flag. Is it set by our code or by the game?")
write("# Flag value from TESForm flags: check what bit it is")

# The flag is in TESForm flags at offset +0x08
# From crash: Flags: MASTER | ALTERED | INITIALIZED | HAS_SPOKEN | PERSISTENT | NEED_TO_CHANGE_PROCESS | TARGETED
# NEED_TO_CHANGE_PROCESS might be a specific bit

# FUN_00450fd0 returns cell state — is it related?
decompile_at(0x00450fd0, "Cell/object state getter")

# ===================================================================
# PART 3: Does vanilla game auto-trigger HeapCompact?
# ===================================================================
write("")
write("#" * 70)
write("# PART 3: Vanilla HeapCompact Auto-Trigger")
write("#" * 70)
write("# Does the game ever write to HEAP_COMPACT_TRIGGER (0x011F636C)")
write("# on its own, without our signal?")

find_refs_to(0x011F636C, "HEAP_COMPACT_TRIGGER")

# ===================================================================
# PART 4: What does the game's own OOM handling do?
# ===================================================================
write("")
write("#" * 70)
write("# PART 4: Vanilla OOM — who calls the stage executor?")
write("#" * 70)

find_refs_to(0x00866a90, "OOM stage executor (FUN_00866a90)")

# ===================================================================
# PART 5: Gen queue — who ADDS entries?
# ===================================================================
write("")
write("#" * 70)
write("# PART 5: Gen Queue Writers")
write("#" * 70)
write("# FUN_008693c0 and FUN_008693f0 add to PDD queues")
write("# Who calls them? What objects go to Gen queue?")

decompile_at(0x008693c0, "PDD queue add 1 (FUN_008693c0)")
find_refs_to(0x008693c0, "PDD queue add 1")

decompile_at(0x008693f0, "PDD queue add 2 (FUN_008693f0)")
find_refs_to(0x008693f0, "PDD queue add 2")

# FUN_00fa1e10 and FUN_00fd8d40 reference Gen queue directly
decompile_at(0x00fa1e10, "Gen queue direct ref 1")
decompile_at(0x00fd8d40, "Gen queue direct ref 2")

# ===================================================================
# PART 6: Post-load cooldown — what does on_ai_join skip?
# ===================================================================
write("")
write("#" * 70)
write("# PART 6: What runs at 0x0086ee62-0x0086ee6a (post AI_JOIN)?")
write("#" * 70)

decompile_at(0x0086ee62, "Main loop post-AI-JOIN area")
decompile_at(0x00870610, "Post-AI function 2 (at 0x0086ee6a)")
find_and_print_calls_from(0x00870610, "Post-AI function 2")


write("")
write("=" * 70)
write("ANALYSIS COMPLETE")
write("=" * 70)

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/bulletproof_npc_crash.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
