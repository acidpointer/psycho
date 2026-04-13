# @category Analysis
# @description Trace ragdoll controller bone array initialization.
# Crash: FUN_00a6df40 with ESI=0x34 (NULL+0x34). The ragdoll controller's
# bone array pointer at param_1+0xa4 is NULL. Allocated from virgin slab
# page (zeroed by VirtualAlloc). SBM would return zombie data (non-zero).
#
# Key questions:
# 1. What is the allocation size of bhkRagdollController? (determines size class)
# 2. Who writes to offset +0xa4? Is it the constructor or a later init?
# 3. What is FUN_00c79680 reading at param_1+0xa4? The full pointer chain.
# 4. Does the QueuedCharacter/QueuedReference processing initialize +0xa4?

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def write(msg):
	output.append(msg)
	print(msg)

def decompile_at(addr_int, label, max_len=10000):
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
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				tgt_func = fm.getFunctionAt(toAddr(tgt))
				name = tgt_func.getName() if tgt_func else "???"
				write("  CALL @ 0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, name))
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
		if count > 40:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)


write("######################################################################")
write("# RAGDOLL BONE ARRAY INITIALIZATION ANALYSIS")
write("# Crash: param_1+0xa4 is NULL in FUN_00c79680 (skeleton update)")
write("# ESI=0x34 = offset into bone transform read from NULL pointer")
write("######################################################################")


write("")
write("######################################################################")
write("# PART 1: bhkRagdollController RTTI and vtable")
write("# RTTI at 0x010C4DDC. Need to find constructor to get alloc size.")
write("######################################################################")

find_refs_to(0x010C4DDC, "bhkRagdollController_vtable")


write("")
write("######################################################################")
write("# PART 2: FUN_00c79680 (skeleton update) - the crash path")
write("# Line 330: local_88 = *(*(*(param_1 + 0x2a4) + 0xc) + 0x1c)")
write("# Line 340: FUN_00c74dd0(&local_80, *(*(local_94 + *(local_90 + 0xa4)) + 0x34))")
write("# The +0xa4 read: what object is at param_1+0xa4?")
write("######################################################################")

decompile_at(0x00C79680, "Ragdoll_SkeletonUpdate (crash reads +0xa4)")


write("")
write("######################################################################")
write("# PART 3: Who WRITES to the ragdoll object at offset +0xa4?")
write("# If a constructor allocates the ragdoll, does it set +0xa4?")
write("# Or is +0xa4 set by a separate init function?")
write("######################################################################")

write("")
write("# The ragdoll is accessed via param_1 in FUN_00c79680.")
write("# param_1 = the ragdoll controller object (bhkRagdollController).")
write("# +0xa4 is read as a pointer to a bone transform array.")
write("# If the ragdoll was just constructed on a virgin page,")
write("# +0xa4 is 0 (from VirtualAlloc). The code reads *(0 + something)")
write("# and crashes at ESI = that something (0x34).")


write("")
write("######################################################################")
write("# PART 4: FUN_00c7d810 - ragdoll bone transform update")
write("# Caller of FUN_00c79680. What does it pass as param_1?")
write("######################################################################")

decompile_at(0x00C7D810, "Ragdoll_BoneTransformUpdate")
find_and_print_calls_from(0x00C7D810, "Ragdoll_BoneTransformUpdate")


write("")
write("######################################################################")
write("# PART 5: FUN_00931443 area - actor process update")
write("# Frame #3 in crash stack. How does it get the ragdoll?")
write("######################################################################")

decompile_at(0x00931443, "ActorProcess_Update_CrashFrame")


write("")
write("######################################################################")
write("# PART 6: FUN_0056F8D4 area - reference processing")
write("# Frame #4. This is between QueuedRef and actor process.")
write("# Does it create/init the ragdoll controller?")
write("######################################################################")

decompile_at(0x0056F8D4, "Reference_Processing_CrashFrame")


write("")
write("######################################################################")
write("# PART 7: FUN_00C3E115 - new frame in IOManager chain")
write("# Frame #8 in this crash. Different from usual IOManager_Process.")
write("# What is this function?")
write("######################################################################")

decompile_at(0x00C3E115, "IOManager_Frame8")


write("")
write("######################################################################")
write("# PART 8: FUN_00943969 - actor/NPC processing")
write("# Frame #9. Near cell transition. What does it do?")
write("######################################################################")

decompile_at(0x00943969, "Actor_NPC_Processing_Frame9")


write("")
write("######################################################################")
write("# PART 9: FUN_0086FA31 - cell transition area")
write("# Frame #10. Just past FUN_0086F940 (cell transition check).")
write("# Is this INSIDE the cell transition or just after?")
write("######################################################################")

decompile_at(0x0086FA31, "CellTransition_Frame10")


outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/ragdoll_bone_array_init.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
