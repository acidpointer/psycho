# @category Analysis
# @description Full trace of worldspace transition crash path.
# Crash: jip_nvse LN_ProcessEvents calls script that accesses freed game data.
# Chain: MainLoopHook -> HandleMainLoopHook -> PluginManager::Dispatch_Message
#        -> jip_nvse NVSEMessageHandler -> LN_ProcessEvents
#        -> CallFunctionScriptAlt -> UserFunctionManager::Call -> AV
#
# Also: IOManager_Process -> DoQueuedReferenceHook -> ragdoll update -> AV
#
# Goal: understand WHAT game objects these paths access, WHERE the freed
# pointers come from, and WHY our allocator's behavior triggers the crash.

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
write("# WORLDSPACE TRANSITION CRASH ANALYSIS")
write("# Traces full call chain from main loop to crash site")
write("######################################################################")


write("")
write("######################################################################")
write("# PART 1: IOManager_Process (Phase 3 inner loop)")
write("# This is where QueuedCharacter/QueuedReference tasks are processed")
write("######################################################################")

decompile_at(0x00C3DBF0, "IOManager_Process (Phase 3)")
find_and_print_calls_from(0x00C3DBF0, "IOManager_Process")


write("")
write("######################################################################")
write("# PART 2: QueuedReference processing (FUN_00451ef0)")
write("# JIP hooks this at DoQueuedReferenceHook (0x0045211D)")
write("# This processes newly loaded references from cell transitions")
write("######################################################################")

decompile_at(0x00451EF0, "QueuedRef_Process")
find_and_print_calls_from(0x00451EF0, "QueuedRef_Process")


write("")
write("######################################################################")
write("# PART 3: Ragdoll crash chain")
write("# 0x00C79680 = skeleton/ragdoll update (963 bytes)")
write("# 0x00A6DF40 = quaternion from rotation matrix (crash at +8)")
write("# These read bone transform arrays from ragdoll controller")
write("######################################################################")

decompile_at(0x00C79680, "Ragdoll_SkeletonUpdate")
decompile_at(0x00A6DF40, "Quaternion_FromRotMatrix (crash site)")


write("")
write("######################################################################")
write("# PART 4: What reads param_1+0xa4 (bone array)")
write("# The crash: *(param_1+0xa4) was NULL -> offset 0x34 -> AV at 0x34")
write("# Where is +0xa4 written? Who initializes it?")
write("######################################################################")

decompile_at(0x00C7D810, "Ragdoll_BoneTransformUpdate (calls skeleton update)")
find_and_print_calls_from(0x00C7D810, "Ragdoll_BoneTransformUpdate")

decompile_at(0x00C6C210, "Ragdoll_ControllerUpdate_Entry")
find_and_print_calls_from(0x00C6C210, "Ragdoll_ControllerUpdate_Entry")


write("")
write("######################################################################")
write("# PART 5: FUN_00931443 area - actor process update")
write("# This is in the stack between QueuedRef and ragdoll")
write("######################################################################")

decompile_at(0x00931443, "ActorProcess_Update (from crash stack)")
decompile_at(0x0056F8D4, "Reference_Processing (from crash stack)")


write("")
write("######################################################################")
write("# PART 6: The inner loop phases - where does IOManager_Process run?")
write("# 0x0086E650 = InnerLoop entry")
write("# IOManager_Process at 0x0086E89C (frame #8 in crash stack)")
write("######################################################################")

decompile_at(0x0086E650, "InnerLoop (2272 bytes)")


write("")
write("######################################################################")
write("# PART 7: NVSE main loop hook - HandleMainLoopHook")
write("# At 0x0086B3E3 NVSE hooks the CALL to InnerLoop")
write("# Before InnerLoop runs, NVSE dispatches plugin messages")
write("# jip_nvse LN_ProcessEvents runs HERE (before InnerLoop)")
write("######################################################################")

decompile_at(0x0086B3E3, "InnerLoop_NVSEHookPoint")


write("")
write("######################################################################")
write("# PART 8: Key globals that control loading/event state")
write("# DAT_01202d6c = LOADING_STATE_COUNTER")
write("# DAT_011dea2b = LOADING_FLAG")
write("# Who reads/writes these during transitions?")
write("######################################################################")

find_refs_to(0x01202D6C, "LOADING_STATE_COUNTER")
find_refs_to(0x011DEA2B, "LOADING_FLAG")


write("")
write("######################################################################")
write("# PART 9: QueuedCharacter processing chain")
write("# From previous crash: QueuedCharacter 'Enclave Soldier' with")
write("# bhkRagdollController on the stack")
write("######################################################################")

decompile_at(0x0043FDF0, "QueuedCharacter_Process_vtable5")
decompile_at(0x00441440, "QueuedCharacter_Ctor")
find_and_print_calls_from(0x00441440, "QueuedCharacter_Ctor")

decompile_at(0x00C7D900, "Ragdoll_Cleanup_BeforeFree")


outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/worldspace_transition_crash.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
