# @category Analysis
# @description Find bhkRagdollController constructor and trace what initializes +0xa4.
# Two vtable refs found: FUN_00c7f060 (constructor?) and FUN_00c7d900 (cleanup).
# The bone array at +0xa4 is NULL on virgin pages. Need to find who sets it.

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
write("# RAGDOLL CONTROLLER CONSTRUCTOR AND +0xA4 INITIALIZATION")
write("######################################################################")


write("")
write("######################################################################")
write("# PART 1: FUN_00c7f060 - likely bhkRagdollController constructor")
write("# Sets vtable to 0x010C4DDC. What fields does it initialize?")
write("# Does it set +0xa4?")
write("######################################################################")

decompile_at(0x00C7F060, "bhkRagdollController_Constructor")
find_and_print_calls_from(0x00C7F060, "bhkRagdollController_Constructor")


write("")
write("######################################################################")
write("# PART 2: FUN_00c7d900 - bhkRagdollController cleanup/destructor")
write("# Also sets vtable 0x010C4DDC. How does it clean up +0xa4?")
write("######################################################################")

decompile_at(0x00C7D900, "bhkRagdollController_Cleanup")
find_and_print_calls_from(0x00C7D900, "bhkRagdollController_Cleanup")


write("")
write("######################################################################")
write("# PART 3: Who allocates bhkRagdollController?")
write("# Search for calls to the constructor (FUN_00c7f060).")
write("# What size is passed to the alloc function before the constructor?")
write("######################################################################")

find_refs_to(0x00C7F060, "bhkRagdollController_Constructor_callers")


write("")
write("######################################################################")
write("# PART 4: The FUN_00c7d810 caller - who calls ragdoll bone update?")
write("# This is where the crash chain starts. Who triggers it during")
write("# QueuedReference processing?")
write("######################################################################")

find_refs_to(0x00C7D810, "Ragdoll_BoneTransformUpdate_callers")


write("")
write("######################################################################")
write("# PART 5: FUN_00c7d030 - called from bone transform update")
write("# (FUN_00c7d810 line 347). What does it do?")
write("# Does it initialize +0xa4 AFTER the skeleton update?")
write("######################################################################")

decompile_at(0x00C7D030, "Ragdoll_PostBoneUpdate")
find_and_print_calls_from(0x00C7D030, "Ragdoll_PostBoneUpdate")


write("")
write("######################################################################")
write("# PART 6: What writes to offset +0xa4 of the ragdoll object?")
write("# The crash reads *(param_1+0xa4). Someone must write this pointer.")
write("# If the constructor does it, the virgin page zero is overwritten.")
write("# If a LATER init does it, there is a window where +0xa4 is zero.")
write("######################################################################")

write("# Manual analysis needed: search for writes to this+0xa4 in the")
write("# decompiled constructor and related init functions above.")
write("# Look for patterns like: *(param_1 + 0xa4) = alloc(size)")
write("# or: this->boneArray = new BoneArray()")


write("")
write("######################################################################")
write("# PART 7: The actor process path that leads to ragdoll update")
write("# FUN_00930c70 (2134 bytes) = actor process update")
write("# How does it get the ragdoll controller?")
write("# Does it check if ragdoll is fully initialized before updating?")
write("######################################################################")

decompile_at(0x00931420, "ActorProcess_near_ragdoll_call")


outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/ragdoll_constructor_fields.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
