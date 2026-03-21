# @category Analysis
# @description Research animation system stale form crash at 0x0087C9AE
#
# EXCEPTION_ILLEGAL_INSTRUCTION: EIP=0x742067EF (string data)
# ECX -> TESForm with DELETED flag. Virtual call through recycled vtable.
# Return addr: 0x0087C9AE in animation/actor processing.
# Calltrace: 0x0087A82D -> 0x0087A7B8 -> 0x0086F7B0 -> 0x0086EE67
#
# Need to find:
# 1. What function is at 0x0087C9AE? What virtual call did it make?
# 2. What function at 0x0087A82D/0x0087A7B8 processes animations?
# 3. What is 0x0086F7B0 in the POST_AI area?
# 4. Can we validate form pointers before virtual calls in this path?
# 5. How does the animation system get its actor/form references?

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)
listing = currentProgram.getListing()

output = []

def write(msg):
	output.append(msg)
	print(msg)

def decompile_at(addr_int, label, max_len=6000):
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
	entry = func.getEntryPoint().getOffset()
	sz = func.getBody().getNumAddresses()
	write("  Function: %s, Size: %d bytes" % (func.getName(), sz))
	write("  Entry: 0x%08x" % entry)
	result = decomp.decompileFunction(func, 60, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		write(code[:max_len])
	else:
		write("  [decompilation failed]")

def disasm_range(start_int, count=25):
	inst = listing.getInstructionAt(toAddr(start_int))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(start_int - 1))
	for i in range(count):
		if inst is None:
			break
		write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
		inst = inst.getNext()

def find_calls_from(addr_int, label):
	addr = toAddr(addr_int)
	func = fm.getFunctionAt(addr)
	if func is None:
		func = fm.getFunctionContaining(addr)
	write("")
	write("--- Calls FROM %s (0x%08x) ---" % (label, addr_int))
	if func is None:
		write("  [function not found]")
		return
	body = func.getBody()
	addr_iter = body.getAddresses(True)
	count = 0
	while addr_iter.hasNext():
		a = addr_iter.next()
		inst = listing.getInstructionAt(a)
		if inst is None:
			continue
		if not inst.getFlowType().isCall():
			continue
		refs_from = inst.getReferencesFrom()
		for r in refs_from:
			target = r.getToAddress().getOffset()
			target_func = fm.getFunctionAt(toAddr(target))
			target_name = target_func.getName() if target_func else "unknown_0x%08x" % target
			write("  CALL 0x%08x -> %s (from 0x%08x)" % (target, target_name, a.getOffset()))
			count += 1
	write("  Total: %d calls" % count)


write("=" * 70)
write("ANIMATION SYSTEM STALE FORM CRASH")
write("=" * 70)

# SECTION 1: 0x0087C9AE - return address from the virtual call that crashed
write("")
write("# SECTION 1: 0x0087C9AE - crash return addr (animation processing)")
disasm_range(0x0087C990, 20)
decompile_at(0x0087C9AE, "AnimCrashPoint")

# SECTION 2: 0x0087A82D - caller in the chain
write("")
write("# SECTION 2: 0x0087A82D - animation caller")
disasm_range(0x0087A810, 15)
decompile_at(0x0087A82D, "AnimCaller1")

# SECTION 3: 0x0087A7B8 - outer caller
write("")
write("# SECTION 3: 0x0087A7B8 - outer animation caller")
disasm_range(0x0087A7A0, 15)

# SECTION 4: 0x0086F7B0 - POST_AI area
write("")
write("# SECTION 4: 0x0086F7B0 - POST_AI processing")
decompile_at(0x0086F7B0, "PostAI_area")

# SECTION 5: 0x0086EE67 - near AI_JOIN
write("")
write("# SECTION 5: 0x0086EE67 - near AI_JOIN in main loop")
disasm_range(0x0086EE50, 15)

# SECTION 6: FUN_00a2f849 on stack - what is this?
write("")
write("# SECTION 6: 0x00A2F849 - on crash stack")
disasm_range(0x00A2F830, 15)
decompile_at(0x00A2F849, "StackFunc_A2F849")

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/anim_stale_form_crash.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
