# @category Analysis
# @description Verify the exact signatures and prologues of the 5
# actor process hook targets. Check if they are hookable
# (standard prologue, enough bytes for inline hook patch).
# Also check calling convention by looking at how params are used.

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def write(msg):
	output.append(msg)
	print(msg)

def check_function(addr_int, label):
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
	write("  Entry: 0x%08x, Size: %d bytes" % (faddr, func.getBody().getNumAddresses()))
	write("  Convention: %s" % func.getCallingConventionName())
	write("  Signature: %s" % func.getSignature())
	write("  Return type: %s" % func.getReturnType())
	params = func.getParameters()
	write("  Parameters: %d" % len(params))
	for p in params:
		write("    %s: %s (storage: %s)" % (p.getName(), p.getDataType(), p.getVariableStorage()))
	write("")
	write("  First 16 bytes (disassembly):")
	listing = currentProgram.getListing()
	cur = addr
	count = 0
	while count < 16:
		inst = listing.getInstructionAt(cur)
		if inst is None:
			write("    0x%08x: [no instruction]" % cur.getOffset())
			break
		write("    0x%08x: %s  %s" % (cur.getOffset(), inst.getMnemonicString(), inst.toString().split(" ", 1)[-1] if " " in inst.toString() else ""))
		cur = inst.getNext().getAddress() if inst.getNext() else cur.add(inst.getLength())
		count += 1
		if count > 8:
			break
	write("")
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		lines = code.split("\n")
		write("  Decompiled signature (first 5 lines):")
		for line in lines[:5]:
			write("    %s" % line)
	else:
		write("  [decompilation failed]")

write("=" * 70)
write("ACTOR HOOK TARGET VERIFICATION")
write("=" * 70)

check_function(0x0096bcd0, "FUN_0096bcd0 (actor downgrade)")
check_function(0x009784c0, "FUN_009784c0 (process mgr update)")
check_function(0x0096c330, "FUN_0096c330 (AI process 1)")
check_function(0x0096cb50, "FUN_0096cb50 (AI process 2)")
check_function(0x00453550, "FUN_00453550 (cell mgmt update)")

write("")
write("=" * 70)
write("RESEARCH COMPLETE")
write("=" * 70)

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/verify_actor_hook_targets.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
