# @category Analysis
# @description Check prologues of alternate hook targets that avoid
# SEH-prologue functions. FUN_0096e870 (actorDowngrade inner) and
# FUN_0096db30 (physics update) are smaller, may have simpler prologues.

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
	params = func.getParameters()
	write("  Parameters: %d" % len(params))
	for p in params:
		write("    %s: %s (storage: %s)" % (p.getName(), p.getDataType(), p.getVariableStorage()))
	write("")
	write("  First 16 bytes (disassembly):")
	listing = currentProgram.getListing()
	cur = addr
	count = 0
	while count < 10:
		inst = listing.getInstructionAt(cur)
		if inst is None:
			write("    0x%08x: [no instruction]" % cur.getOffset())
			break
		write("    0x%08x: %-6s %s" % (cur.getOffset(), inst.getMnemonicString(), inst.toString()))
		cur = inst.getNext().getAddress() if inst.getNext() else cur.add(inst.getLength())
		count += 1

write("=" * 70)
write("ALTERNATE HOOK TARGET VERIFICATION")
write("Looking for functions WITHOUT SEH prologues")
write("=" * 70)

# Inner downgrade function
check_function(0x0096e870, "FUN_0096e870 (actorDowngrade inner)")

# Process swap
check_function(0x008feb60, "FUN_008feb60 (processSwap)")

# Physics update (Worker 2)
check_function(0x0096db30, "FUN_0096db30 (physics update)")

# Animations (Worker 2)
check_function(0x004772f0, "FUN_004772f0 (animations)")

# Worker 1 actor iteration functions (steps 1-2)
check_function(0x0096cca0, "FUN_0096cca0 (Worker1 actor iter 1)")
check_function(0x0096cda0, "FUN_0096cda0 (Worker1 actor iter 2)")

# Process manager update callee
check_function(0x008c3c40, "FUN_008c3c40 (process update inner)")

# PostProcess at end of downgrade
check_function(0x00977130, "FUN_00977130 (postProcess)")

write("")
write("=" * 70)
write("RESEARCH COMPLETE")
write("=" * 70)

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/verify_alternate_targets.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
