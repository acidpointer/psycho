# @category Analysis
# @description Decompile PostDestructionRestore (FUN_00878200) and verify
# it properly unlocks hkWorld. The previous script got the wrong function.

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def write(msg):
	output.append(msg)
	print(msg)

def decompile_at(addr_int, label, max_len=8000):
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
		write("  WARNING: Requested 0x%08x but Ghidra resolved to 0x%08x" % (addr_int, faddr))
		write("  This means 0x%08x is inside function %s, not a separate function" % (addr_int, func.getName()))
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		write(code[:max_len])
	else:
		write("  [decompilation failed]")

write("=" * 70)
write("POST-DESTRUCTION RESTORE ANALYSIS")
write("=" * 70)

# FUN_00878200 was previously misresolved to FUN_00878160.
# Let's check what's actually at 0x00878200.
write("")
write("# Checking function boundaries around 0x00878200")

decompile_at(0x00878200, "PostDestructionRestore @ 0x00878200")
decompile_at(0x00878160, "PreDestructionSetup @ 0x00878160")

# Check raw bytes at 0x00878200 to verify it's a real function
write("")
write("# Checking if 0x00878200 is a function entry point")
func_at = fm.getFunctionAt(toAddr(0x00878200))
if func_at:
	write("  YES: %s @ 0x%08x (size %d)" % (func_at.getName(), func_at.getEntryPoint().getOffset(), func_at.getBody().getNumAddresses()))
else:
	func_containing = fm.getFunctionContaining(toAddr(0x00878200))
	if func_containing:
		write("  NO: 0x00878200 is inside %s @ 0x%08x" % (func_containing.getName(), func_containing.getEntryPoint().getOffset()))
		write("  The function that CONTAINS 0x00878200 starts at 0x%08x" % func_containing.getEntryPoint().getOffset())
	else:
		write("  NO: No function found at or containing 0x00878200")

# Check what's between 0x00878160 and 0x00878280
write("")
write("# Functions in range 0x00878100 - 0x00878300:")
func_iter = fm.getFunctions(toAddr(0x00878100), True)
while func_iter.hasNext():
	func = func_iter.next()
	addr = func.getEntryPoint().getOffset()
	if addr > 0x00878300:
		break
	write("  0x%08x  %s  (%d bytes)" % (addr, func.getName(), func.getBody().getNumAddresses()))

# Decompile each function in the range
write("")
write("# Decompiling all functions in range:")
func_iter = fm.getFunctions(toAddr(0x00878100), True)
while func_iter.hasNext():
	func = func_iter.next()
	addr = func.getEntryPoint().getOffset()
	if addr > 0x00878300:
		break
	decompile_at(addr, func.getName())

write("")
write("=" * 70)
write("RESEARCH COMPLETE")
write("=" * 70)

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/post_destruction_restore.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
print("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
