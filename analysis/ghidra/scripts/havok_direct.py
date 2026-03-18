# @category Analysis
# @description Decompile FUN_008325a0 (direct Havok stop/start) and related

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def decompile_at(addr_int, label):
	addr = toAddr(addr_int)
	func = fm.getFunctionAt(addr)
	if func is None:
		func = fm.getFunctionContaining(addr)
	output.append("")
	output.append("=" * 70)
	output.append("%s @ 0x%08x" % (label, addr_int))
	output.append("=" * 70)
	if func is None:
		output.append("  [function not found]")
		return
	output.append("  Function: %s, Size: %d bytes" % (func.getName(), func.getBody().getNumAddresses()))
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		if len(code) > 6000:
			output.append(code[:6000])
		else:
			output.append(code)
	output.append("")

decompile_at(0x008325a0, "HavokWorldStopStart (called by 008324e0)")
decompile_at(0x008304a0, "HavokPre (called before 008325a0)")
decompile_at(0x008304c0, "HavokPost (called after 008325a0 in start mode)")
decompile_at(0x008300c0, "HavokStepInit (called during start mode)")
decompile_at(0x00830ad0, "HavokIsRunning (checked before stop)")
decompile_at(0x00ad88f0, "QueueDrain (drains task queue)")
decompile_at(0x00ad8d10, "QueueWait (waits for queue completion)")

text = "\n".join(output)
outpath = "/tmp/havok_direct.txt"
fout = open(outpath, "w")
fout.write(text)
fout.close()
print("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
