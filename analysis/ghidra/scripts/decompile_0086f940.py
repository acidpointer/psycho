# @category Analysis
# @description Decompile FUN_0086f940 - the safe hook point

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
		if len(code) > 8000:
			output.append(code[:8000])
		else:
			output.append(code)
	output.append("")

decompile_at(0x0086f940, "SafeHookTarget (pre-AI, calls ProcessDeferredDestruction)")
decompile_at(0x008c80e0, "AI_StartFrame (signals AI threads)")
decompile_at(0x008c78c0, "AI_WaitFrame (waits for AI threads)")
decompile_at(0x008c7990, "AI_PostRender (post-render AI signal)")
decompile_at(0x008782b0, "AnotherSafePoint (calls 00878250 which calls ProcessDeferredDestruction)")

text = "\n".join(output)
outpath = "/tmp/safe_hook_point.txt"
fout = open(outpath, "w")
fout.write(text)
fout.close()
print("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
