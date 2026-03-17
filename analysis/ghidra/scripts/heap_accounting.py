# @category Analysis
# @description Analyze heap accounting - FUN_00866a90 and FUN_00aa4290

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def analyze(addr, label):
	output.append("=== %s @ 0x%08x ===" % (label, addr))
	func = fm.getFunctionContaining(toAddr(addr))
	if func is None:
		output.append("  [not found]")
		return
	sz = func.getBody().getNumAddresses()
	output.append("  Size: %d bytes" % sz)
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		if len(code) < 6000:
			output.append(code)
		else:
			output.append(code[:6000])
	output.append("")

analyze(0x00866a90, "HeapCompact (called on alloc fail)")
analyze(0x00aa4290, "FallbackAllocator")

text = "\n".join(output)
fout = open("/tmp/heap_accounting.txt", "w")
fout.write(text)
fout.close()
print(text)
decomp.dispose()
