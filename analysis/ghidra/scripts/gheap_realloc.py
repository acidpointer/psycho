# @category Analysis
# @description Analyze GameHeap::Realloc functions

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
		if len(code) < 4000:
			output.append(code)
		else:
			output.append(code[:4000])
	output.append("")

analyze(0x00AA4150, "GameHeap::Realloc1")
analyze(0x00AA4200, "GameHeap::Realloc2")

text = "\n".join(output)
fout = open("/tmp/gheap_realloc.txt", "w")
fout.write(text)
fout.close()
print(text)
decomp.dispose()
