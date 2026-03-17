# @category Analysis
# @description Analyze FUN_00877a30 (queue item getter)

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []
func = fm.getFunctionContaining(toAddr(0x00877a30))
if func is not None:
	entry = func.getEntryPoint().getOffset()
	sz = func.getBody().getNumAddresses()
	output.append("Function: %s @ 0x%08x (%d bytes)" % (func.getName(), entry, sz))
	result = decomp.decompileFunction(func, 60, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		output.append(code)

text = "\n".join(output)
fout = open("/tmp/analyze_877a30.txt", "w")
fout.write(text)
fout.close()
print(text)
decomp.dispose()
