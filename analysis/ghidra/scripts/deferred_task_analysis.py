# @category Analysis
# @name Deferred Task Analysis
# Ghidra Jython Script: Disassemble FUN_00c458f0 and FUN_0096b050
# to find exact patch addresses for performance bottlenecks

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()

decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def disasm_func(addr_int, label):
	output.append("=" * 70)
	output.append("=== %s ===" % label)
	output.append("=" * 70)
	func_addr = toAddr(addr_int)
	func = fm.getFunctionContaining(func_addr)
	if func is None:
		output.append("ERROR: Function not found at 0x%08X" % addr_int)
		return
	output.append("Function: %s @ %s" % (func.getName(), func.getEntryPoint()))
	output.append("Size: %d bytes" % func.getBody().getNumAddresses())
	output.append("")
	output.append("--- Disassembly ---")
	output.append("")
	addr_set = func.getBody()
	inst_iter = listing.getInstructions(addr_set, True)
	while inst_iter.hasNext():
		inst = inst_iter.next()
		addr = inst.getAddress()
		raw_bytes = []
		for i in range(inst.getLength()):
			b = getByte(addr.add(i)) & 0xFF
			raw_bytes.append("%02X" % b)
		byte_str = " ".join(raw_bytes)
		while len(byte_str) < 20:
			byte_str = byte_str + " "
		mnemonic = inst.getMnemonicString()
		ops = ""
		for i in range(inst.getNumOperands()):
			if i > 0:
				ops = ops + ", "
			ops = ops + inst.getDefaultOperandRepresentation(i)
		line = "  %08X  %s  %s %s" % (addr.getOffset(), byte_str, mnemonic, ops)
		output.append(line)
		ops_lower = ops.lower()
		if "0xc8" in ops_lower or "0x3e8" in ops_lower:
			output.append("  ^^^ POTENTIAL PATCH TARGET (200=0xC8 or 1000=0x3E8) ^^^")
		if "0x5" == ops.strip():
			output.append("  ^^^ CHECK FREQUENCY (mod 5) ^^^")
	output.append("")
	output.append("--- Decompiled C ---")
	output.append("")
	result = decomp.decompileFunction(func, 30, monitor)
	if result is not None and result.decompileCompleted():
		output.append(result.getDecompiledFunction().getC())
	else:
		output.append("[decompile failed]")
	output.append("")

disasm_func(0x00c458f0, "FUN_00c458f0 - DEFERRED TASK BUDGET (1000ms stall)")
disasm_func(0x0096b050, "FUN_0096b050 - CELL OBJECT PROCESSING")

decomp.dispose()

output_text = "\n".join(output)
f = open("/tmp/deferred_task_analysis.txt", "w")
f.write(output_text)
f.close()

print("=== Done! Written to /tmp/deferred_task_analysis.txt ===")
print("=== %d lines ===" % len(output))
