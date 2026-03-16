# @category Analysis
# @name Crash Site Analysis
# Analyze the AI thread crash at 0x0044DDC0 and its callers

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()

decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def analyze_addr(addr_int, label):
	output.append("=" * 70)
	output.append("=== %s ===" % label)
	output.append("=" * 70)
	func_addr = toAddr(addr_int)
	func = fm.getFunctionContaining(func_addr)
	if func is None:
		output.append("ERROR: No function at 0x%08X" % addr_int)
		# Show raw disassembly around the address
		output.append("Raw disassembly around 0x%08X:" % addr_int)
		addr = toAddr(addr_int - 0x20)
		for i in range(0x60):
			inst = listing.getInstructionAt(addr)
			if inst is not None:
				raw = []
				for j in range(inst.getLength()):
					b = getByte(addr.add(j)) & 0xFF
					raw.append("%02X" % b)
				bstr = " ".join(raw)
				while len(bstr) < 20:
					bstr = bstr + " "
				ops = ""
				for j in range(inst.getNumOperands()):
					if j > 0:
						ops = ops + ", "
					ops = ops + inst.getDefaultOperandRepresentation(j)
				marker = " <<<" if addr.getOffset() == addr_int else ""
				output.append("  %08X  %s  %s %s%s" % (addr.getOffset(), bstr, inst.getMnemonicString(), ops, marker))
				addr = addr.add(inst.getLength())
			else:
				addr = addr.add(1)
		return
	output.append("Function: %s @ %s" % (func.getName(), func.getEntryPoint()))
	output.append("Size: %d bytes" % func.getBody().getNumAddresses())
	output.append("")
	# Disassembly
	output.append("--- Disassembly ---")
	output.append("")
	addr_set = func.getBody()
	inst_iter = listing.getInstructions(addr_set, True)
	while inst_iter.hasNext():
		inst = inst_iter.next()
		addr = inst.getAddress()
		raw = []
		for i in range(inst.getLength()):
			b = getByte(addr.add(i)) & 0xFF
			raw.append("%02X" % b)
		bstr = " ".join(raw)
		while len(bstr) < 20:
			bstr = bstr + " "
		ops = ""
		for i in range(inst.getNumOperands()):
			if i > 0:
				ops = ops + ", "
			ops = ops + inst.getDefaultOperandRepresentation(i)
		marker = " <<<" if addr.getOffset() == addr_int else ""
		output.append("  %08X  %s  %s %s%s" % (addr.getOffset(), bstr, inst.getMnemonicString(), ops, marker))
	output.append("")
	# Decompiled
	output.append("--- Decompiled C ---")
	output.append("")
	result = decomp.decompileFunction(func, 30, monitor)
	if result is not None and result.decompileCompleted():
		output.append(result.getDecompiledFunction().getC())
	else:
		output.append("[decompile failed]")
	output.append("")

# Crash site
analyze_addr(0x0044DDC0, "CRASH SITE 0x0044DDC0")

# Immediate caller
analyze_addr(0x009EABF5, "CALLER 1: 0x009EABF5")

# Next callers in the chain
analyze_addr(0x009DC5C0, "CALLER 2: 0x009DC5C0")
analyze_addr(0x009DC2E4, "CALLER 3: 0x009DC2E4")
analyze_addr(0x008B336A, "CALLER 4: 0x008B336A")
analyze_addr(0x00886580, "CALLER 5: 0x00886580")
analyze_addr(0x0096D715, "CALLER 6: 0x0096D715 (near cell processing)")
analyze_addr(0x00AA64E0, "THREAD ENTRY: 0x00AA64E0")

decomp.dispose()

output_text = "\n".join(output)
f = open("/tmp/crash_analysis.txt", "w")
f.write(output_text)
f.close()

print("=== Done! Written to /tmp/crash_analysis.txt ===")
print("=== %d lines ===" % len(output))
