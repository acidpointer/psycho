# @category Analysis
# @name NPC Load Crash Analysis
# Analyze the FalloutNV.exe functions in the NPC loading crash chain
# Crash: InitNPCPerks -> nvidia driver access violation during queued reference processing

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

# FalloutNV.exe functions from the crash callstack (bottom to top)
analyze_addr(0x0086B3E8, "MAIN LOOP: 0x0086B3E8")
analyze_addr(0x0086E765, "GAME UPDATE: 0x0086E765")
analyze_addr(0x0086FA31, "REF PROCESSING: 0x0086FA31")
analyze_addr(0x00943969, "QUEUED REF DISPATCH: 0x00943969")
analyze_addr(0x00C3E115, "QUEUED REF HANDLER 1: 0x00C3E115")
analyze_addr(0x00C3DD8E, "QUEUED REF HANDLER 2: 0x00C3DD8E (closest to jip_nvse hook)")

# Also look at the function entry points near the hook targets
# These are likely the functions that jip_nvse hooks
analyze_addr(0x00C3DD00, "FUNCTION NEAR 0x00C3DD8E (potential hook target)")
analyze_addr(0x00C3E000, "FUNCTION NEAR 0x00C3E115 (potential hook target)")

decomp.dispose()

output_text = "\n".join(output)
f = open("/tmp/npc_load_crash_analysis.txt", "w")
f.write(output_text)
f.close()

print("=== Done! Written to /tmp/npc_load_crash_analysis.txt ===")
print("=== %d lines ===" % len(output))
