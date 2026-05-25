# @category Analysis
# @description Audit fresh EIP=0 crash inside FUN_00CF7080 Havok narrowphase dispatch

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
ref_mgr = currentProgram.getReferenceManager()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def write(msg):
	output.append(msg)
	print(msg)

def func_for(addr_int):
	addr = toAddr(addr_int)
	func = fm.getFunctionAt(addr)
	if func is None:
		func = fm.getFunctionContaining(addr)
	return func

def name_for_func(func):
	if func is None:
		return "???"
	return "%s @ 0x%08x" % (func.getName(), func.getEntryPoint().getOffset())

def decompile_at(addr_int, label, max_len=12000):
	addr = toAddr(addr_int)
	func = func_for(addr_int)
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
		write("  NOTE: Requested 0x%08x is inside %s (entry at 0x%08x)" % (addr_int, func.getName(), faddr))
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		write(code[:max_len])
		if len(code) > max_len:
			write("  [decompile truncated at %d chars]" % max_len)
	else:
		write("  [decompilation failed]")

def find_refs_to(addr_int, label, limit=160):
	write("")
	write("-" * 70)
	write("References TO 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		faddr = from_func.getEntryPoint().getOffset() if from_func else 0
		fname = from_func.getName() if from_func else "???"
		write("  %s @ 0x%08x (in %s @ 0x%08x)" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname, faddr))
		count += 1
		if count >= limit:
			write("  ... (truncated at %d)" % limit)
			break
	write("  Total printed: %d" % count)

def find_refs_into_function(addr_int, label, limit=220):
	func = func_for(addr_int)
	write("")
	write("-" * 70)
	write("References INTO function containing 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	if func is None:
		write("  [function not found]")
		return
	body = func.getBody()
	addr_iter = body.getAddresses(True)
	count = 0
	while addr_iter.hasNext():
		addr = addr_iter.next()
		refs = ref_mgr.getReferencesTo(addr)
		while refs.hasNext():
			ref = refs.next()
			from_func = fm.getFunctionContaining(ref.getFromAddress())
			if from_func is not None and from_func.getEntryPoint() == func.getEntryPoint():
				continue
			write("  target=0x%08x %s from 0x%08x in %s" % (addr.getOffset(), ref.getReferenceType(), ref.getFromAddress().getOffset(), name_for_func(from_func)))
			count += 1
			if count >= limit:
				write("  ... (truncated at %d)" % limit)
				write("  Total printed: %d" % count)
				return
	write("  Total printed: %d" % count)

def find_and_print_calls_from(addr_int, label, limit=240):
	func = func_for(addr_int)
	write("")
	write("-" * 70)
	write("Calls FROM %s (0x%08x)" % (label, addr_int))
	write("-" * 70)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				tgt_func = fm.getFunctionAt(toAddr(tgt))
				if tgt_func is None:
					tgt_func = fm.getFunctionContaining(toAddr(tgt))
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, name_for_func(tgt_func)))
				count += 1
				if count >= limit:
					write("  ... (truncated at %d)" % limit)
					write("  Total printed: %d" % count)
					return
	write("  Total printed: %d" % count)

def byte_at(addr_int):
	b = memory.getByte(toAddr(addr_int))
	if b < 0:
		b += 256
	return b

def print_bytes(start_int, length, label):
	write("")
	write("-" * 70)
	write("Bytes: %s @ 0x%08x len=0x%x" % (label, start_int, length))
	write("-" * 70)
	pos = 0
	while pos < length:
		line_addr = start_int + pos
		parts = []
		i = 0
		while i < 16 and pos + i < length:
			try:
				parts.append("%02x" % byte_at(line_addr + i))
			except:
				parts.append("??")
			i += 1
		write("  0x%08x: %s" % (line_addr, " ".join(parts)))
		pos += 16

def print_instruction(addr_int, label):
	inst = listing.getInstructionAt(toAddr(addr_int))
	write("")
	write("-" * 70)
	write("Instruction: %s @ 0x%08x" % (label, addr_int))
	write("-" * 70)
	if inst is None:
		write("  [instruction not found]")
		return
	write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
	write("  Flow: %s" % inst.getFlowType())

def disasm_window(start_int, length, label, max_inst=260):
	end_int = start_int + length
	write("")
	write("-" * 70)
	write("Disassembly: %s 0x%08x..0x%08x" % (label, start_int, end_int))
	write("-" * 70)
	inst = listing.getInstructionAt(toAddr(start_int))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(start_int))
	count = 0
	while inst is not None and inst.getAddress().getOffset() < end_int:
		write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
		inst = inst.getNext()
		count += 1
		if count >= max_inst:
			write("  ... (truncated at %d instructions)" % max_inst)
			break
	write("  Instructions printed: %d" % count)

def disasm_function(addr_int, label, max_inst=220):
	func = func_for(addr_int)
	write("")
	write("-" * 70)
	write("Function disassembly: %s @ 0x%08x" % (label, addr_int))
	write("-" * 70)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
		count += 1
		if count >= max_inst:
			write("  ... (truncated at %d instructions)" % max_inst)
			break
	write("  Instructions printed: %d" % count)

def print_ret_instructions(addr_int, label):
	func = func_for(addr_int)
	write("")
	write("-" * 70)
	write("RET/calling-convention clues: %s @ 0x%08x" % (label, addr_int))
	write("-" * 70)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		if inst.getMnemonicString().upper().startswith("RET"):
			write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
			count += 1
	write("  RET instructions: %d" % count)

def print_refs_with_context(addr_int, label, before=0x34, after=0x74, limit=100):
	write("")
	write("-" * 70)
	write("References with disasm context TO 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		from_addr = ref.getFromAddress().getOffset()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		write("")
		write("  REF %d: %s from 0x%08x in %s" % (count + 1, ref.getReferenceType(), from_addr, name_for_func(from_func)))
		disasm_window(from_addr - before, before + after, "xref context for 0x%08x" % from_addr, 100)
		count += 1
		if count >= limit:
			write("  ... (truncated at %d)" % limit)
			break
	write("  Context refs printed: %d" % count)

def scan_function_for_text(addr_int, label, needles, limit=220):
	func = func_for(addr_int)
	write("")
	write("-" * 70)
	write("Instruction text scan: %s" % label)
	write("-" * 70)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		text = inst.toString().lower()
		matched = False
		for needle in needles:
			if needle.lower() in text:
				matched = True
		if matched:
			write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
			count += 1
			if count >= limit:
				write("  ... (truncated at %d)" % limit)
				break
	write("  Total matches: %d" % count)

def audit_function(addr_int, label, max_len=18000):
	decompile_at(addr_int, label, max_len)
	print_ret_instructions(addr_int, label)
	disasm_function(addr_int, label)
	find_refs_to(addr_int, label)
	find_refs_into_function(addr_int, label)
	find_and_print_calls_from(addr_int, label)

def main():
	write("=" * 70)
	write("CRASH EIP=0 FUN_00CF7080 DISPATCH AUDIT")
	write("=" * 70)
	write("")
	write("Fresh runtime facts:")
	write("  Crash thread: [FNV] AI Linear Task Thread 2")
	write("  CrashLogger: EIP=0x00000000, ESP[0]=0x00CF70D8, ESP[6]=0x00D0D7D6")
	write("  Therefore the failing indirect call most likely returned to 0x00CF70D8 inside FUN_00CF7080.")
	write("  Previous push-zero lock-argument patch only moved the crash deeper; do not treat it as a valid fix.")
	write("")
	write("# SECTION 1: exact dispatch site")
	print_instruction(0x00CF70D6, "CALL EDX, return address 0x00CF70D8")
	print_instruction(0x00CF70B6, "filter virtual CALL EDX")
	print_bytes(0x00CF7080, 0x70, "FUN_00CF7080 bytes")
	disasm_window(0x00CF7080, 0x70, "FUN_00CF7080 full body")
	scan_function_for_text(0x00CF7080, "FUN_00CF7080 dispatch data flow", ["[esi]", "[esi + 0x4]", "[ebx", "call edx", "+ 0x4", "+ 0x5"])
	write("")
	write("# SECTION 2: decompile and call graph")
	audit_function(0x00CF7080, "FUN_00CF7080 StAddAgt / narrowphase setup", 26000)
	audit_function(0x00CF70F0, "FUN_00CF70F0 StRemoveAgt helper", 22000)
	audit_function(0x00CF7130, "FUN_00CF7130 nearby pair helper", 22000)
	write("")
	write("# SECTION 3: caller contexts")
	print_refs_with_context(0x00CF7080, "FUN_00CF7080", 0x40, 0x98, 120)
	audit_function(0x00D0D3F0, "FUN_00D0D3F0 caller with old 0x00D0D7D8 crash", 36000)
	audit_function(0x00D93BA0, "FUN_00D93BA0 clone caller", 30000)
	audit_function(0x00C94BD0, "FUN_00C94BD0 addEntityBatch caller", 32000)
	write("")
	write("# SECTION 4: comparable broadphase/slot sanitizers")
	audit_function(0x00D00370, "FUN_00D00370 null-slot compactor", 24000)
	audit_function(0x00CFFA00, "FUN_00CFFA00 post-add callback target", 18000)
	write("")
	write("=" * 70)
	write("END CRASH EIP=0 FUN_00CF7080 DISPATCH AUDIT")
	write("=" * 70)

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/crash_eip0_cf7080_dispatch_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
