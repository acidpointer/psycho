# @category Analysis
# @description Audit 0x00401170 crash through Stewie cell reference enumeration callback

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
ref_mgr = currentProgram.getReferenceManager()
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

def decompile_at(addr_int, label, max_len=16000):
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

def find_refs_to(addr_int, label, limit=120):
	write("")
	write("-" * 70)
	write("References TO 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		write("  %s @ 0x%08x (in %s)" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), name_for_func(from_func)))
		count += 1
		if count >= limit:
			write("  ... (truncated at %d)" % limit)
			break
	write("  Total printed: %d" % count)

def find_refs_into_function(addr_int, label, limit=160):
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

def find_and_print_calls_from(addr_int, label, limit=220):
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

def disasm_window(start_int, length, label, highlights, max_inst=220):
	end_int = start_int + length
	write("")
	write("-" * 70)
	write("Disassembly: %s 0x%08x..0x%08x" % (label, start_int, end_int))
	write("-" * 70)
	inst = listing.getInstructionAt(toAddr(start_int))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(start_int))
	count = 0
	while inst is not None and inst.getAddress().getOffset() < end_int and count < max_inst:
		off = inst.getAddress().getOffset()
		prefix = "=> " if off in highlights else "   "
		write("%s0x%08x: %s" % (prefix, off, inst.toString()))
		inst = inst.getNext()
		count += 1
	if count >= max_inst:
		write("  ... (truncated at %d instructions)" % max_inst)

def decompile_cell_enum_patch_callers():
	write("")
	write("=" * 70)
	write("Stewie TESObjectCELL__EnumReferencesCloseToPoint replacement callsites")
	write("=" * 70)
	addrs = [0x0046f300, 0x0058866d, 0x0058875f, 0x00588833, 0x00588907, 0x005889db, 0x00588a2e, 0x007f5d5b]
	for addr_int in addrs:
		decompile_at(addr_int, "Patched cell enum callsite", 8000)

def main():
	write("Crash 0x00401170 Stewie cell enum callback audit")
	write("")
	write("CrashLogger frame: Stewie Process::TESObjectCELL__EnumReferencesCloseToPoint line 719 calls callback(ref, arg).")
	write("Faulting EIP 0x00401170 is the tiny TESForm::GetTypeID inline; callback frame is 0x009F544E.")
	decompile_at(0x00401170, "TESForm::GetTypeID inline")
	disasm_window(0x00401160, 0x40, "GetTypeID inline vicinity", [0x00401170])
	decompile_at(0x009f544e, "Callback frame from CrashLogger")
	disasm_window(0x009f5400, 0x120, "Callback frame vicinity", [0x009f544e])
	find_refs_into_function(0x009f544e, "Callback frame")
	find_and_print_calls_from(0x009f544e, "Callback frame")
	decompile_cell_enum_patch_callers()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/crash_00401170_stewie_cell_enum_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
