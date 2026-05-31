# @category Analysis
# @description Audit AI package ownership GetTypeID crash path at 0x00401170/0x005786CC

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

def decompile_at(addr_int, label, max_len=22000):
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
		write("  %s @ 0x%08x (in %s)" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), name_for_func(from_func)))
		count += 1
		if count >= limit:
			write("  ... (truncated at %d)" % limit)
			break
	write("  Total printed: %d" % count)

def find_and_print_calls_from(addr_int, label, limit=260):
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
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, name_for_func(func_for(tgt))))
				count += 1
				if count >= limit:
					write("  ... (truncated at %d)" % limit)
					write("  Total printed: %d" % count)
					return
	write("  Total printed: %d" % count)

def disasm_window(center_int, before_count, after_count, label):
	write("")
	write("-" * 70)
	write("Disassembly: %s around 0x%08x" % (label, center_int))
	write("-" * 70)
	inst = listing.getInstructionAt(toAddr(center_int))
	if inst is None:
		inst = listing.getInstructionBefore(toAddr(center_int))
	count = 0
	while inst is not None and count < before_count:
		prev = inst.getPrevious()
		if prev is None:
			break
		inst = prev
		count += 1
	idx = 0
	limit = before_count + after_count + 1
	while inst is not None and idx < limit:
		off = inst.getAddress().getOffset()
		marker = ""
		if off == center_int:
			marker = " << target"
		write("  0x%08x: %-48s%s" % (off, inst.toString(), marker))
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				write("      call -> 0x%08x %s" % (tgt, name_for_func(func_for(tgt))))
		inst = inst.getNext()
		idx += 1

def print_calls_to_401170_inside(addr_int, label):
	func = func_for(addr_int)
	write("")
	write("=" * 70)
	write("GetTypeID callsites inside %s" % label)
	write("=" * 70)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall() and ref.getToAddress().getOffset() == 0x00401170:
				disasm_window(inst.getAddress().getOffset(), 14, 18, "GetTypeID callsite in " + label)
				count += 1
	write("  Total GetTypeID callsites printed: %d" % count)

def analyze_functions():
	targets = [
		(0x00401170, "TESForm::GetTypeID inline"),
		(0x009F5070, "AI package cell-enum callback"),
		(0x005785E0, "ownership/package comparison helper"),
		(0x00567790, "owner/current package helper A"),
		(0x005679F0, "owner/current package helper B"),
		(0x00567960, "owner/current package helper C"),
		(0x007AF430, "reference/base-form resolver used before GetTypeID"),
		(0x00559450, "current actor/process helper"),
		(0x009344A0, "callback package gate")
	]
	idx = 0
	while idx < len(targets):
		item = targets[idx]
		decompile_at(item[0], item[1], 26000)
		find_and_print_calls_from(item[0], item[1], 260)
		idx += 1

def analyze_windows():
	write("")
	write("=" * 70)
	write("Focused crash windows")
	write("=" * 70)
	disasm_window(0x005786CC, 36, 24, "Crash return address on stack inside 0x005785E0")
	disasm_window(0x009F5449, 28, 28, "Caller 0x009F5070 invokes 0x005785E0")
	disasm_window(0x009F5159, 24, 24, "Earlier direct GetTypeID in 0x009F5070")
	print_calls_to_401170_inside(0x005785E0, "0x005785E0")
	print_calls_to_401170_inside(0x009F5070, "0x009F5070")

def main():
	write("Crash 0x00401170 AI package ownership audit")
	write("")
	write("Fresh CrashLogger: EIP=0x00401170, ECX=EDX=0x00000007, thread=AI Linear Task Thread 1.")
	write("Calltrace frame 0x009F544E is the AI callback after calling 0x005785E0; stack top return address is 0x005786CC.")
	write("Goal: identify which helper feeds the invalid TESForm* and where a safe guard boundary exists.")
	analyze_windows()
	analyze_functions()
	find_refs_to(0x005785E0, "ownership/package comparison helper")
	find_refs_to(0x00567790, "owner/current package helper A")
	find_refs_to(0x007AF430, "reference/base-form resolver")
	find_refs_to(0x009F5070, "AI package cell-enum callback")

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/crash_00401170_ai_package_ownership_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
