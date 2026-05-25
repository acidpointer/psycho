# @category Analysis
# @description Analyze save-load crash at 0x006EC846 involving still-loading TESObjectREFR tree

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def write(msg):
	output.append(msg)
	print(msg)

def decompile_at(addr_int, label, max_len=10000):
	addr = toAddr(addr_int)
	func = fm.getFunctionAt(addr)
	if func is None:
		func = fm.getFunctionContaining(addr)
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
	else:
		write("  [decompilation failed]")

def find_refs_to(addr_int, label):
	write("")
	write("-" * 70)
	write("References TO 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		fname = from_func.getName() if from_func else "???"
		write("  %s @ 0x%08x (in %s)" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname))
		count += 1
		if count > 40:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)

def find_and_print_calls_from(addr_int, label):
	addr = toAddr(addr_int)
	func = fm.getFunctionAt(addr)
	if func is None:
		func = fm.getFunctionContaining(addr)
	write("")
	write("-" * 70)
	write("Calls FROM 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	if func is None:
		write("  [function not found]")
		return
	addr_iter = func.getBody().getAddresses(True)
	count = 0
	while addr_iter.hasNext():
		a = addr_iter.next()
		inst = listing.getInstructionAt(a)
		if inst is None:
			continue
		if not inst.getFlowType().isCall():
			continue
		refs_from = inst.getReferencesFrom()
		for ref in refs_from:
			target = ref.getToAddress().getOffset()
			target_func = fm.getFunctionAt(toAddr(target))
			target_name = target_func.getName() if target_func else "unknown_0x%08x" % target
			write("  CALL 0x%08x -> %s (from 0x%08x)" % (target, target_name, a.getOffset()))
			count += 1
	write("  Total: %d calls" % count)

def disasm_window(center_int, before_count, after_count, label):
	write("")
	write("-" * 70)
	write("Disassembly %s around 0x%08x" % (label, center_int))
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
		marker = " << FAULT" if inst.getAddress().getOffset() == center_int else ""
		write("  0x%08x: %-36s%s" % (inst.getAddress().getOffset(), inst.toString(), marker))
		inst = inst.getNext()
		idx += 1

def print_function_range(addr_int, label):
	addr = toAddr(addr_int)
	func = fm.getFunctionAt(addr)
	if func is None:
		func = fm.getFunctionContaining(addr)
	write("")
	write("-" * 70)
	write("Function range for %s @ 0x%08x" % (label, addr_int))
	write("-" * 70)
	if func is None:
		write("  [function not found]")
		return
	write("  %s entry=0x%08x size=%d" % (func.getName(), func.getEntryPoint().getOffset(), func.getBody().getNumAddresses()))

def print_calltrace_context():
	write("")
	write("# CrashLogger calltrace")
	write("  0x006EC846 fault")
	write("  0x0044955D")
	write("  0x0066503F")
	write("  0x0050F85B")
	write("  0x0050EE3D")
	write("  0x0056B515")
	write("  0x00452001")
	write("  0x00440CEC")
	write("  0x0043FE04")
	write("  0x00C3DD8E")
	write("  0x00C3E115")
	write("  0x00456531")
	write("  0x00849364")
	write("  0x00848BEA")
	write("  0x0085084B")
	write("  0x008467D3")
	write("  0x007D3548")
	write("  0x007CED81")

def analyze_targets():
	targets = [
		(0x006EC846, "Fault site"),
		(0x0044955D, "Caller 1"),
		(0x0066503F, "Caller 2"),
		(0x0050F85B, "Caller 3"),
		(0x0050EE3D, "Caller 4"),
		(0x0056B515, "Caller 5"),
		(0x00452001, "Caller 6"),
		(0x00440CEC, "Caller 7"),
		(0x0043FE04, "Caller 8"),
		(0x00C3DD8E, "Task manager caller"),
		(0x00C3E115, "ModelLoader wait loop"),
		(0x00456531, "Loader caller"),
		(0x00849364, "Menu/load caller"),
		(0x00848BEA, "Menu/load caller"),
		(0x0085084B, "Menu/load caller"),
		(0x008467D3, "Menu/load caller"),
		(0x007D3548, "Menu caller"),
		(0x007CED81, "Menu caller")
	]
	for item in targets:
		print_function_range(item[0], item[1])
	write("")
	write("# Fault-site disassembly/decompile")
	disasm_window(0x006EC846, 12, 24, "fault site")
	decompile_at(0x006EC846, "Fault site containing function")
	find_and_print_calls_from(0x006EC846, "Fault site containing function")
	write("")
	write("# Task manager / ModelLoader context")
	disasm_window(0x00C3DD8E, 16, 24, "task manager caller")
	disasm_window(0x00C3E115, 20, 24, "ModelLoader wait loop")
	decompile_at(0x00C3DD8E, "Task manager caller")
	decompile_at(0x00C3E115, "ModelLoader wait loop")
	write("")
	write("# Immediate caller context")
	decompile_at(0x0044955D, "Caller 1")
	decompile_at(0x0066503F, "Caller 2")
	decompile_at(0x0050F85B, "Caller 3")
	find_refs_to(0x006EC846, "fault site")

def main():
	write("=" * 70)
	write("SAVE-LOAD TREE REF CRASH 0x006EC846")
	write("=" * 70)
	write("Crash facts:")
	write("  Fault: read 0x00000000 at EIP=0x006EC846")
	write("  ECX/EDX: TESObjectREFR WastelandShrub01, cell STILL_LOADING")
	write("  Recent experiment: IOManager worker count was patched 1 -> 2")
	write("  Goal: identify exact fault instruction and whether stack is task/model-loader path")
	print_calltrace_context()
	analyze_targets()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/crash_006ec846_save_load_tree_ref.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
