# @category Analysis
# @description Prove SpeedTree clone payload ownership, owner-vector insertion, and destruction synchronization for the BSTree crash

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

def decompile_at(addr_int, label, max_len=8000):
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
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	if func is None:
		write("  [function not found at 0x%08x]" % addr_int)
		return
	body = func.getBody()
	inst_iter = currentProgram.getListing().getInstructions(body, True)
	write("")
	write("--- Calls FROM %s (0x%08x) ---" % (label, addr_int))
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				tgt_func = fm.getFunctionAt(toAddr(tgt))
				name = tgt_func.getName() if tgt_func else "???"
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, name))
				count += 1
	write("  Total: %d calls" % count)

def function_for(addr_int):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	return func

def function_name(addr_int):
	func = function_for(addr_int)
	if func is None:
		return "???"
	return "%s @ 0x%08x" % (func.getName(), func.getEntryPoint().getOffset())

def print_function_disassembly(addr_int, label):
	func = function_for(addr_int)
	write("")
	write("-" * 70)
	write("Full disassembly for %s @ 0x%08x" % (label, addr_int))
	write("-" * 70)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	while inst_iter.hasNext():
		inst = inst_iter.next()
		write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				target = ref.getToAddress().getOffset()
				write("      call -> 0x%08x %s" % (target, function_name(target)))

def print_offset_accesses(addr_int, label, needles):
	func = function_for(addr_int)
	write("")
	write("-" * 70)
	write("Candidate clone ownership accesses in %s @ 0x%08x" % (label, addr_int))
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
			if needle in text:
				matched = True
		if matched:
			write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
			count += 1
	write("  Total: %d candidate accesses" % count)

def decompile_direct_callees_in_range(addr_int, label, range_start, range_end, max_len):
	func = function_for(addr_int)
	write("")
	write("-" * 70)
	write("Direct callees from %s in 0x%08x-0x%08x" % (label, range_start, range_end))
	write("-" * 70)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	seen = set()
	items = []
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				target = ref.getToAddress().getOffset()
				if range_start <= target <= range_end and target not in seen:
					seen.add(target)
					items.append((target, function_name(target)))
	write("  Unique callees: %d" % len(items))
	for item in items:
		decompile_at(item[0], "%s direct callee %s" % (label, item[1]), max_len)
		find_and_print_calls_from(item[0], "%s direct callee %s" % (label, item[1]))

write("BSTree SpeedTree clone-registration final audit")
write("=" * 70)
write("Established: base core constructor 0x00B02EF0 initializes +0x34 to zero; only clone constructor 0x00B036D0 can create the crashing nonzero state.")
write("Goal: prove clone payload allocation, shared owner/refcount publication, vector insertion, lock coverage, and inverse destruction order.")

write("")
write("# PART 1: Clone constructor and wrapper")
decompile_at(0x00B036D0, "core SpeedTree clone constructor", 24000)
find_and_print_calls_from(0x00B036D0, "core SpeedTree clone constructor")
print_function_disassembly(0x00B036D0, "core SpeedTree clone constructor")
print_offset_accesses(0x00B036D0, "core SpeedTree clone constructor", ["0x30", "0x34", "0x38", "0xc]", "+ 0xc", "0x10"])
find_refs_to(0x00B036D0, "core SpeedTree clone constructor")
decompile_at(0x00B05210, "clone allocation wrapper", 12000)
find_and_print_calls_from(0x00B05210, "clone allocation wrapper")
find_refs_to(0x00B05210, "clone allocation wrapper")

write("")
write("# PART 2: Every clone-constructor container helper")
decompile_direct_callees_in_range(0x00B036D0, "core SpeedTree clone constructor", 0x00B0C000, 0x00B12000, 16000)

write("")
write("# PART 3: Base registry and per-owner vector primitives for contrast")
decompile_at(0x00B0DCE0, "embedded owner-container constructor", 12000)
find_and_print_calls_from(0x00B0DCE0, "embedded owner-container constructor")
find_refs_to(0x00B0DCE0, "embedded owner-container constructor")
decompile_at(0x00B0DDC0, "global registry insertion helper", 16000)
find_and_print_calls_from(0x00B0DDC0, "global registry insertion helper")
find_refs_to(0x00B0DDC0, "global registry insertion helper")
decompile_at(0x00B0DF00, "vector erase helper", 12000)
find_and_print_calls_from(0x00B0DF00, "vector erase helper")
decompile_at(0x00B0E7F0, "owner-container destruction helper", 12000)
find_and_print_calls_from(0x00B0E7F0, "owner-container destruction helper")

write("")
write("# PART 4: Proven inverse path and physical free boundary")
decompile_at(0x00B03B30, "core SpeedTree destructor", 20000)
find_and_print_calls_from(0x00B03B30, "core SpeedTree destructor")
decompile_at(0x00666910, "core scalar deleting destructor", 8000)
find_and_print_calls_from(0x00666910, "core scalar deleting destructor")
decompile_at(0x00666800, "BSTreeModel destructor", 14000)
find_and_print_calls_from(0x00666800, "BSTreeModel destructor")

write("")
write("ANALYSIS COMPLETE")

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/bstree_speedtree_clone_registration_final_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
