# @category Analysis
# @description Trace SpeedTree owner-vector registration, replacement, and destruction ordering behind the BSTree stress crash

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

def disasm_window(center_int, before_count, after_count, label):
	write("")
	write("-" * 70)
	write("Disassembly around 0x%08x (%s)" % (center_int, label))
	write("-" * 70)
	inst = listing.getInstructionContaining(toAddr(center_int))
	if inst is None:
		inst = listing.getInstructionBefore(toAddr(center_int))
	count = 0
	while inst is not None and count < before_count:
		previous = inst.getPrevious()
		if previous is None:
			break
		inst = previous
		count += 1
	index = 0
	limit = before_count + after_count + 1
	while inst is not None and index < limit:
		address = inst.getAddress().getOffset()
		marker = " << FOCUS" if address == center_int else ""
		write("  0x%08x: %-48s%s" % (address, inst.toString(), marker))
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				target = ref.getToAddress().getOffset()
				write("      call -> 0x%08x %s" % (target, function_name(target)))
		inst = inst.getNext()
		index += 1

def decompile_function_list(items):
	for item in items:
		decompile_at(item[0], item[1], item[2])
		find_and_print_calls_from(item[0], item[1])

def decompile_ref_functions(addr_int, label, range_start, range_end, max_len):
	write("")
	write("-" * 70)
	write("Functions referencing 0x%08x (%s) in 0x%08x-0x%08x" % (addr_int, label, range_start, range_end))
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	seen = set()
	items = []
	while refs.hasNext():
		ref = refs.next()
		func = fm.getFunctionContaining(ref.getFromAddress())
		if func is not None:
			entry = func.getEntryPoint().getOffset()
			if range_start <= entry <= range_end and entry not in seen:
				seen.add(entry)
				items.append((entry, func.getName()))
	write("  Unique functions: %d" % len(items))
	for item in items:
		decompile_at(item[0], "%s referrer to %s" % (item[1], label), max_len)
		find_and_print_calls_from(item[0], "%s referrer to %s" % (item[1], label))

def decompile_relevant_callees(addr_int, label, ranges, max_len):
	func = function_for(addr_int)
	write("")
	write("-" * 70)
	write("Relevant direct callees from %s @ 0x%08x" % (label, addr_int))
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
				in_range = False
				for address_range in ranges:
					if address_range[0] <= target <= address_range[1]:
						in_range = True
				if in_range and target not in seen:
					seen.add(target)
					items.append((target, function_name(target)))
	write("  Unique relevant callees: %d" % len(items))
	for item in items:
		decompile_at(item[0], "%s direct callee %s" % (label, item[1]), max_len)
		find_and_print_calls_from(item[0], "%s direct callee %s" % (label, item[1]))

def print_offset_accesses(addr_int, label, needles):
	func = function_for(addr_int)
	write("")
	write("-" * 70)
	write("Candidate field accesses in %s @ 0x%08x" % (label, addr_int))
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

write("BSTree SpeedTree owner-registration follow-up audit")
write("=" * 70)
write("Established invariant: core SpeedTree +0x34 is nonzero and +0x38 names an owner, but the object is absent from owner[+0x0c,+0x10).")
write("Goal: prove who inserts, removes, replaces, and destroys that registration and identify the first safe intervention edge.")

write("")
write("# PART 1: BSTreeModel construction, load, replacement, and alternate destruction")
tree_functions = [
	(0x0066A650, "BSTreeModel initial core load", 16000),
	(0x0066AC40, "BSTreeModel reload or replacement", 20000),
	(0x00666940, "BSTreeModel virtual load method", 20000),
	(0x00667190, "BSTreeModel virtual operation", 16000),
	(0x00669A10, "BSTreeModel vtable slot 2", 16000),
	(0x00669FD0, "BSTreeModel vtable slot 3 instance creation", 16000)
]
decompile_function_list(tree_functions)
disasm_window(0x0066AF52, 48, 48, "alternate core SpeedTree destruction during model replacement")
print_offset_accesses(0x0066A650, "BSTreeModel initial core load", ["0xc]", "+ 0xc", "0x34", "0x38"])
print_offset_accesses(0x0066AC40, "BSTreeModel reload or replacement", ["0xc]", "+ 0xc", "0x34", "0x38"])

write("")
write("# PART 2: Discover core SpeedTree constructors and registration helpers")
relevant_ranges = [(0x00660000, 0x0066C000), (0x00B00000, 0x00B20000)]
decompile_relevant_callees(0x0066A650, "BSTreeModel initial core load", relevant_ranges, 16000)
decompile_relevant_callees(0x0066AC40, "BSTreeModel reload or replacement", relevant_ranges, 16000)
decompile_relevant_callees(0x00666940, "BSTreeModel virtual load method", relevant_ranges, 16000)
decompile_relevant_callees(0x00669FD0, "BSTreeModel instance creation", relevant_ranges, 12000)

write("")
write("# PART 3: Core global and owner-container writers")
find_refs_to(0x011F8BDC, "core SpeedTree global registry begin")
find_refs_to(0x011F8BE0, "core SpeedTree global registry end")
find_refs_to(0x011F8BE8, "core SpeedTree registry state")
find_refs_to(0x011F8BEC, "core SpeedTree registry state")
find_refs_to(0x011F8BC4, "core SpeedTree registry critical section")
decompile_ref_functions(0x011F8BDC, "core SpeedTree global registry begin", 0x00B00000, 0x00B20000, 16000)
decompile_ref_functions(0x011F8BE0, "core SpeedTree global registry end", 0x00B00000, 0x00B20000, 16000)
decompile_ref_functions(0x011F8BE8, "core SpeedTree registry state", 0x00B00000, 0x00B20000, 16000)
decompile_ref_functions(0x011F8BEC, "core SpeedTree registry state", 0x00B00000, 0x00B20000, 16000)
decompile_ref_functions(0x011F8BC4, "core SpeedTree registry critical section", 0x00B00000, 0x00B20000, 16000)

write("")
write("# PART 4: Registration vector mutation helpers and destructor lock coverage")
decompile_at(0x00B03B30, "core SpeedTree destructor", 20000)
find_and_print_calls_from(0x00B03B30, "core SpeedTree destructor")
decompile_at(0x00B0DF00, "core owner-vector erase", 12000)
find_refs_to(0x00B0DF00, "core owner-vector erase")
decompile_ref_functions(0x00B0DF00, "core owner-vector erase", 0x00B00000, 0x00B20000, 16000)
find_refs_to(0x00B10430, "core registration iterator constructor")
decompile_ref_functions(0x00B10430, "core registration iterator constructor", 0x00B00000, 0x00B20000, 16000)
print_offset_accesses(0x00B03B30, "core SpeedTree destructor", ["0x34", "0x38", "0xc]", "+ 0xc", "0x10"])

write("")
write("# PART 5: Manager locking and publication boundary")
decompile_at(0x00664B50, "BSTreeManager locked model find or create", 20000)
find_and_print_calls_from(0x00664B50, "BSTreeManager locked model find or create")
decompile_at(0x00664F50, "BSTreeManager model and node creation", 22000)
find_and_print_calls_from(0x00664F50, "BSTreeManager model and node creation")
decompile_at(0x00664CD0, "BSTreeManager cleanup under manager lock", 18000)
find_and_print_calls_from(0x00664CD0, "BSTreeManager cleanup under manager lock")
find_refs_to(0x011D5CC0, "BSTreeManager critical section")
decompile_ref_functions(0x011D5CC0, "BSTreeManager critical section", 0x00660000, 0x0066C000, 12000)

write("")
write("ANALYSIS COMPLETE")

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/bstree_speedtree_owner_registration_followup_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
