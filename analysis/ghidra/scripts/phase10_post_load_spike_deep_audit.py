# @category Analysis
# @description Split the phase-10 post-load spike into its callees, loops, process-manager lock ownership, and load-boundary work

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
		if len(code) > max_len:
			write("  [decompile truncated at %d chars, total %d]" % (max_len, len(code)))
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
		if count > 160:
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
	inst_iter = listing.getInstructions(body, True)
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

def audit(addr_int, label, max_len=50000):
	decompile_at(addr_int, label, max_len)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)

def collect_call_targets(addr_int):
	targets = {}
	func = func_for(addr_int)
	if func is None:
		return targets
	inst_iter = listing.getInstructions(func.getBody(), True)
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				target = ref.getToAddress().getOffset()
				targets[target] = True
	return targets

def audit_immediate_callees(addr_int, label, max_funcs=100):
	write("")
	write("=" * 70)
	write("IMMEDIATE CALLEES: %s" % label)
	write("=" * 70)
	targets = collect_call_targets(addr_int)
	count = 0
	for target in sorted(targets.keys()):
		decompile_at(target, "callee of %s" % label, 30000)
		find_and_print_calls_from(target, "callee of %s" % label)
		count += 1
		if count >= max_funcs:
			write("  ... callee audit truncated at %d" % max_funcs)
			break
	write("  Unique callees audited: %d" % count)

def print_callers(addr_int, label):
	write("")
	write("=" * 70)
	write("CALLERS: %s" % label)
	write("=" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	seen = {}
	while refs.hasNext():
		ref = refs.next()
		if not ref.getReferenceType().isCall():
			continue
		func = fm.getFunctionContaining(ref.getFromAddress())
		if func is None:
			continue
		entry = func.getEntryPoint().getOffset()
		if entry in seen:
			continue
		seen[entry] = True
		write("  %s" % name_for_func(func))
		find_and_print_calls_from(entry, "caller of %s" % label)

def print_process_lock_users():
	write("")
	write("=" * 70)
	write("PROCESS-MANAGER LOCK USERS")
	write("=" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(0x0040FBF0))
	seen = {}
	while refs.hasNext():
		ref = refs.next()
		if not ref.getReferenceType().isCall():
			continue
		func = fm.getFunctionContaining(ref.getFromAddress())
		if func is None:
			continue
		entry = func.getEntryPoint().getOffset()
		if entry in seen:
			continue
		seen[entry] = True
		write("  lock user %s acquire_site=0x%08x" % (name_for_func(func), ref.getFromAddress().getOffset()))
		find_and_print_calls_from(entry, "process-manager lock user")
	write("  Unique lock users: %d" % len(seen))

def print_function_data_refs(addr_int, label):
	func = func_for(addr_int)
	write("")
	write("-" * 70)
	write("Direct data references: %s" % label)
	write("-" * 70)
	if func is None:
		write("  [function not found]")
		return
	seen = {}
	inst_iter = listing.getInstructions(func.getBody(), True)
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				continue
			target = ref.getToAddress().getOffset()
			if target in seen:
				continue
			if 0x01000000 <= target < 0x01400000:
				seen[target] = True
				write("  0x%08x %s from 0x%08x" % (target, ref.getReferenceType(), inst.getAddress().getOffset()))
	write("  Total direct globals: %d" % len(seen))

def main():
	write("PHASE-10 POST-LOAD SPIKE DEEP AUDIT")
	write("")
	write("Goal:")
	write("  Resolve the repeatable first-post-load 128-203 ms spike currently timed")
	write("  around FUN_0086F670. Split its two callees, identify bounded versus backlog")
	write("  work, and map process-manager lock acquisition, holders, and ownership.")
	audit(0x0086F670, "phase-10 post wrapper", 30000)
	audit(0x005A38E0, "phase-10 post callee A", 100000)
	audit(0x00455490, "phase-10 post callee B", 100000)
	audit(0x0040FBF0, "process-manager lock acquisition", 40000)
	audit(0x0040FBA0, "process-manager lock release", 30000)
	audit(0x008705D0, "per-frame phase-10 caller", 40000)
	audit(0x00850D60, "load-boundary phase-10 caller", 90000)
	audit_immediate_callees(0x005A38E0, "FUN_005A38E0")
	audit_immediate_callees(0x00455490, "FUN_00455490")
	print_callers(0x005A38E0, "FUN_005A38E0")
	print_callers(0x00455490, "FUN_00455490")
	print_process_lock_users()
	print_function_data_refs(0x005A38E0, "FUN_005A38E0")
	print_function_data_refs(0x00455490, "FUN_00455490")
	find_refs_to(0x011F11A0, "process-manager lock global")
	find_refs_to(0x011DEA2B, "loading flag")
	find_refs_to(0x011DEA10, "main or process-manager owner")
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/phase10_post_load_spike_deep_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
