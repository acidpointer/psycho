# @category Analysis
# @description Audit the vanilla main-loop tail after the last phase10-exit heartbeat in the 2026-07-15 hard freeze

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

def decompile_at(addr_int, label, max_len=20000):
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
		previous = inst.getPrevious()
		if previous is None:
			break
		inst = previous
		count += 1
	index = 0
	limit = before_count + after_count + 1
	while inst is not None and index < limit:
		offset = inst.getAddress().getOffset()
		marker = " << last heartbeat call" if offset == center_int else ""
		write("  0x%08x: %-62s%s" % (offset, inst.toString(), marker))
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				target = ref.getToAddress().getOffset()
				write("      call -> 0x%08x %s" % (target, name_for_func(func_for(target))))
		inst = inst.getNext()
		index += 1

def audit_function(addr_int, label):
	decompile_at(addr_int, label)
	find_and_print_calls_from(addr_int, label)
	func = func_for(addr_int)
	if func is not None:
		find_refs_to(func.getEntryPoint().getOffset(), label + " entry")

write("2026-07-15 PHASE10-EXIT HARD FREEZE AUDIT")
write("=" * 70)
write("Runtime facts:")
write("  Last main heartbeat: phase10-exit after hook target 0x008705D0 returned.")
write("  No exception reached CrashLogger and no engine guard fired.")
write("  AI/Havok guards were inactive, loading was false, heap cleanup was idle,")
write("  and the watchdog reported more than 1 GB total free VAS.")
write("  The next phase7 heartbeat never arrived.")
write("")
write("Questions:")
write("  1. Which calls after 0x0086EDF0 can wait, spin, join, lock, or pump messages?")
write("  2. Which runtime flags select the deferred call, AI join, or fallback path?")
write("  3. Can post-AI work wait on renderer, IO, task, or animation workers?")
write("  4. Which narrow call boundaries should receive runtime heartbeats next?")
write("  5. Does any tail function loop on a result that an engine guard can alter?")

decompile_at(0x0086e650, "Outer main-loop frame", 30000)
disasm_window(0x0086edf0, 24, 115, "Main-loop tail after phase10 maintenance")
find_and_print_calls_from(0x0086e650, "Outer main-loop frame")

audit_function(0x004dc360, "Conditional deferred main-thread call")
audit_function(0x008c7990, "AI worker join")
audit_function(0x008ca300, "Single-thread AI fallback")
audit_function(0x0086f6a0, "Post-AI frame work")
audit_function(0x00870610, "Frame-tail update after post-AI")
audit_function(0x0070ed10, "Frame-tail predicate")
audit_function(0x0070ed20, "Frame-tail state setter")
audit_function(0x00703e10, "Frame-tail conditional action")
audit_function(0x00a29680, "Late frame global update")
audit_function(0x005ae270, "Late frame update A")
audit_function(0x005a9d60, "Late frame update B")
audit_function(0x00aa7290, "Periodic frame-tail callback")

find_refs_to(0x011c6fbb, "conditional deferred-call flag")
find_refs_to(0x011dea2b, "main-loop mode flag A")
find_refs_to(0x011dea2d, "main-loop mode flag B")
find_refs_to(0x011dea2e, "main-loop mode flag C")
find_refs_to(0x011dfa19, "AI work-active flag")

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/crash_20260715_phase10_exit_hard_freeze_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
