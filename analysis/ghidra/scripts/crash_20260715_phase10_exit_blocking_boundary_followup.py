# @category Analysis
# @description Audit blocking boundaries after the phase10-exit heartbeat for the 2026-07-15 hard freeze

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

def disasm_entry(addr_int, label, count):
	write("")
	write("-" * 70)
	write("Entry disassembly: %s @ 0x%08x" % (label, addr_int))
	write("-" * 70)
	inst = listing.getInstructionAt(toAddr(addr_int))
	index = 0
	while inst is not None and index < count:
		write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
		inst = inst.getNext()
		index += 1

def audit_boundary(addr_int, label, max_len=8000):
	decompile_at(addr_int, label, max_len)
	find_and_print_calls_from(addr_int, label)
	disasm_entry(addr_int, label, 12)
	find_refs_to(addr_int, label)

write("2026-07-15 PHASE10-EXIT BLOCKING BOUNDARY FOLLOW-UP")
write("=" * 70)
write("Established runtime facts:")
write("  The 0x008705D0 phase10 maintenance hook returned and marked phase10-exit.")
write("  No next-frame phase7 heartbeat arrived and CrashLogger saw no exception.")
write("  The AI-join hook counter did not advance, but mode flags can bypass that hook.")
write("  Existing display counters only observe SetWindowPos after renderer recreation.")
write("")
write("This audit separates three dynamic paths:")
write("  A. Deferred renderer recreation and its device-reset callback sequence.")
write("  B. Mode-bypassed post-AI cleanup and queue synchronization.")
write("  C. Later frame-tail processing, including the periodic free-block callback.")

audit_boundary(0x004dc360, "A1 deferred renderer recreation owner", 18000)
audit_boundary(0x00e73eb0, "A2 renderer recreate wrapper", 10000)
audit_boundary(0x00e736b0, "A3 renderer device reset and registered callbacks", 30000)
audit_boundary(0x0043d4d0, "A4 processor-setting lookup before AI join")
audit_boundary(0x00713d80, "A5 AI manager lookup before AI join")

audit_boundary(0x0086f6a0, "B1 post-AI frame work", 18000)
audit_boundary(0x0096c240, "B2 post-AI synchronization entry")
audit_boundary(0x0096c970, "B3 threaded post-AI synchronization branch")
audit_boundary(0x0096c860, "B4 single-thread post-AI synchronization branch")
audit_boundary(0x0096c710, "B5 post-AI synchronization exit")
audit_boundary(0x009781d0, "B6 post-AI timed update")
audit_boundary(0x0054ae30, "B7 threaded post-AI pre-queue step")
audit_boundary(0x0087a6d0, "B8 threaded queue step A")
audit_boundary(0x0087a790, "B9 threaded queue step B")
audit_boundary(0x00552570, "B10 deferred deletion queue drain", 16000)
audit_boundary(0x0086f830, "B11 threaded post-queue update")
audit_boundary(0x0087a6b0, "B12 threaded queue step C")
audit_boundary(0x007034c0, "B13 late post-AI update")
audit_boundary(0x00703490, "B14 late post-AI finalize")
audit_boundary(0x00991600, "B15 post-AI audio state update")

audit_boundary(0x00870610, "C1 frame-tail update owner", 12000)
audit_boundary(0x005aa720, "C2 frame-tail worker update")
audit_boundary(0x0087a710, "C3 frame-tail queue step A")
audit_boundary(0x0087a850, "C4 frame-tail queue step B")
audit_boundary(0x0087a6f0, "C5 frame-tail queue step C")
audit_boundary(0x007094f0, "C6 frame-tail manager update")
audit_boundary(0x00870680, "C7 frame-tail state update", 16000)
audit_boundary(0x00a0e770, "C8 frame-tail task update", 16000)
audit_boundary(0x00703e10, "C9 conditional frame-tail action", 12000)
audit_boundary(0x00aa7290, "C10 periodic free-block callback")
audit_boundary(0x00aa7260, "C11 free-block sort implementation", 16000)

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/crash_20260715_phase10_exit_blocking_boundary_followup.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
