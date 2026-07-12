# @category Analysis
# @description Audit the 2026-07-12 save crash at 0x00865DFB through the new 0x0092EA45 caller chain

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

def disasm_around(addr_int, label, before_count=28, after_count=36):
	write("")
	write("-" * 70)
	write("Disassembly around %s 0x%08x" % (label, addr_int))
	write("-" * 70)
	inst = listing.getInstructionAt(toAddr(addr_int))
	if inst is None:
		inst = listing.getInstructionBefore(toAddr(addr_int))
	count = 0
	while inst is not None and count < before_count:
		prev = inst.getPrevious()
		if prev is None:
			break
		inst = prev
		count += 1
	printed = 0
	limit = before_count + after_count + 1
	while inst is not None and printed < limit:
		off = inst.getAddress().getOffset()
		marker = "=>" if off == addr_int else "  "
		write("%s 0x%08x: %s" % (marker, off, inst.toString()))
		inst = inst.getNext()
		printed += 1

def audit_frame(addr_int, label):
	func = func_for(addr_int)
	entry = func.getEntryPoint().getOffset() if func else addr_int
	disasm_around(addr_int, label)
	decompile_at(addr_int, label, 18000)
	find_and_print_calls_from(entry, label)

def main():
	write("=" * 70)
	write("2026-07-12 SAVE FORM-REFERENCE CRASH AUDIT")
	write("=" * 70)
	write("Crash: EIP=0x00865DFB, EAX=0x0000000D, EDX=0xCDA794EC")
	write("Stewie Tweaks 9.90 rewrites 0x00865DF0; runtime 0x00865DFB is MOV EAX,[EAX+0x0C].")
	write("Therefore 0x0000000D is the invalid TESForm pointer passed to AppendRefID, not a form type.")
	write("ECX/ESI=BGSSaveFormBuffer; actor context is Head Scribe Taggart.")
	write("This chain does not pass through the existing EntryData list hook at 0x004D4090.")
	write("Questions: which field supplies 0x0D, who owns it, and what validation boundary preserves save layout?")
	audit_frame(0x00865DFB, "faulting form-reference writer")
	audit_frame(0x0092EA45, "direct caller return")
	audit_frame(0x00926A45, "caller frame 2")
	audit_frame(0x009329FA, "caller frame 3")
	audit_frame(0x008AAF55, "actor/process save caller")
	audit_frame(0x008D33B3, "actor save caller")
	audit_frame(0x00847B99, "save pipeline caller")
	audit_frame(0x008505C0, "save pipeline caller 2")
	audit_frame(0x00850A81, "save pipeline caller 3")
	audit_frame(0x00851DFE, "save pipeline caller 4")
	find_refs_to(0x0092EA45, "runtime return site")
	find_refs_to(0x00865DF0, "form-reference writer entry")
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/crash_20260712_save_formref_chain_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
