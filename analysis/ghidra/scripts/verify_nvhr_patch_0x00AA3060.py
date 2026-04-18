# @category Analysis
# @description Verify what the CALL at 0x00AA3060 targets and why NVHR NOPs it.
#
# NVHR applies: patch_nop_call((void *)0x00AA3060);
# We don't. Before copying the patch, understand what CALL this disables.
#
# Questions this answers:
#  Q1. What function contains the instruction at 0x00AA3060?
#  Q2. What function does the CALL at 0x00AA3060 target?
#  Q3. What does the target function do -- SBM init? arena alloc?
#       TLS setup? Something that expects a working vanilla SBM?
#  Q4. If the target were still called on our build, which of our
#       existing patches would its state conflict with?
#  Q5. Are there other callers of the same target that we'd need
#       to also NOP, or is 0x00AA3060 the only invocation?

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def write(msg):
	output.append(msg)
	print(msg)

def decompile_at(addr_int, label, max_len=12000):
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
		write("  NOTE: Requested 0x%08x is inside %s (entry at 0x%08x, +0x%x)" % (addr_int, func.getName(), faddr, addr_int - faddr))
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		write(code[:max_len])
	else:
		write("  [decompilation failed]")

def disasm_window(addr_int, label, before=32, after=32):
	write("")
	write("-" * 70)
	write("Disassembly window around %s @ 0x%08x (-%d / +%d bytes)" % (label, addr_int, before, after))
	write("-" * 70)
	listing = currentProgram.getListing()
	start = addr_int - before
	end = addr_int + after
	inst_iter = listing.getInstructions(toAddr(start), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		ia = inst.getAddress().getOffset()
		if ia < start:
			continue
		if ia > end:
			break
		marker = "  <-- NOP'd CALL" if ia == addr_int else ""
		targets = []
		for ref in inst.getReferencesFrom():
			rt = ref.getReferenceType()
			if rt.isCall() or rt.isConditional() or rt.isJump():
				tgt = ref.getToAddress().getOffset()
				tgt_func = fm.getFunctionAt(toAddr(tgt))
				name = tgt_func.getName() if tgt_func else "???"
				targets.append("-> 0x%08x %s" % (tgt, name))
		suffix = (" ; " + " ; ".join(targets)) if targets else ""
		write("  0x%08x: %s%s%s" % (ia, inst.toString(), suffix, marker))
		count += 1
		if count > 60:
			write("  ... (truncated)")
			break

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
	write("--- Calls FROM %s (entry 0x%08x) ---" % (label, func.getEntryPoint().getOffset()))
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

def get_call_target_at(addr_int):
	listing = currentProgram.getListing()
	inst = listing.getInstructionAt(toAddr(addr_int))
	if inst is None:
		return None
	for ref in inst.getReferencesFrom():
		if ref.getReferenceType().isCall():
			return ref.getToAddress().getOffset()
	return None

def decompile_call_target(addr_int):
	# Resolve the CALL target at addr_int and decompile it.
	tgt = get_call_target_at(addr_int)
	if tgt is None:
		write("")
		write("[No direct CALL at 0x%08x -- might be indirect or not a CALL instruction]" % addr_int)
		return
	write("")
	write("CALL at 0x%08x targets 0x%08x" % (addr_int, tgt))
	decompile_at(tgt, "CALL target (NVHR NOPs this call)", max_len=12000)
	find_and_print_calls_from(tgt, "CALL target")
	find_refs_to(tgt, "CALL target (is it called from other sites?)")

def callers_of_containing(addr_int, label):
	write("")
	write("-" * 70)
	write("Callers of the function containing %s" % label)
	write("-" * 70)
	func = fm.getFunctionContaining(toAddr(addr_int))
	if func is None:
		write("  [no containing function]")
		return
	entry = func.getEntryPoint().getOffset()
	write("  Function entry: %s @ 0x%08x" % (func.getName(), entry))
	refs = ref_mgr.getReferencesTo(toAddr(entry))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		if not ref.getReferenceType().isCall():
			continue
		src = ref.getFromAddress().getOffset()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		fname = from_func.getName() if from_func else "???"
		fentry = from_func.getEntryPoint().getOffset() if from_func else 0
		write("  0x%08x in %s (entry 0x%08x)" % (src, fname, fentry))
		count += 1
		if count > 40:
			write("  ... (truncated)")
			break
	write("  Total callers: %d" % count)

# --- Main body ---

write("######################################################################")
write("# Verify NVHR patch: patch_nop_call(0x00AA3060)")
write("######################################################################")
write("")
write("Goal: see which CALL NVHR disables at 0x00AA3060, what that CALL")
write("targets, and what the target function does.")

# The instruction itself and its immediate neighbourhood.
disasm_window(0x00AA3060, "NOP'd CALL", before=40, after=40)

# The function containing the NOP'd CALL -- we need the surrounding
# logic to understand what the CALL is SUPPOSED to accomplish.
decompile_at(0x00AA3060, "Containing function", max_len=12000)

# Decompile what the CALL targets. This is the function NVHR thinks
# shouldn't run at all on a replaced-allocator build.
decompile_call_target(0x00AA3060)

# Who else calls the containing function? If multiple call sites
# reach this containing function, the one at 0x00AA3060 might be
# specifically a late-init invocation that races with our hooks.
callers_of_containing(0x00AA3060, "0x00AA3060")

# --- Output ---

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/verify_nvhr_patch_0x00AA3060.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
