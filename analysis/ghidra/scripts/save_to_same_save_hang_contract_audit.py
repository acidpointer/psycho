# @category Analysis
# @description Audit repeated save-load dispatch, changed-form finalization, ModelLoader drain counters, and completion ownership

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
		if count > 200:
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

def disassemble_range(start_int, end_int, label):
	write("")
	write("-" * 70)
	write("Disassembly %s: 0x%08x - 0x%08x" % (label, start_int, end_int))
	write("-" * 70)
	inst = listing.getInstructionAt(toAddr(start_int))
	if inst is None:
		inst = listing.getInstructionContaining(toAddr(start_int))
	count = 0
	while inst is not None and inst.getAddress().getOffset() < end_int:
		line = "  0x%08x: %-72s" % (inst.getAddress().getOffset(), inst.toString())
		refs = inst.getReferencesFrom()
		targets = []
		for ref in refs:
			if ref.getReferenceType().isCall():
				target = ref.getToAddress().getOffset()
				target_func = fm.getFunctionAt(toAddr(target))
				name = target_func.getName() if target_func else "???"
				targets.append("0x%08x %s" % (target, name))
		if len(targets) != 0:
			line += " -> " + ", ".join(targets)
		write(line)
		inst = inst.getNext()
		count += 1
		if count > 4000:
			write("  ... disassembly truncated")
			break

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
		write("  %s @ 0x%08x call_site=0x%08x" % (func.getName(), entry, ref.getFromAddress().getOffset()))
		find_and_print_calls_from(entry, "caller of %s" % label)
	write("  Unique callers: %d" % len(seen))

def print_function_data_refs(addr_int, label):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
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

def audit(addr_int, label, max_len=60000):
	decompile_at(addr_int, label, max_len)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)
	print_function_data_refs(addr_int, label)

write("SAVE-TO-SAME-SAVE HANG CONTRACT AUDIT")
write("")
write("Runtime boundary:")
write("  The third quicksave.fos attempt reached xNVSE PreLoad at 0x00847FD9")
write("  but never reached xNVSE completion at 0x00848C3C. The audit resolves")
write("  dispatch ownership and every counter that can hold the ModelLoader drain.")
write("")
write("Questions:")
write("  1. Which call from FUN_007028B0 dispatches the selected-save callback?")
write("  2. Which exact stage reaches FUN_008492B0 before 0x00848C3C?")
write("  3. What do all three counts summed by FUN_00C3DFA0 represent?")
write("  4. Which functions increment, decrement, or publish those counts?")
write("  5. Can a task fail, be discarded, or reach zero refcount without decrementing?")

audit(0x007028B0, "frame UI/load request dispatcher", 100000)
audit(0x007CE9B0, "selected-save menu owner", 100000)
audit(0x007D3470, "selected-save callback", 70000)
audit(0x008467B0, "load request bridge", 50000)
audit(0x00850760, "top-level load owner", 100000)
audit(0x00847DF0, "changed-form load owner", 180000)
disassemble_range(0x00847FC0, 0x00848010, "xNVSE preload boundary")
disassemble_range(0x00848B80, 0x00848C60, "changed-form finalization and xNVSE completion boundary")

audit(0x008492B0, "load global synchronization release", 140000)
audit(0x00C3E340, "Havok world unlock", 40000)
audit(0x00456520, "ModelLoader drain mode-5 wrapper", 40000)
audit(0x00C3DFA0, "ModelLoader and IO drain wait loop", 140000)
disassemble_range(0x00C3DFA0, 0x00C3E1A0, "ModelLoader drain full loop")
audit(0x00C3E860, "mode-indexed pending task count", 70000)
audit(0x00C3E1B0, "ModelLoader mode transition", 100000)
audit(0x00C3DBF0, "main-thread completed task processing", 140000)

audit(0x004416C0, "queued model task execute wrapper", 100000)
audit(0x00449A50, "model task scalar destructor", 70000)
audit(0x0044DD60, "intrusive release used by completion drain", 70000)
print_callers(0x00C3DFA0, "FUN_00C3DFA0 drain wait")
print_callers(0x00C3E860, "FUN_00C3E860 mode count")
print_callers(0x00C3E1B0, "FUN_00C3E1B0 mode transition")
print_callers(0x00C3DBF0, "FUN_00C3DBF0 completion processing")
print_callers(0x004416C0, "FUN_004416C0 queued model task")

find_refs_to(0x01202D98, "ModelLoader or IO manager singleton")
find_refs_to(0x011AF70C, "ModelLoader drain complete flag")
find_refs_to(0x01202DD8, "completed-task processing reentrancy flag")

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/save_to_same_save_hang_contract_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
