# @category Analysis
# @description Audit the current Psycho display fix patch sites, renderer size fields, and reset/present reachability

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

def disasm_window(center_int, before_count, after_count, label):
	write("")
	write("-" * 70)
	write("%s around 0x%08x" % (label, center_int))
	write("-" * 70)
	inst = listing.getInstructionAt(toAddr(center_int))
	if inst is None:
		write("  [instruction not found]")
		return
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
		addr_int = inst.getAddress().getOffset()
		marker = " << TARGET" if addr_int == center_int else ""
		write("  0x%08x: %-58s%s" % (addr_int, inst.toString(), marker))
		inst = inst.getNext()
		index += 1

def scan_renderer_size_field_uses():
	write("")
	write("=" * 70)
	write("Instruction uses of NiDX9Renderer offsets +0xA98/+0xA9C")
	write("=" * 70)
	patterns = ["0xa98]", "0xa9c]"]
	functions = {}
	inst_iter = listing.getInstructions(True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		text = inst.toString().lower()
		matched = False
		for pattern in patterns:
			if pattern in text:
				matched = True
		if not matched:
			continue
		func = fm.getFunctionContaining(inst.getAddress())
		fname = func.getName() if func else "???"
		write("  0x%08x %-58s in %s" % (inst.getAddress().getOffset(), inst.toString(), fname))
		if func is not None:
			functions[func.getEntryPoint().getOffset()] = fname
		count += 1
	write("  Total instructions: %d" % count)
	write("  Functions containing uses: %d" % len(functions))
	for entry in sorted(functions.keys()):
		decompile_at(entry, "renderer size field user %s" % functions[entry], 12000)

def scan_os_globals_active_uses():
	write("")
	write("=" * 70)
	write("Candidate OSGlobals+3 accesses in functions referencing 0x011DEA0C")
	write("=" * 70)
	functions = {}
	refs = ref_mgr.getReferencesTo(toAddr(0x011DEA0C))
	while refs.hasNext():
		ref = refs.next()
		func = fm.getFunctionContaining(ref.getFromAddress())
		if func is not None:
			functions[func.getEntryPoint().getOffset()] = func
	count = 0
	for entry in sorted(functions.keys()):
		func = functions[entry]
		inst_iter = listing.getInstructions(func.getBody(), True)
		while inst_iter.hasNext():
			inst = inst_iter.next()
			text = inst.toString().lower()
			if "+ 0x3]" in text or "+0x3]" in text:
				write("  0x%08x %-58s in %s" % (inst.getAddress().getOffset(), inst.toString(), func.getName()))
				count += 1
	write("  Total candidates: %d" % count)

def print_key_contracts():
	targets = [
		(0x00871C90, "OSGlobals focus state function", 12000),
		(0x0086A0A0, "FNV WndProc", 16000),
		(0x004DC360, "renderer recreation and window resize helper", 16000),
		(0x00E73EB0, "renderer device recreation helper", 16000),
		(0x00B6B730, "frame display/present function", 16000),
		(0x0087055E, "normal-frame xNVSE present hook site owner", 16000),
		(0x007147C4, "loading-frame xNVSE present hook site owner", 16000),
		(0x00E72E60, "NiDX9Renderer device initialization", 16000),
	]
	for item in targets:
		decompile_at(item[0], item[1], item[2])
		find_and_print_calls_from(item[0], item[1])
		find_refs_to(item[0], item[1])

def print_patch_surfaces():
	disasm_window(0x00871C90, 0, 26, "focus function entry fingerprint")
	disasm_window(0x0086B4BF, 14, 10, "main-loop focus-regain SetWindowPos call")
	disasm_window(0x0086B628, 14, 10, "main-loop focus-loss SetWindowPos call")
	disasm_window(0x0087055E, 12, 12, "normal-frame present hook site")
	disasm_window(0x007147C4, 12, 12, "loading-frame present hook site")

def main():
	write("DISPLAY CURRENT FIX CONTRACT AUDIT")
	write("Goal: close current display.rs gaps without assuming Wine behavior matches Windows.")
	print_patch_surfaces()
	print_key_contracts()
	scan_renderer_size_field_uses()
	scan_os_globals_active_uses()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/display_current_fix_contract_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
