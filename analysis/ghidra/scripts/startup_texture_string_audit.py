# @category Analysis
# @description Trace slow startup texture names to static strings and callers

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

def label_for(addr_int):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is not None:
		return func.getName()
	func = fm.getFunctionContaining(toAddr(addr_int))
	if func is not None:
		return "%s+0x%x" % (func.getName(), addr_int - func.getEntryPoint().getOffset())
	return "unknown"

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
		if count > 80:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)

def find_and_print_calls_from(addr_int, label):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	write("")
	write("--- Calls FROM %s (0x%08x) ---" % (label, addr_int))
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, label_for(tgt)))
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
		addr_int = inst.getAddress().getOffset()
		marker = " << TARGET" if addr_int == center_int else ""
		write("  0x%08x: %-44s%s" % (addr_int, inst.toString(), marker))
		inst = inst.getNext()
		idx += 1

def pattern_list():
	return [
		"loading_screen_bethsoft.dds",
		"loading_screen_legal.dds",
		"wasteland_2048_no_map.dds",
		"InterfaceShared0.dds",
		"loading_background.dds",
		"loading_strips.dds",
		"loading_glare.dds",
		"solid_black.dds"
	]

def find_strings_matching(patterns):
	results = []
	data_iter = listing.getDefinedData(True)
	while data_iter.hasNext():
		data = data_iter.next()
		try:
			if not data.hasStringValue():
				continue
			value = data.getValue()
		except:
			continue
		if value is None:
			continue
		text = str(value)
		lower = text.lower()
		for pattern in patterns:
			if pattern.lower() in lower:
				results.append((data.getAddress().getOffset(), text, pattern))
				break
	return results

def print_ref_context(from_addr, label):
	from_func = fm.getFunctionContaining(toAddr(from_addr))
	fname = from_func.getName() if from_func else "???"
	write("")
	write("Reference context: 0x%08x in %s (%s)" % (from_addr, fname, label))
	disasm_window(from_addr, 10, 22, "string reference")
	if from_func is not None:
		decompile_at(from_func.getEntryPoint().getOffset(), "function using %s" % label, 9000)
		find_and_print_calls_from(from_func.getEntryPoint().getOffset(), "function using %s" % label)

def analyze_string(addr_int, text, pattern):
	write("")
	write("=" * 70)
	write("STARTUP TEXTURE STRING: %s" % pattern)
	write("=" * 70)
	write("String @ 0x%08x: %s" % (addr_int, text))
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		from_addr = ref.getFromAddress().getOffset()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		fname = from_func.getName() if from_func else "???"
		write("  %s @ 0x%08x in %s" % (ref.getReferenceType(), from_addr, fname))
		if count < 8:
			print_ref_context(from_addr, pattern)
		count += 1
		if count > 40:
			write("  ... refs truncated")
			break
	write("  Total refs: %d" % count)

def analyze_known_texture_entrypoints():
	write("")
	write("=" * 70)
	write("KNOWN TEXTURE ENTRYPOINTS")
	write("=" * 70)
	items = [
		(0x0043c4b0, "frequent startup texture/cache helper from renderer bucket audit"),
		(0x00e68a80, "NiDX9SourceTextureData texture load"),
		(0x00a61a60, "texture cache find"),
		(0x00a5fca0, "NiSourceTexture destructor")
	]
	for item in items:
		decompile_at(item[0], item[1])
		find_and_print_calls_from(item[0], item[1])
		find_refs_to(item[0], item[1])

def main():
	write("=" * 70)
	write("STARTUP TEXTURE STRING AUDIT")
	write("=" * 70)
	write("Goal: find who requests the slow startup textures and whether any are bypass candidates.")
	results = find_strings_matching(pattern_list())
	write("Matched startup texture strings: %d" % len(results))
	for item in results:
		analyze_string(item[0], item[1], item[2])
	analyze_known_texture_entrypoints()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/startup_texture_string_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
