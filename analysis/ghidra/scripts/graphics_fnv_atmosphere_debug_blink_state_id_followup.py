# @category Analysis
# @description Census exact render-state IDs constructed by FNV state-node builder calls for atmosphere debug blinking

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

IMAGE_SPACE_PRESET_STAGES = 0x00C04120
RENDER_STATE_NODE_BUILDER = 0x00E7F430

STATE_IDS = {
	52: "D3DRS_STENCILENABLE",
	152: "D3DRS_CLIPPLANEENABLE",
	161: "D3DRS_MULTISAMPLEANTIALIAS",
	162: "D3DRS_MULTISAMPLEMASK",
	174: "D3DRS_SCISSORTESTENABLE",
	181: "D3DRS_ADAPTIVETESS_Y",
	206: "D3DRS_SEPARATEALPHABLENDENABLE",
}

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
	index = 0
	limit = before_count + after_count + 1
	while inst is not None and index < limit:
		addr_int = inst.getAddress().getOffset()
		marker = " << TARGET" if addr_int == center_int else ""
		write("  0x%08x: %-52s%s" % (addr_int, inst.toString(), marker))
		inst = inst.getNext()
		index += 1

def immediate_state_id_at_call(call_addr):
	call_inst = listing.getInstructionAt(toAddr(call_addr))
	if call_inst is None:
		return None
	previous = call_inst.getPrevious()
	lookback = 0
	while previous is not None and previous.getMnemonicString() != "PUSH" and lookback < 4:
		previous = previous.getPrevious()
		lookback += 1
	if previous is None or previous.getMnemonicString() != "PUSH":
		return None
	try:
		scalar = previous.getScalar(0)
	except:
		scalar = None
	if scalar is None:
		return None
	return scalar.getUnsignedValue()

def add_count(counts, state_id):
	current = counts.get(state_id)
	if current is None:
		counts[state_id] = 1
	else:
		counts[state_id] = current + 1

def scan_exact_state_ids():
	write("")
	write("=" * 70)
	write("EXACT IMMEDIATE STATE-ID CENSUS")
	write("=" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(RENDER_STATE_NODE_BUILDER))
	counts = {}
	total_refs = 0
	call_refs = 0
	immediate_calls = 0
	non_immediate_calls = []
	target_matches = []
	while refs.hasNext():
		ref = refs.next()
		total_refs += 1
		if not ref.getReferenceType().isCall():
			continue
		call_refs += 1
		call_addr = ref.getFromAddress().getOffset()
		state_id = immediate_state_id_at_call(call_addr)
		if state_id is None:
			non_immediate_calls.append(call_addr)
			continue
		immediate_calls += 1
		add_count(counts, state_id)
		if state_id in STATE_IDS:
			target_matches.append((call_addr, state_id))
	write("Total references: %d" % total_refs)
	write("Call references: %d" % call_refs)
	write("Immediate state-ID calls: %d" % immediate_calls)
	write("Computed or unrecognized state-ID calls: %d" % len(non_immediate_calls))
	write("")
	write("Immediate state-ID histogram:")
	state_keys = counts.keys()
	state_keys.sort()
	for state_id in state_keys:
		write("  %d (0x%x): %d calls" % (state_id, state_id, counts[state_id]))
	write("")
	write("Exact IDs relevant to the blink contract:")
	target_keys = STATE_IDS.keys()
	target_keys.sort()
	for state_id in target_keys:
		write("  %d/%s: %d immediate calls" % (state_id, STATE_IDS[state_id], counts.get(state_id, 0)))
	write("")
	write("Matching call sites:")
	for item in target_matches:
		call_addr = item[0]
		state_id = item[1]
		from_func = fm.getFunctionContaining(toAddr(call_addr))
		fname = from_func.getName() if from_func else "???"
		write("  0x%08x in %s: %d/%s" % (call_addr, fname, state_id, STATE_IDS[state_id]))
		disasm_window(call_addr, 6, 4, "%d/%s" % (state_id, STATE_IDS[state_id]))
	write("")
	write("Computed or unrecognized state-ID call sites:")
	for call_addr in non_immediate_calls:
		from_func = fm.getFunctionContaining(toAddr(call_addr))
		fname = from_func.getName() if from_func else "???"
		write("  0x%08x in %s" % (call_addr, fname))
		disasm_window(call_addr, 8, 4, "computed or unrecognized state ID")

def main():
	write("FNV ATMOSPHERE DEBUG BLINK STATE-ID FOLLOW-UP")
	write("")
	write("This follow-up reads the nearest argument PUSH before every call to")
	write("the render-state node builder. It skips intervening ECX setup but does")
	write("not infer IDs from unrelated nearby")
	write("instructions and does not cap the census or relevant call-site output.")
	write("Computed state IDs are printed separately and remain unresolved until")
	write("their call windows are reviewed.")
	decompile_at(IMAGE_SPACE_PRESET_STAGES, "ImageSpaceShader::PresetStages")
	find_and_print_calls_from(IMAGE_SPACE_PRESET_STAGES, "ImageSpaceShader::PresetStages")
	decompile_at(RENDER_STATE_NODE_BUILDER, "render-state node builder")
	scan_exact_state_ids()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_atmosphere_debug_blink_state_id_followup.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("")
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
