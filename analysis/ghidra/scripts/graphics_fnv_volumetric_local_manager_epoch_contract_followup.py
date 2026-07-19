# @category Analysis
# @description Prove the FNV scene-wide local-light snapshot boundary when native shadow rendering is disabled

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

FUNCTIONS = [
	(0x00871290, "world-frame local-light and shadow owner"),
	(0x00B5B880, "selected-shadow traversal and proposed scene-list snapshot boundary"),
	(0x00B5AC20, "scene-wide light-list first accessor candidate"),
	(0x00B5AC60, "scene-wide light-list next accessor candidate"),
	(0x00B5B4A0, "scene-wide light lookup candidate"),
	(0x00B5B4D0, "scene-wide copied-light value publisher candidate A"),
	(0x00B5B610, "scene-wide copied-light value publisher candidate B"),
	(0x00B5C3C0, "shadow scene manager collection clear"),
	(0x00B5C450, "scene-wide light lookup and shadow-class update"),
	(0x00B5C940, "scene-wide light find create associate and insert"),
	(0x00B5D040, "scene-wide light retirement candidate"),
	(0x00B5D180, "scene-wide light removal candidate"),
	(0x00B5E0F0, "shadow scene manager construction or destruction owner"),
	(0x00B9DBE0, "ShadowSceneLight contribution score"),
	(0x00B9DDA0, "ShadowSceneLight native light association and positional classifier"),
	(0x00B9F0C0, "ShadowSceneLight destruction or reset owner"),
]

CALL_CONTEXT_TARGETS = [
	(0x00B5B880, "selected-shadow traversal and proposed scene-list snapshot boundary"),
	(0x00B5AC20, "scene-wide light-list first accessor candidate"),
	(0x00B5AC60, "scene-wide light-list next accessor candidate"),
	(0x00B5B4A0, "scene-wide light lookup candidate"),
	(0x00B5C3C0, "shadow scene manager collection clear"),
	(0x00B5C940, "scene-wide light find create associate and insert"),
	(0x00B5D040, "scene-wide light retirement candidate"),
	(0x00B5D180, "scene-wide light removal candidate"),
	(0x00B9DDA0, "ShadowSceneLight native light association and positional classifier"),
	(0x00B9F0C0, "ShadowSceneLight destruction or reset owner"),
]

FIELD_SCAN_RANGES = [
	(0x00871290, 0x00871A00, "world-frame selection and render transaction"),
	(0x00B5A800, 0x00B5DFFF, "shadow scene manager list ownership"),
	(0x00B5E000, 0x00B600FF, "shadow scene manager construction cleanup and reset"),
	(0x00B9CF00, 0x00BA0FFF, "ShadowSceneLight association lifetime and reset"),
]

FIELD_MARKERS = [
	" + 0xb4]",
	" + 0xb8]",
	" + 0xc0]",
	" + 0xc4]",
	" + 0xc8]",
	" + 0xd0]",
	" + 0xd4]",
	" + 0xec]",
	" + 0xf4]",
	" + 0xf8]",
	" + 0x10c]",
	" + 0x110]",
	" + 0x240]",
]

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

def disasm_window(addr_int, before_count, after_count, label):
	write("")
	write("=" * 70)
	write("DISASM: %s around 0x%08x" % (label, addr_int))
	write("=" * 70)
	inst = listing.getInstructionContaining(toAddr(addr_int))
	if inst is None:
		write("  [instruction not found]")
		return
	start = inst
	count = 0
	while count < before_count:
		previous = start.getPrevious()
		if previous is None:
			break
		start = previous
		count += 1
	current = start
	remaining = before_count + after_count + 1
	while current is not None and remaining > 0:
		marker = "=>" if current.getAddress() == inst.getAddress() else "  "
		write("%s 0x%08x: %s" % (marker, current.getAddress().getOffset(), current.toString()))
		refs = current.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall() or ref.getReferenceType().isData() or ref.getReferenceType().isJump():
				write("      ref %-18s -> 0x%08x" % (ref.getReferenceType(), ref.getToAddress().getOffset()))
		current = current.getNext()
		remaining -= 1

def audit_functions(items):
	idx = 0
	while idx < len(items):
		item = items[idx]
		decompile_at(item[0], item[1], 20000)
		find_refs_to(item[0], item[1])
		find_and_print_calls_from(item[0], item[1])
		idx += 1

def print_call_contexts(items):
	idx = 0
	while idx < len(items):
		item = items[idx]
		refs = ref_mgr.getReferencesTo(toAddr(item[0]))
		count = 0
		while refs.hasNext():
			ref = refs.next()
			if ref.getReferenceType().isCall():
				disasm_window(ref.getFromAddress().getOffset(), 14, 26, item[1])
				count += 1
				if count >= 24:
					write("  Callsite windows truncated after %d" % count)
					break
		if count == 0:
			write("  [no direct call references to %s]" % item[1])
		idx += 1

def scan_field_accesses():
	write("")
	write("=" * 70)
	write("BOUNDED LOCAL-LIGHT OWNER FIELD SCAN")
	write("=" * 70)
	range_index = 0
	while range_index < len(FIELD_SCAN_RANGES):
		item = FIELD_SCAN_RANGES[range_index]
		write("")
		write("Range 0x%08x-0x%08x (%s)" % (item[0], item[1], item[2]))
		inst = listing.getInstructionAt(toAddr(item[0]))
		if inst is None:
			inst = listing.getInstructionAfter(toAddr(item[0]))
		matches = 0
		while inst is not None and inst.getAddress().getOffset() <= item[1]:
			text = inst.toString().lower()
			marker_index = 0
			matched = False
			while marker_index < len(FIELD_MARKERS):
				if FIELD_MARKERS[marker_index] in text:
					matched = True
					break
				marker_index += 1
			if matched:
				func = fm.getFunctionContaining(inst.getAddress())
				name = func.getName() if func else "???"
				write("  0x%08x in %-24s %s" % (inst.getAddress().getOffset(), name, inst.toString()))
				matches += 1
			inst = inst.getNext()
		write("  Total matches: %d" % matches)
		range_index += 1

def print_contract_questions():
	write("FNV VOLUMETRIC LOCAL-LIGHT MANAGER EPOCH CONTRACT FOLLOWUP")
	write("")
	write("Required architecture:")
	write("1. OMV local-light values must remain available when bDrawShadows=0 and native shadow counts are zero.")
	write("2. Native shadow textures are optional per-light enrichment, never the local-light enumeration owner.")
	write("3. The render hook copies bounded scalar values only; it never retains a manager list node or native light pointer.")
	write("")
	write("Closure questions:")
	write("1. Is manager +0xB4 a conventional node chain with next at +0 and ShadowSceneLight payload at +8?")
	write("2. Which functions insert, unlink, clear, destroy, or reassociate +0xB4 entries?")
	write("3. Can any mutation run concurrently with the world-frame call to 0x00B5B880?")
	write("4. Is 0x00B5B880 called even when native shadow drawing and both shadow counts are disabled?")
	write("5. At entry or return from 0x00B5B880, are +0xF8 native light, +0xF4 positional flag, +0xD0 multiplier, and native position/color/radius complete for the current world frame?")
	write("6. Which stable copied identity joins a scene-wide value record to an optional completed shadow record?")
	write("7. What bounded deterministic ordering matches the engine contribution score without retaining engine pointers?")
	write("8. Which loading, reset, camera, or scene transitions require publishing an explicit empty epoch?")
	write("")
	write("Required result:")
	write("A proven zero-native-shadow snapshot boundary and copied-value ABI suitable for an always-available bounded OMV local-light path.")

print_contract_questions()
audit_functions(FUNCTIONS)
print_call_contexts(CALL_CONTEXT_TARGETS)
disasm_window(0x008719A0, 48, 48, "world owner call to the proposed snapshot boundary")
disasm_window(0x00B5B8C0, 24, 96, "selected-shadow traversal entry and zero-count branch")
scan_field_accesses()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_volumetric_local_manager_epoch_contract_followup.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("")
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
