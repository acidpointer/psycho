# @category Analysis
# @description Close the FNV per-light shadow rendered-texture lifecycle for OMV volumetric lighting

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []
decompiled_entries = {}
critical_field_entries = {}

OUTPATH = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_volumetric_shadow_texture_lifecycle_followup_audit.txt"
DECOMPILE_TIMEOUT_SECONDS = 15
MAX_DECOMPILE_FUNCTION_BYTES = 5000

FUNCTIONS = [
	(0x00871290, "vanilla RenderShadowMaps"),
	(0x00871A50, "vanilla RenderShadowMaps tail and type 0x2D borrow"),
	(0x00B5CBD0, "per-light shadow object find/create"),
	(0x00B9FDA0, "0x250-byte per-light shadow object constructor"),
	(0x00B5B880, "selected shadow-light post-render loop"),
	(0x00B9F780, "per-light shadow projection and image-space pass"),
	(0x00B9D150, "shadow camera/projection setup"),
	(0x00B9DFC0, "selected shadow-light index publication"),
	(0x00B9E970, "shadow render state setup"),
	(0x00B9FBA0, "shadow render state helper"),
	(0x00B5B1F0, "per-light +0x10C release path A"),
	(0x00B5B060, "per-light +0x10C release path B"),
	(0x00B5C3C0, "per-light +0x10C release path C"),
	(0x00B6B260, "current rendered-texture accessor"),
	(0x00B6B610, "BSRenderedTexture CreateTexture"),
	(0x00B6B8D0, "BSRenderedTexture StartOffscreen"),
	(0x00B6B790, "BSRenderedTexture StopOffscreen"),
	(0x00B6C0D0, "rendered-texture target setup"),
	(0x00B6C2C0, "rendered-texture parameter resolver"),
	(0x00B6D170, "rendered-texture allocation constructor"),
	(0x00B6D3F0, "temporary rendered-texture accessor"),
	(0x00B6D4C0, "rendered-texture manager release"),
	(0x00B6D5E0, "rendered-texture exact create/borrow"),
	(0x00B6DA10, "rendered-texture pool return"),
	(0x00B6E110, "BSTextureManager BorrowRenderedTexture"),
	(0x00B6EE70, "temporary rendered-texture pool resize"),
	(0x00B9E850, "temporary rendered-texture pool pop"),
	(0x00B9EFA0, "temporary rendered-texture pool unlink"),
	(0x00B97550, "ImageSpaceManager RenderEffect"),
	(0x00B8C830, "image-space effect dispatch"),
	(0x00BA30F0, "render-task semaphore signal"),
	(0x00BA3130, "render-task semaphore wait"),
	(0x00BA3390, "queued shadow render submission"),
	(0x004BC320, "BSRenderedTexture GetTexture"),
	(0x00BD22C0, "selector-9 shadow texture publication"),
	(0x00BD23F0, "selector-9 shader interface constructor"),
	(0x0066B0D0, "RenderShadowMaps tail type 0x2D consumer"),
]

CALLER_TARGETS = [
	(0x00B9F780, "per-light shadow projection and image-space pass"),
	(0x00B6D4C0, "rendered-texture manager release"),
	(0x00B6D5E0, "rendered-texture exact create/borrow"),
	(0x00B6E110, "BSTextureManager BorrowRenderedTexture"),
	(0x00B97550, "ImageSpaceManager RenderEffect"),
	(0x00BA30F0, "render-task semaphore signal"),
	(0x00BA3130, "render-task semaphore wait"),
	(0x00BA3390, "queued shadow render submission"),
	(0x00BD22C0, "selector-9 shadow texture publication"),
]

GLOBALS = [
	(0x011AD830, "type 0x2B shadow texture dimension"),
	(0x011AD870, "type 0x2B shadow texture format/configuration"),
	(0x011F91A8, "rendered-texture manager used for temporary release"),
	(0x011F9174, "current per-light shadow object"),
	(0x011F9508, "BSTextureManager singleton"),
	(0x011F956C, "shader-interface selector slot 9"),
]

DISASM_WINDOWS = [
	(0x00871AF0, 20, 50, "RenderShadowMaps tail texture cleanup"),
	(0x00871B17, 20, 50, "RenderShadowMaps tail BorrowRenderedTexture type 0x2D"),
	(0x00B5B9DC, 24, 44, "selected-light call to B9F780"),
	(0x00B9F7C2, 20, 44, "render-task wait before offscreen shadow render"),
	(0x00B9E03C, 28, 44, "type 0x2B pool acquisition for +0x10C"),
	(0x00B9E6CB, 28, 48, "queued shadow render submission"),
	(0x00B9F830, 20, 48, "StartOffscreen target selection"),
	(0x00B9F8AA, 24, 48, "shadow rendered-texture target setup"),
	(0x00B9FB04, 24, 52, "+0x10C ImageSpace effect input/output"),
	(0x00B9FB22, 24, 48, "effect 0x11 dispatch"),
	(0x00B9FB2E, 24, 48, "temporary rendered-texture release"),
	(0x00B9FB61, 24, 48, "selector-9 publication of filtered +0x10C texture"),
	(0x00B6EF70, 28, 60, "temporary pool type 0x2B creation path"),
]

RELEVANT_RANGES = [
	(0x00871000, 0x00871FFF, "RenderShadowMaps"),
	(0x00B5A000, 0x00B5FFFF, "shadow scene and manager"),
	(0x00B6B000, 0x00B6EFFF, "rendered-texture manager"),
	(0x00B9D000, 0x00BA1FFF, "shadow light and image-space bridge"),
]

FIELD_MARKERS = [
	" + 0x10c]",
	" + 0x20c]",
	" + 0x124]",
	" + 0x128]",
	" + 0x140]",
]

CRITICAL_FIELD_MARKERS = [
	" + 0x10c]",
	" + 0x20c]",
]

def write(msg):
	output.append(msg)
	print(msg)

def checkpoint_output():
	fout = open(OUTPATH, "w")
	try:
		fout.write("\n".join(output))
	finally:
		fout.close()

def read_u32(addr_int):
	try:
		value = memory.getInt(toAddr(addr_int))
		if value < 0:
			value += 0x100000000
		return value
	except:
		return None

def read_u16(addr_int):
	try:
		value = memory.getShort(toAddr(addr_int))
		if value < 0:
			value += 0x10000
		return value
	except:
		return None

def decompile_at(addr_int, label, max_len=32000):
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
	fsize = func.getBody().getNumAddresses()
	write("  Function: %s @ 0x%08x, Size: %d bytes" % (func.getName(), faddr, fsize))
	if faddr != addr_int:
		write("  NOTE: Requested 0x%08x is inside %s (entry at 0x%08x)" % (addr_int, func.getName(), faddr))
	if decompiled_entries.get(faddr):
		write("  [decompilation already emitted for this containing function]")
		return
	decompiled_entries[faddr] = True
	if fsize > MAX_DECOMPILE_FUNCTION_BYTES:
		write("  [decompilation skipped: function exceeds %d-byte audit bound]" % MAX_DECOMPILE_FUNCTION_BYTES)
		return
	write("  Starting bounded decompile (%d second timeout)..." % DECOMPILE_TIMEOUT_SECONDS)
	checkpoint_output()
	result = decomp.decompileFunction(func, DECOMPILE_TIMEOUT_SECONDS, monitor)
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
	shown = 0
	max_shown = 120
	while refs.hasNext():
		if monitor.isCancelled():
			write("  [cancelled]")
			break
		ref = refs.next()
		count += 1
		if shown < max_shown:
			from_func = fm.getFunctionContaining(ref.getFromAddress())
			fname = from_func.getName() if from_func else "???"
			inst = listing.getInstructionContaining(ref.getFromAddress())
			text = inst.toString() if inst is not None else ""
			write("  %s @ 0x%08x (in %s) %s" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname, text))
			shown += 1
	if count > shown:
		write("  ... (%d refs omitted)" % (count - shown))
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
	resolved = 0
	indirect = 0
	while inst_iter.hasNext():
		if monitor.isCancelled():
			write("  [cancelled]")
			break
		inst = inst_iter.next()
		if not inst.getFlowType().isCall():
			continue
		refs = inst.getReferencesFrom()
		found = False
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				tgt_func = fm.getFunctionAt(toAddr(tgt))
				name = tgt_func.getName() if tgt_func else "???"
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, name))
				resolved += 1
				found = True
		if not found:
			write("  0x%08x -> [indirect/unresolved] %s" % (inst.getAddress().getOffset(), inst.toString()))
			indirect += 1
	write("  Total: %d resolved call references, %d indirect/unresolved calls" % (resolved, indirect))

def disasm_window(center_int, before_count, after_count, label):
	write("")
	write("-" * 70)
	write("Disassembly %s around 0x%08x" % (label, center_int))
	write("-" * 70)
	inst = listing.getInstructionContaining(toAddr(center_int))
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
		max_addr_int = inst.getMaxAddress().getOffset()
		marker = " << TARGET" if addr_int <= center_int <= max_addr_int else ""
		write("  0x%08x: %-64s%s" % (addr_int, inst.toString(), marker))
		inst = inst.getNext()
		idx += 1

def entry_in_relevant_range(entry_int):
	idx = 0
	while idx < len(RELEVANT_RANGES):
		item = RELEVANT_RANGES[idx]
		if item[0] <= entry_int <= item[1]:
			return True
		idx += 1
	return False

def instruction_field_marker(text):
	lower = text.lower()
	idx = 0
	while idx < len(FIELD_MARKERS):
		marker = FIELD_MARKERS[idx]
		if marker in lower:
			return marker
		idx += 1
	return None

def is_critical_field_marker(marker):
	idx = 0
	while idx < len(CRITICAL_FIELD_MARKERS):
		if marker == CRITICAL_FIELD_MARKERS[idx]:
			return True
		idx += 1
	return False

def scan_field_access_range(start_int, end_int, label):
	write("")
	write("=" * 70)
	write("EXACT OBJECT-FIELD ACCESSES: %s 0x%08x-0x%08x" % (label, start_int, end_int))
	write("=" * 70)
	func_iter = fm.getFunctions(toAddr(start_int), True)
	count = 0
	while func_iter.hasNext():
		if monitor.isCancelled():
			write("  [cancelled]")
			break
		func = func_iter.next()
		entry_int = func.getEntryPoint().getOffset()
		if entry_int > end_int:
			break
		if entry_int < start_int:
			continue
		inst_iter = listing.getInstructions(func.getBody(), True)
		while inst_iter.hasNext():
			inst = inst_iter.next()
			text = inst.toString()
			marker = instruction_field_marker(text)
			if marker is not None:
				write("  0x%08x in %s @ 0x%08x: %s" % (inst.getAddress().getOffset(), func.getName(), entry_int, text))
				count += 1
				if is_critical_field_marker(marker):
					critical_field_entries[entry_int] = func.getName()
	write("  Total exact field-access instructions: %d" % count)

def audit_functions():
	idx = 0
	while idx < len(FUNCTIONS):
		item = FUNCTIONS[idx]
		decompile_at(item[0], item[1])
		find_and_print_calls_from(item[0], item[1])
		checkpoint_output()
		if monitor.isCancelled():
			return
		idx += 1

def audit_callers():
	idx = 0
	while idx < len(CALLER_TARGETS):
		item = CALLER_TARGETS[idx]
		find_refs_to(item[0], item[1])
		checkpoint_output()
		if monitor.isCancelled():
			return
		idx += 1

def audit_globals():
	idx = 0
	while idx < len(GLOBALS):
		item = GLOBALS[idx]
		value32 = read_u32(item[0])
		value16 = read_u16(item[0])
		write("")
		write("Global 0x%08x (%s): u32=%s u16=%s" % (item[0], item[1], str(value32), str(value16)))
		find_refs_to(item[0], item[1])
		checkpoint_output()
		if monitor.isCancelled():
			return
		idx += 1

def audit_relevant_callers():
	entries = {}
	idx = 0
	while idx < len(CALLER_TARGETS):
		item = CALLER_TARGETS[idx]
		refs = ref_mgr.getReferencesTo(toAddr(item[0]))
		while refs.hasNext():
			ref = refs.next()
			if not ref.getReferenceType().isCall():
				continue
			func = fm.getFunctionContaining(ref.getFromAddress())
			if func is None:
				continue
			entry_int = func.getEntryPoint().getOffset()
			if entry_in_relevant_range(entry_int):
				entries[entry_int] = func.getName()
		idx += 1
	write("")
	write("=" * 70)
	write("RELEVANT CALLER DECOMPILATIONS")
	write("=" * 70)
	entry_list = entries.keys()
	entry_list.sort()
	idx = 0
	while idx < len(entry_list):
		entry_int = entry_list[idx]
		decompile_at(entry_int, "relevant caller %s" % entries[entry_int])
		checkpoint_output()
		if monitor.isCancelled():
			return
		idx += 1

def audit_field_accesses():
	idx = 0
	while idx < len(RELEVANT_RANGES):
		item = RELEVANT_RANGES[idx]
		scan_field_access_range(item[0], item[1], item[2])
		checkpoint_output()
		if monitor.isCancelled():
			return
		idx += 1
	write("")
	write("=" * 70)
	write("CRITICAL FIELD OWNER DECOMPILATIONS")
	write("=" * 70)
	entry_list = critical_field_entries.keys()
	entry_list.sort()
	idx = 0
	while idx < len(entry_list):
		entry_int = entry_list[idx]
		decompile_at(entry_int, "critical field owner %s" % critical_field_entries[entry_int])
		checkpoint_output()
		if monitor.isCancelled():
			return
		idx += 1

def audit_windows():
	idx = 0
	while idx < len(DISASM_WINDOWS):
		item = DISASM_WINDOWS[idx]
		disasm_window(item[0], item[1], item[2], item[3])
		checkpoint_output()
		if monitor.isCancelled():
			return
		idx += 1

def main():
	write("FNV VOLUMETRIC SHADOW TEXTURE LIFECYCLE FOLLOW-UP AUDIT")
	write("")
	write("Proven starting point:")
	write("1. B9FDA0 constructs the 0x250-byte per-light shadow object and initializes +0x10C to null.")
	write("2. B5B1F0/B5B060/B5C3C0 release the refcounted +0x10C resource.")
	write("3. B9F780 renders the selected light offscreen and dispatches ImageSpace effect 0x11 with +0x10C.")
	write("")
	write("Closure questions:")
	write("1. Which exact instruction writes the live +0x10C rendered texture, and with what creation/borrow parameters?")
	write("2. Is +0x10C the raw shadow map, a filtered copy, or another image-space intermediate?")
	write("3. Which shader texture slot consumes it, and how does that slot map to each selected light?")
	write("4. What dimensions, D3D format, depth surface, projection matrix, and frame lifetime apply?")
	write("5. What is rendered-texture type 0x2D in the RenderShadowMaps tail, and is it related to +0x10C?")
	write("")
	write("Scope guard:")
	write("Field-offset scanning is restricted to the proven RenderShadowMaps, shadow manager, rendered-texture manager, and shadow/image-space bridge ranges. It is not a whole-program layout inference.")
	checkpoint_output()
	audit_functions()
	if monitor.isCancelled():
		return
	audit_callers()
	if monitor.isCancelled():
		return
	audit_globals()
	if monitor.isCancelled():
		return
	audit_relevant_callers()
	if monitor.isCancelled():
		return
	audit_field_accesses()
	if monitor.isCancelled():
		return
	audit_windows()
	checkpoint_output()
	print("Output written to %s (%d lines)" % (OUTPATH, len(output)))

try:
	main()
finally:
	checkpoint_output()
	decomp.dispose()
