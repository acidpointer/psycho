# @category Analysis
# @description Close FNV scene-wide local-light enumeration, native shadow encoding, and safe frame-copy ownership

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

FUNCTIONS = [
	(0x00450B80, "shadow scene manager getter"),
	(0x00871290, "vanilla RenderShadowMaps world-frame owner"),
	(0x00B5C450, "scene-wide +0xB4 light lookup and shadow-class update"),
	(0x00B5C940, "scene-wide light find, create, associate, and insert"),
	(0x00B5CBD0, "per-light shadow object find or create"),
	(0x00B5CDE0, "shadow candidate list ordering and filtering"),
	(0x00B5D300, "scene geometry and light association builder"),
	(0x00B5A930, "candidate collection lookup"),
	(0x00B5AEA0, "candidate collection removal or state update"),
	(0x00BA0110, "candidate collection insertion or retention"),
	(0x00BA02B0, "candidate collection publication finalizer"),
	(0x00B5B880, "selected shadow-light post-render loop"),
	(0x00B9DCB0, "ShadowSceneLight shadow-casting state setter"),
	(0x00B9DDA0, "ShadowSceneLight native light association and type classifier"),
	(0x00B9CFD0, "render-accumulator refcounted owner setter"),
	(0x00B9FDA0, "per-light shadow object constructor"),
	(0x00B9DFC0, "selected light shadow-camera and queue publication"),
	(0x00B9F780, "per-light shadow render completion and matrix publication"),
	(0x00B4F710, "renderer package selection and ATI shadow-format override"),
	(0x00B78A90, "draw-scoped ShadowLightShader UpdateLights"),
	(0x00B70820, "draw-scoped native light constant publisher"),
	(0x00B7DAB0, "PPLighting draw setup and UpdateLights caller"),
]

CALL_CONTEXT_TARGETS = [
	(0x00B5C450, "scene-wide +0xB4 light lookup and shadow-class update"),
	(0x00B5C940, "scene-wide light find, create, associate, and insert"),
	(0x00B5CBD0, "per-light shadow object find or create"),
	(0x00B5CDE0, "shadow candidate list ordering and filtering"),
	(0x00B5D300, "scene geometry and light association builder"),
	(0x00B5B880, "selected shadow-light post-render loop"),
	(0x00B9CFD0, "render-accumulator refcounted owner setter"),
	(0x00B9DFC0, "selected light shadow-camera and queue publication"),
	(0x00B9F780, "per-light shadow render completion and matrix publication"),
	(0x00B78A90, "draw-scoped ShadowLightShader UpdateLights"),
	(0x00B70820, "draw-scoped native light constant publisher"),
]

REFERENCE_TARGETS = [
	(0x011AD870, "type-0x2B rendered-texture format selector, default R32F"),
	(0x011F9174, "current selected shadow-light object diagnostic global"),
	(0x011F91C8, "current world camera or scene root used by light transforms"),
	(0x011FA170, "draw-scoped native light position or direction array"),
	(0x011FA1F0, "draw-scoped native light color or attenuation array"),
	(0x011FD9A8, "transformed draw-scoped light constant array"),
	(0x011FA0D0, "current draw light color constant"),
]

OFFSET_SCAN_RANGES = [
	(0x00871290, 0x00871A00, "RenderShadowMaps selection and render transaction"),
	(0x00B5A800, 0x00B5D9FF, "shadow scene manager collection helpers"),
	(0x00B9CF00, 0x00BA0FFF, "per-light shadow object preparation and submission"),
	(0x00B70000, 0x00B7EFFF, "PPLighting draw-scoped light publication"),
]

OFFSET_MARKERS = [
	" + 0xb4]",
	" + 0xc0]",
	" + 0xc4]",
	" + 0xc8]",
	" + 0xcc]",
	" + 0xd0]",
	" + 0xd4]",
	" + 0xec]",
	" + 0xf4]",
	" + 0xf8]",
	" + 0x10c]",
	" + 0x110]",
	" + 0x118]",
	" + 0x11c]",
	" + 0x128]",
	" + 0x140]",
	" + 0x20c]",
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

def checkpoint_output(path):
	fout = open(path, "w")
	fout.write("\n".join(output))
	fout.close()

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

def print_call_contexts(items):
	idx = 0
	while idx < len(items):
		item = items[idx]
		refs = ref_mgr.getReferencesTo(toAddr(item[0]))
		count = 0
		while refs.hasNext():
			ref = refs.next()
			if ref.getReferenceType().isCall():
				disasm_window(ref.getFromAddress().getOffset(), 12, 20, item[1])
				count += 1
				if count >= 20:
					write("  Callsite windows truncated after %d" % count)
					break
		if count == 0:
			write("  [no direct call references to %s]" % item[1])
		idx += 1

def audit_functions(items):
	idx = 0
	while idx < len(items):
		item = items[idx]
		decompile_at(item[0], item[1], 18000)
		find_refs_to(item[0], item[1])
		find_and_print_calls_from(item[0], item[1])
		idx += 1

def audit_references(items):
	idx = 0
	while idx < len(items):
		item = items[idx]
		find_refs_to(item[0], item[1])
		idx += 1

def decompile_direct_callees(addr_int, label, max_count=24, max_len=12000):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	write("")
	write("=" * 70)
	write("DIRECT CALLEES: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	if func is None:
		write("  [function not found]")
		return
	seen = set()
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				target = ref.getToAddress().getOffset()
				if target not in seen:
					seen.add(target)
					callee = fm.getFunctionAt(toAddr(target))
					name = callee.getName() if callee else "unknown direct callee"
					decompile_at(target, "%s direct callee %s" % (label, name), max_len)
					count += 1
					if count >= max_count:
						write("  Direct callee audit truncated after %d functions" % count)
						return
	write("  Total unique direct callees: %d" % count)

def scan_offset_markers():
	write("")
	write("=" * 70)
	write("BOUNDED OBJECT-FIELD ACCESS SCAN")
	write("=" * 70)
	range_idx = 0
	while range_idx < len(OFFSET_SCAN_RANGES):
		item = OFFSET_SCAN_RANGES[range_idx]
		write("")
		write("Range 0x%08x-0x%08x (%s)" % (item[0], item[1], item[2]))
		inst = listing.getInstructionAt(toAddr(item[0]))
		if inst is None:
			inst = listing.getInstructionAfter(toAddr(item[0]))
		matches = 0
		while inst is not None and inst.getAddress().getOffset() <= item[1]:
			text = inst.toString().lower()
			marker_idx = 0
			matched = False
			while marker_idx < len(OFFSET_MARKERS):
				if OFFSET_MARKERS[marker_idx] in text:
					matched = True
					break
				marker_idx += 1
			if matched:
				func = fm.getFunctionContaining(inst.getAddress())
				name = func.getName() if func else "???"
				write("  0x%08x in %-24s %s" % (inst.getAddress().getOffset(), name, inst.toString()))
				matches += 1
			inst = inst.getNext()
		write("  Total matches: %d" % matches)
		range_idx += 1

def print_contract_questions():
	write("FNV VOLUMETRIC LOCAL-LIGHT ENUMERATION AND SHADOW-ENCODING CONTRACT AUDIT")
	write("")
	write("Proven starting point:")
	write("1. ShadowLightShader UpdateLights is draw-scoped and exposes at most ten material/pass lights.")
	write("2. ShadowSceneNode +0xB4 is a manager-wide ShadowSceneLight list keyed by each entry's +0xF8 native light.")
	write("3. ShadowSceneNode +0xC0 is the narrower shadow-candidate list and must not be used as all-light enumeration.")
	write("4. Selected 0x250-byte shadow objects retain an R32F type-0x2B texture at +0x10C on the normal path.")
	write("5. Per-light render completion publishes +0x10, +0x50, and +0x90 matrices beside that texture.")
	write("")
	write("Closure questions:")
	write("1. Which exact functions insert, remove, invalidate, or destroy members of manager +0xB4?")
	write("2. Is +0xB4 stable while RenderShadowMaps runs, so values can be copied at one proven world-frame hook?")
	write("3. Does +0xB4 include player, muzzle, projectile, scripted, non-shadow, and selected shadow point lights?")
	write("4. Which copied identity safely joins a +0xB4 value record to the selected object completed by 0x00B9F780?")
	write("5. What exact scalar or channel does the native shadow pass write to the normal R32F texture?")
	write("6. What transform, divide, compare direction, depth bias, clear value, and out-of-frustum rule decode it?")
	write("7. What does the ATI A8R8G8B8 compatibility path encode, and can unsupported encoding fail closed?")
	write("8. Does NVR preserve the +0xB4 lifecycle, R32F producer, and per-light completion transaction?")
	write("")
	write("Required result:")
	write("A bounded copied-value epoch plus a sampled shadow texture-and-matrix ABI with explicit lifetime and decode rules.")

print_contract_questions()
audit_functions(FUNCTIONS)
decompile_direct_callees(0x00B9CFD0, "render-accumulator refcounted owner setter", 24, 14000)
print_call_contexts(CALL_CONTEXT_TARGETS)
audit_references(REFERENCE_TARGETS)
scan_offset_markers()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_volumetric_local_light_value_copy_contract_audit.txt"
checkpoint_output(outpath)
write("")
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
