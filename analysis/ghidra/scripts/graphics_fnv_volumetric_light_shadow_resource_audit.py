# @category Analysis
# @description Audit FNV shadow-map and scene-light resource ownership for OMV volumetric lighting

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []
decompiled_entries = {}

OUTPATH = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_volumetric_light_shadow_resource_audit.txt"
DECOMPILE_TIMEOUT_SECONDS = 15
MAX_DECOMPILE_FUNCTION_BYTES = 5000

FUNCTIONS = [
	(0x00871290, "vanilla RenderShadowMaps"),
	(0x00B5B1F0, "RenderShadowMaps direct helper 00B5B1F0"),
	(0x00B5B060, "RenderShadowMaps direct helper 00B5B060"),
	(0x00B5C3C0, "RenderShadowMaps direct helper 00B5C3C0"),
	(0x00B5CBD0, "RenderShadowMaps direct helper 00B5CBD0"),
	(0x00B5CDE0, "RenderShadowMaps direct helper 00B5CDE0"),
	(0x00B5AFC0, "RenderShadowMaps direct helper 00B5AFC0"),
	(0x00B5B010, "RenderShadowMaps direct helper 00B5B010"),
	(0x00B5D300, "RenderShadowMaps direct helper 00B5D300"),
	(0x00B5B880, "RenderShadowMaps direct helper 00B5B880"),
	(0x00871A50, "vanilla RenderShadowMaps tail"),
	(0x00B7DAB0, "PPLighting current-draw constant staging owner"),
	(0x00B78A90, "ShadowLightShader UpdateLights"),
	(0x00B7B930, "ShadowProj matrix writer"),
	(0x00B7B450, "lighting shader constant owner A"),
	(0x00B7C3A0, "lighting shader constant owner B"),
	(0x00BB1F60, "lighting shader constant owner C"),
	(0x00BD66C0, "camera projection constant writer"),
	(0x00B6B610, "BSRenderedTexture CreateTexture"),
	(0x00B6E110, "BSTextureManager BorrowRenderedTexture"),
	(0x00B6B890, "BSRenderedTexture Start"),
	(0x00B6B8D0, "BSRenderedTexture StartOffscreen"),
	(0x00B6B730, "BSRenderedTexture Stop"),
	(0x00B6B790, "BSRenderedTexture StopOffscreen"),
	(0x00E88A20, "NiDX9RenderState SetTexture"),
]

GLOBALS = [
	(0x011FA0C0, "Ambient Color backing"),
	(0x011FA0D0, "draw-scoped LightColors slot 0 backing"),
	(0x011FA0E0, "draw-scoped LightColors slot 1 backing"),
	(0x011FA1F0, "staged draw-scoped LightData/radius slot 0 backing"),
	(0x011FD968, "ShadowProj matrix backing"),
	(0x011FD9A8, "transformed draw-scoped light position/direction slot 0"),
	(0x011FD9B8, "transformed draw-scoped light position/direction slot 1"),
	(0x011FD9C8, "transformed draw-scoped light position/direction slot 2"),
	(0x011FD9D8, "transformed draw-scoped light position/direction slot 3"),
	(0x011FD9E8, "transformed draw-scoped light position/direction slot 4"),
	(0x011F91AC, "ImageSpaceManager singleton"),
]

CALLER_TARGETS = [
	(0x00871290, "vanilla RenderShadowMaps"),
	(0x00B78A90, "ShadowLightShader UpdateLights"),
	(0x00B7B930, "ShadowProj matrix writer"),
	(0x00B6B610, "BSRenderedTexture CreateTexture"),
	(0x00B6E110, "BSTextureManager BorrowRenderedTexture"),
	(0x00B6B890, "BSRenderedTexture Start"),
	(0x00B6B8D0, "BSRenderedTexture StartOffscreen"),
	(0x00E88A20, "NiDX9RenderState SetTexture"),
]

WINDOWS = [
	(0x00871290, "RenderShadowMaps entry"),
	(0x00871A50, "RenderShadowMaps vanilla tail used by NVR"),
	(0x00B78AB1, "UpdateLights active light publication"),
	(0x00B78B93, "UpdateLights direction publication"),
	(0x00B78DD4, "UpdateLights color publication"),
	(0x00BD676C, "camera projection constant upload"),
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

def audit_globals():
	idx = 0
	while idx < len(GLOBALS):
		item = GLOBALS[idx]
		find_refs_to(item[0], item[1])
		checkpoint_output()
		if monitor.isCancelled():
			return
		idx += 1

def audit_windows():
	idx = 0
	while idx < len(WINDOWS):
		item = WINDOWS[idx]
		disasm_window(item[0], 20, 32, item[1])
		checkpoint_output()
		if monitor.isCancelled():
			return
		idx += 1

def audit_callers():
	idx = 0
	while idx < len(CALLER_TARGETS):
		item = CALLER_TARGETS[idx]
		find_callers(item[0], item[1])
		checkpoint_output()
		if monitor.isCancelled():
			return
		idx += 1

def find_callers(addr_int, label):
	write("")
	write("-" * 70)
	write("Call references TO 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext():
		if monitor.isCancelled():
			write("  [cancelled]")
			break
		ref = refs.next()
		if ref.getReferenceType().isCall():
			from_func = fm.getFunctionContaining(ref.getFromAddress())
			fname = from_func.getName() if from_func else "???"
			inst = listing.getInstructionContaining(ref.getFromAddress())
			text = inst.toString() if inst is not None else ""
			write("  0x%08x (in %s) %s" % (ref.getFromAddress().getOffset(), fname, text))
			count += 1
	write("  Total: %d call references" % count)

def main():
	write("FNV VOLUMETRIC LIGHT SHADOW RESOURCE AUDIT")
	write("")
	write("Questions:")
	write("1. Does vanilla RenderShadowMaps create or retain a shader-readable sun/local shadow texture?")
	write("2. What texture format, projection matrix, cascade/atlas layout, and lifetime would a volumetric pass consume?")
	write("3. Are UpdateLights values a stable scene list or draw-scoped material constants?")
	write("4. Is there a safe value-copy hook that can publish bounded visible local lights after world rendering?")
	write("5. Which paths remain valid when NVR or another shadow owner replaces RenderShadowMaps?")
	write("")
	write("Static-analysis limit:")
	write("This traces vanilla RenderShadowMaps helpers and resolved/indirect callsites. Runtime plugin ownership, live resource identity/format, and NVR compatibility require source comparison plus runtime telemetry.")
	checkpoint_output()
	audit_functions()
	if monitor.isCancelled():
		return
	audit_globals()
	if monitor.isCancelled():
		return
	audit_callers()
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
