# @category Analysis
# @description Audit FNV native fog color lifetime and render-stage ownership for OMV volumetric fog

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []
decompiled_entries = {}

OUTPATH = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_volumetric_fog_stage_ownership_audit.txt"
DECOMPILE_TIMEOUT_SECONDS = 15
MAX_DECOMPILE_FUNCTION_BYTES = 5000

FUNCTIONS = [
	(0x00B5E870, "BSShaderManager camera/fog publication"),
	(0x00B5AAC0, "native fog constant consumer A"),
	(0x00B5E0F0, "native fog constant consumer B"),
	(0x00B7C3A0, "fog-color backing writer A"),
	(0x00B7B450, "fog-color backing writer B"),
	(0x00BB1F60, "fog-color backing writer C"),
	(0x00E87C50, "NiDX9RenderState SetFog"),
	(0x00873200, "Main RenderWorldSceneGraph"),
	(0x00875110, "Main RenderFirstPerson"),
	(0x00B64570, "BSShaderAccumulator RenderFirstPersonAccumulated"),
	(0x00B64E30, "BSShaderAccumulator RenderFirstPersonGeometryGroups"),
	(0x00875FD0, "main image-space owner"),
	(0x00B55AC0, "ProcessImageSpaceShaders"),
]

GLOBALS = [
	(0x011F4998, "default/current fog color R"),
	(0x011F499C, "default/current fog color G"),
	(0x011F49A0, "default/current fog color B"),
	(0x011FA280, "fog end backing"),
	(0x011FA284, "fog range backing"),
	(0x011FA288, "fog power backing"),
	(0x011FA290, "active fog color R backing"),
	(0x011FA294, "active fog color G backing"),
	(0x011FA298, "active fog color B backing"),
	(0x011F91C4, "active scene graph index"),
	(0x011F91C8, "ShadowSceneNode array"),
]

FOG_COLOR_GLOBALS = [
	(0x011FA290, "active fog color R backing"),
	(0x011FA294, "active fog color G backing"),
	(0x011FA298, "active fog color B backing"),
]

WINDOWS = [
	(0x00874180, "world camera upload before world draws"),
	(0x00876136, "ProcessImageSpaceShaders callsite"),
	(0x00B5EC45, "camera writer fog-color publication"),
	(0x00B7C444, "fog-color writer A"),
	(0x00B7C4D1, "fog-color writer A R store"),
	(0x00B7B5D4, "fog-color writer B"),
	(0x00B7B65F, "fog-color writer B R store"),
	(0x00BAA4C8, "unbounded fog-color R writer candidate A"),
	(0x00BAA540, "unbounded fog-color R writer candidate B"),
	(0x00BB1BE8, "unbounded fog-color R writer candidate C"),
	(0x00BB219A, "fog-color writer C"),
]

# These are source-derived NVR replacement sites, not proof that the list is
# complete. The audit records bounded disassembly around every listed site.
FOG_INTERVENTION_SITES = [
	(0x006335EE, "NVR fog-property callsite 01"),
	(0x00B795FA, "NVR fog-property callsite 02"),
	(0x00B7AE86, "NVR fog-property callsite 03"),
	(0x00B7B539, "NVR fog-property callsite 04"),
	(0x00B7C3AB, "NVR fog-property callsite 05"),
	(0x00B86738, "NVR fog-property callsite 06"),
	(0x00BAA43B, "NVR fog-property callsite 07"),
	(0x00BB1B5B, "NVR fog-property callsite 08"),
	(0x00BB1FA5, "NVR fog-property callsite 09"),
	(0x00BB670E, "NVR fog-property callsite 10"),
	(0x00BBDF26, "NVR fog-property callsite 11"),
	(0x00BBE3EC, "NVR fog-property callsite 12"),
	(0x00BC6E33, "NVR fog-property callsite 13"),
	(0x00BD4BED, "NVR fog-property callsite 14"),
	(0x004EC8EE, "NVR underwater-fog callsite"),
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

def decompile_at(addr_int, label, max_len=26000):
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
	max_shown = 100
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

def audit_fog_color_writers():
	write("")
	write("=" * 70)
	write("WRITE SITES FOR ACTIVE FOG COLOR BACKING")
	write("=" * 70)
	idx = 0
	while idx < len(FOG_COLOR_GLOBALS):
		item = FOG_COLOR_GLOBALS[idx]
		refs = ref_mgr.getReferencesTo(toAddr(item[0]))
		count = 0
		while refs.hasNext():
			if monitor.isCancelled():
				write("  [cancelled]")
				return
			ref = refs.next()
			if ref.getReferenceType().isWrite():
				from_addr = ref.getFromAddress().getOffset()
				disasm_window(from_addr, 12, 20, "%s write" % item[1])
				count += 1
		write("  Total write references for 0x%08x (%s): %d" % (item[0], item[1], count))
		checkpoint_output()
		idx += 1

def audit_windows():
	idx = 0
	while idx < len(WINDOWS):
		item = WINDOWS[idx]
		disasm_window(item[0], 18, 28, item[1])
		checkpoint_output()
		if monitor.isCancelled():
			return
		idx += 1

def audit_fog_intervention_sites():
	idx = 0
	while idx < len(FOG_INTERVENTION_SITES):
		item = FOG_INTERVENTION_SITES[idx]
		disasm_window(item[0], 16, 24, item[1])
		checkpoint_output()
		if monitor.isCancelled():
			return
		idx += 1

def main():
	write("FNV VOLUMETRIC FOG STAGE OWNERSHIP AUDIT")
	write("")
	write("Questions:")
	write("1. Which renderer-owned RGB is final and stable for the world camera?")
	write("2. Which writers can replace that RGB between world rendering and image space?")
	write("3. Is native fog applied per draw, and can one boundary disable it without missing transparent/forward geometry?")
	write("4. What is the safe capture point for volumetric-fog color and native-fog replacement state?")
	write("")
	write("Static-analysis limit:")
	write("This audits vanilla code and source-derived NVR intervention sites. It cannot prove runtime plugin ownership, exhaustive draw coverage, or DXVK render-target behavior without runtime telemetry.")
	checkpoint_output()
	audit_functions()
	if monitor.isCancelled():
		return
	audit_globals()
	if monitor.isCancelled():
		return
	audit_fog_color_writers()
	if monitor.isCancelled():
		return
	audit_windows()
	if monitor.isCancelled():
		return
	audit_fog_intervention_sites()
	checkpoint_output()
	print("Output written to %s (%d lines)" % (OUTPATH, len(output)))

try:
	main()
finally:
	checkpoint_output()
	decomp.dispose()
