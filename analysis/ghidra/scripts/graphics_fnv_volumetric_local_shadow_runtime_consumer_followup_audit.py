# @category Analysis
# @description Trace FNV SimpleShadow package objects to draw-time texture and projection consumers

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

OUTPATH = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_volumetric_local_shadow_runtime_consumer_followup_audit.txt"
DECOMPILE_TIMEOUT_SECONDS = 15
MAX_DECOMPILE_FUNCTION_BYTES = 5000
MAX_DECOMPILE_TEXT = 12000

PACKAGE_RANGE_START = 0x00BF5D80
PACKAGE_RANGE_END = 0x00BF66BF

STRING_TARGETS = [
	(0x010AE95C, "SimpleShadow vertex/pixel descriptor entry point"),
	(0x010AEE24, "SimpleShadow pixel descriptor token A"),
	(0x010AEE1C, "SimpleShadow pixel descriptor token B"),
	(0x010AEE54, "SimpleShadow pixel descriptor token C"),
	(0x01063F48, "SimpleShadow pixel descriptor token D"),
	(0x010AEE14, "SimpleShadow pixel descriptor token E"),
	(0x010AEFE0, "SimpleShadow pixel descriptor token F"),
	(0x01063F30, "SimpleShadow pixel descriptor token G"),
	(0x010AEA5C, "SimpleShadow pixel descriptor token H"),
	(0x01063F24, "SimpleShadow pixel descriptor token I"),
	(0x01063F3C, "SimpleShadow pixel descriptor token J"),
	(0x010AEF10, "SimpleShadow pixel descriptor token K"),
	(0x010AEE0C, "SimpleShadow pixel descriptor token L"),
	(0x0101C45C, "SimpleShadow vertex descriptor token A"),
	(0x010AED64, "SimpleShadow vertex descriptor token B"),
]

REFERENCE_TARGETS = [
	(0x00BF0720, "PPLighting package setup containing SimpleShadow"),
	(0x00B78980, "shader package setup dispatcher"),
	(0x00BA53C0, "package-block object acquisition helper"),
	(0x00B79950, "vertex shader refcounted setter"),
	(0x00B80600, "pixel shader refcounted setter"),
	(0x00E88A20, "D3D SetTexture stage wrapper"),
	(0x00E910A0, "D3D sampler-state wrapper"),
	(0x011F9174, "current per-light shadow object diagnostic global"),
	(0x011FD968, "ShadowProj per-draw matrix backing"),
]

FUNCTIONS = [
	(0x00B78980, "shader package setup dispatcher"),
	(0x00BA53C0, "package-block object acquisition helper"),
	(0x00B79950, "vertex shader refcounted setter"),
	(0x00B80600, "pixel shader refcounted setter"),
	(0x00B80040, "shader-interface field setup helper"),
	(0x00C163A0, "pixel shader indexed lookup helper"),
	(0x00E7DEF0, "render pass state apply helper"),
	(0x00E7F430, "shader-interface field registration helper"),
	(0x00B7B930, "ShadowProj per-draw matrix writer"),
	(0x00B78A90, "ShadowLightShader UpdateLights"),
	(0x00B5B880, "selected local-shadow render loop"),
	(0x00B9F780, "per-light shadow render and matrix producer"),
	(0x00BF66C0, "package setup function following SimpleShadow blocks"),
]

FIELD_SCAN_RANGES = [
	(0x00B78000, 0x00B7EFFF, "PPLighting draw helpers"),
	(0x00BF0000, 0x00BF66BF, "PPLighting package setup"),
	(0x00B58000, 0x00B5FFFF, "local shadow scene manager"),
	(0x00B9D000, 0x00BA0FFF, "local shadow renderer"),
]

FIELD_MARKERS = [
	" + 0x10c]",
	" + 0x110]",
	" + 0x50]",
	" + 0x90]",
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


def decompile_at(addr_int, label, max_len=MAX_DECOMPILE_TEXT):
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
	if fsize > MAX_DECOMPILE_FUNCTION_BYTES:
		write("  [skipped: function exceeds %d-byte bound]" % MAX_DECOMPILE_FUNCTION_BYTES)
		return
	result = decomp.decompileFunction(func, DECOMPILE_TIMEOUT_SECONDS, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		write(code[:max_len])
	else:
		write("  [decompilation failed or timed out]")


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
		inst = listing.getInstructionContaining(ref.getFromAddress())
		inst_text = inst.toString() if inst else "<no instruction>"
		write("  %s @ 0x%08x (in %s) %s" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname, inst_text))
		count += 1
		if count > 80:
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
				if count >= 120:
					write("  ... (truncated)")
					write("  Total shown: %d calls" % count)
					return
	write("  Total: %d calls" % count)


def read_ascii(addr_int, max_length):
	chars = []
	idx = 0
	while idx < max_length:
		try:
			value = getByte(toAddr(addr_int + idx)) & 0xff
		except:
			return None
		if value == 0:
			break
		if value < 0x20 or value > 0x7e:
			return None
		chars.append(chr(value))
		idx += 1
	if len(chars) == 0:
		return None
	return "".join(chars)


def print_strings():
	write("")
	write("=" * 70)
	write("SIMPLESHADOW DESCRIPTOR STRINGS")
	write("=" * 70)
	idx = 0
	while idx < len(STRING_TARGETS):
		item = STRING_TARGETS[idx]
		value = read_ascii(item[0], 160)
		write("  0x%08x %-46s %r" % (item[0], item[1], value))
		idx += 1


def disasm_range(start_int, end_int, label):
	write("")
	write("=" * 70)
	write("DISASM RANGE: %s 0x%08x-0x%08x" % (label, start_int, end_int))
	write("=" * 70)
	inst = listing.getInstructionAt(toAddr(start_int))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(start_int))
	count = 0
	while inst is not None and inst.getAddress().getOffset() <= end_int:
		write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall() or ref.getReferenceType().isData() or ref.getReferenceType().isJump():
				write("      ref %-18s -> 0x%08x" % (ref.getReferenceType(), ref.getToAddress().getOffset()))
		inst = inst.getNext()
		count += 1
		if count >= 1600:
			write("  ... (instruction bound reached)")
			break


def collect_package_globals():
	targets = {}
	inst = listing.getInstructionAt(toAddr(PACKAGE_RANGE_START))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(PACKAGE_RANGE_START))
	while inst is not None and inst.getAddress().getOffset() <= PACKAGE_RANGE_END:
		refs = inst.getReferencesFrom()
		for ref in refs:
			target = ref.getToAddress().getOffset()
			if 0x01100000 <= target and target <= 0x012fffff:
				targets[target] = True
		inst = inst.getNext()
	write("")
	write("=" * 70)
	write("GLOBALS REFERENCED BY SIMPLESHADOW PACKAGE BLOCKS")
	write("=" * 70)
	keys = targets.keys()
	keys.sort()
	idx = 0
	while idx < len(keys):
		target = keys[idx]
		write("")
		write("Global 0x%08x" % target)
		refs = ref_mgr.getReferencesTo(toAddr(target))
		count = 0
		outside_count = 0
		while refs.hasNext():
			ref = refs.next()
			source = ref.getFromAddress().getOffset()
			if source < PACKAGE_RANGE_START or source > PACKAGE_RANGE_END:
				outside_count += 1
				if count < 20:
					func = fm.getFunctionContaining(ref.getFromAddress())
					name = func.getName() if func else "???"
					inst_ref = listing.getInstructionContaining(ref.getFromAddress())
					text = inst_ref.toString() if inst_ref else "<no instruction>"
					write("  outside %-12s 0x%08x in %-24s %s" % (ref.getReferenceType(), source, name, text))
					count += 1
		write("  Outside-range references: %d" % outside_count)
		idx += 1


def scan_field_markers():
	write("")
	write("=" * 70)
	write("FIELD-DISPLACEMENT SCAN")
	write("=" * 70)
	range_idx = 0
	while range_idx < len(FIELD_SCAN_RANGES):
		item = FIELD_SCAN_RANGES[range_idx]
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
			while marker_idx < len(FIELD_MARKERS):
				if FIELD_MARKERS[marker_idx] in text:
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


def audit_references():
	idx = 0
	while idx < len(REFERENCE_TARGETS):
		item = REFERENCE_TARGETS[idx]
		find_refs_to(item[0], item[1])
		checkpoint_output()
		if monitor.isCancelled():
			return
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


def print_starting_contract():
	write("FNV VOLUMETRIC LOCAL-SHADOW RUNTIME CONSUMER FOLLOW-UP AUDIT")
	write("")
	write("Proven starting point:")
	write("1. BF0720 installs SimpleShadow vertex indices 89-91 into three package blocks.")
	write("2. Each block pairs its vertex shader with the pixel family rooted at index 152.")
	write("3. B80600 only assigns the package pixel shader at +0x44; it does not bind a texture stage.")
	write("4. PROJ_SHADOW is a compile define; ShadowProj backing 0x011FD968 is a separate per-draw matrix.")
	write("5. Current-shadow global 0x011F9174 has only the render-loop write and no proven sampling read.")
	write("")
	write("Closure questions:")
	write("1. Which persistent package objects own the three SimpleShadow blocks, and who dispatches them at draw time?")
	write("2. Does any draw-time path read the selected light's +0x10C texture and bind it through D3D SetTexture?")
	write("3. Which object/matrix is paired with that texture, and is its lifetime safe outside the native draw?")


def main():
	try:
		print_starting_contract()
		print_strings()
		checkpoint_output()
		disasm_range(PACKAGE_RANGE_START, PACKAGE_RANGE_END, "three SimpleShadow package blocks")
		checkpoint_output()
		if monitor.isCancelled():
			return
		collect_package_globals()
		checkpoint_output()
		if monitor.isCancelled():
			return
		audit_references()
		if monitor.isCancelled():
			return
		scan_field_markers()
		checkpoint_output()
		if monitor.isCancelled():
			return
		audit_functions()
	finally:
		checkpoint_output()
		decomp.dispose()


main()
