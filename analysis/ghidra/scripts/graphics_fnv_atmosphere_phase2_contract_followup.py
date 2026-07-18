# @category Analysis
# @description Closes FNV atmosphere Phase 2 image-target lineage and underwater-state ownership gaps

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

OUTPATH = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_atmosphere_phase2_contract_followup.txt"

output = []

FUNCTIONS = [
	(0x008707C0, "Main world/image-space caller A", 36000),
	(0x00870A00, "Main world/image-space caller B", 36000),
	(0x00870BD0, "Main world/image-space caller C", 48000),
	(0x00872940, "Main world/image-space caller D", 36000),
	(0x00875FD0, "Main image-space owner", 30000),
	(0x00B55AC0, "ProcessImageSpaceShaders", 12000),
	(0x00B97900, "ImageSpaceManager RenderEndOfFrameEffects", 30000),
	(0x004E21B0, "TESWater main render owner", 70000),
	(0x004E2180, "TESWater render-mode getter", 12000),
	(0x004E2160, "TESWater render enable predicate", 12000),
	(0x00408D60, "Boolean setting value getter", 12000),
	(0x004E32E0, "Water-group underwater-pass predicate A", 12000),
	(0x004E3280, "Water-group underwater-pass predicate B", 12000),
	(0x0076B610, "Water-group underwater-pass predicate C", 12000),
	(0x005D43C0, "Water-group underwater-pass state owner", 16000),
	(0x0041F140, "Water-group underwater-pass state query", 12000),
	(0x008256D0, "Water-group underwater-pass exclusion query", 12000),
	(0x004E3320, "Water-group visibility flag writer", 30000),
	(0x004E3520, "Water-group post-render update A", 24000),
	(0x004E3D60, "Water-group post-render update B", 24000),
	(0x004E56C0, "Water-group visible-path setup", 30000),
	(0x004E58A0, "Water-group hidden-path setup", 24000),
	(0x004E62E0, "Water-group camera visibility query", 30000),
	(0x004EC800, "Underwater render-state transaction", 36000),
	(0x004ECB60, "Water reflection/refraction setup transaction", 40000),
	(0x00B79730, "Underwater scalar consumer A", 30000),
	(0x00BBBE80, "Underwater scalar consumer B", 30000),
	(0x00BC7100, "Underwater scalar consumer C", 30000),
]

GLOBALS = [
	(0x011C7A59, "TESWater render-mode byte"),
	(0x011C7A66, "TESWater LOD group active byte A"),
	(0x011C7A67, "TESWater LOD group active byte B"),
	(0x011C7A68, "TESWater visible-group count"),
	(0x011C7A74, "TESWater current water type/stencil value"),
	(0x011F9614, "Underwater fog scalar A"),
	(0x011F9618, "Underwater fog scalar B"),
]

WINDOWS = [
	(0x00870994, 56, 32, "Main caller A image-space invocation"),
	(0x00870B89, 56, 32, "Main caller B image-space invocation"),
	(0x008710E4, 72, 40, "Main caller C image-space invocation"),
	(0x00872A79, 56, 32, "Main caller D image-space invocation"),
	(0x00876136, 40, 32, "ProcessImageSpaceShaders argument handoff"),
	(0x00B55AD6, 24, 28, "RenderEndOfFrameEffects argument handoff"),
	(0x00B9795F, 20, 72, "Native image-space input/output initialization"),
	(0x00B97A01, 40, 40, "Native image-space ping-pong dispatch A"),
	(0x00B97A68, 40, 40, "Native image-space ping-pong dispatch B"),
	(0x004E2EEF, 36, 32, "Water render-mode branch before transaction loop"),
	(0x004E3036, 72, 36, "Underwater transaction caller branch"),
	(0x004E3440, 36, 40, "Water visibility flag writer mode branch"),
	(0x004E392A, 36, 40, "Water post-render mode branch"),
	(0x004EC845, 24, 28, "Underwater transaction enable predicate"),
	(0x004EC8F8, 28, 28, "Underwater scalar publication"),
	(0x00B79807, 28, 36, "Underwater scalar consumer A read"),
	(0x00BBBF9E, 28, 36, "Underwater scalar consumer B read"),
	(0x00BC7157, 28, 36, "Underwater scalar consumer C read"),
]

FIELD_SCANS = [
	(0x004E21B0, "TESWater main render water-group fields"),
	(0x004E3320, "Water visibility writer water-group fields"),
	(0x004E3520, "Water post-render update A fields"),
	(0x004E3D60, "Water post-render update B fields"),
	(0x004E56C0, "Water visible-path fields"),
	(0x004E58A0, "Water hidden-path fields"),
	(0x004E62E0, "Water camera visibility fields"),
]

FIELD_PATTERNS = ["0x5c", "0x5d", "0x5e", "0x5f", "0x60", "0xac"]

def write(msg):
	output.append(msg)
	print(msg)

def checkpoint_output():
	fout = open(OUTPATH, "w")
	try:
		fout.write("\n".join(output))
	finally:
		fout.close()

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
	inst = listing.getInstructionContaining(toAddr(center_int))
	if inst is None:
		inst = listing.getInstructionBefore(toAddr(center_int))
	if inst is None:
		write("  [instruction not found]")
		return
	count = 0
	while count < before_count:
		previous = inst.getPrevious()
		if previous is None:
			break
		inst = previous
		count += 1
	remaining = before_count + after_count + 1
	while inst is not None and remaining > 0:
		addr_int = inst.getAddress().getOffset()
		max_addr_int = inst.getMaxAddress().getOffset()
		marker = " << TARGET" if addr_int <= center_int <= max_addr_int else ""
		write("  0x%08x: %-64s%s" % (addr_int, inst.toString(), marker))
		inst = inst.getNext()
		remaining -= 1

def find_field_accesses(addr_int, label):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	write("")
	write("-" * 70)
	write("Field access scan: %s @ 0x%08x" % (label, addr_int))
	write("-" * 70)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		inst_text = inst.toString().lower()
		pattern_index = 0
		matched = False
		while pattern_index < len(FIELD_PATTERNS):
			if FIELD_PATTERNS[pattern_index] in inst_text:
				matched = True
				break
			pattern_index += 1
		if matched:
			write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
			count += 1
	write("  Total: %d matching instructions" % count)

def audit_functions():
	index = 0
	while index < len(FUNCTIONS):
		item = FUNCTIONS[index]
		decompile_at(item[0], item[1], item[2])
		find_refs_to(item[0], item[1])
		find_and_print_calls_from(item[0], item[1])
		checkpoint_output()
		if monitor.isCancelled():
			return
		index += 1

def audit_globals():
	index = 0
	while index < len(GLOBALS):
		item = GLOBALS[index]
		find_refs_to(item[0], item[1])
		checkpoint_output()
		if monitor.isCancelled():
			return
		index += 1

def audit_windows():
	index = 0
	while index < len(WINDOWS):
		item = WINDOWS[index]
		disasm_window(item[0], item[1], item[2], item[3])
		checkpoint_output()
		if monitor.isCancelled():
			return
		index += 1

def audit_fields():
	index = 0
	while index < len(FIELD_SCANS):
		item = FIELD_SCANS[index]
		find_field_accesses(item[0], item[1])
		checkpoint_output()
		if monitor.isCancelled():
			return
		index += 1

def main():
	write("FNV ATMOSPHERE PHASE 2 CONTRACT FOLLOW-UP")
	write("")
	write("Questions:")
	write("1. Which exact Main caller arguments become the first native image-space source and final destination targets?")
	write("2. Are water-group fields +0x5D/+0x5E camera-underwater state, or only per-group render eligibility?")
	write("3. Who owns and writes fields +0x5C through +0x60 and the render-mode byte at 0x011C7A59?")
	write("4. Do underwater fog scalars have a separate active bit, or are they parameter values consumed outside the transaction?")
	write("5. Is any bounded value-copy boolean valid at the post-world boundary without retaining a water-group pointer?")
	write("")
	write("Do not infer a camera-underwater reader from a scalar or per-water render flag. If no stable flag is proven, identify the exact transaction or camera-query point that OMV must instrument.")
	checkpoint_output()
	audit_functions()
	if monitor.isCancelled():
		return
	audit_globals()
	if monitor.isCancelled():
		return
	audit_windows()
	if monitor.isCancelled():
		return
	audit_fields()
	checkpoint_output()
	print("Output written to %s (%d lines)" % (OUTPATH, len(output)))

try:
	main()
finally:
	checkpoint_output()
	decomp.dispose()
