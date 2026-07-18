# @category Analysis
# @description Audit FNV atmosphere boundary sequencing and native render-state ownership for debug-view blinking

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

MAIN_OWNER_A = 0x008707C0
MAIN_OWNER_B = 0x00870BD0
RENDER_WORLD_SCENE_GRAPH = 0x00873200
RENDER_FIRST_PERSON = 0x00875110
IMAGE_SPACE_OWNER = 0x00875FD0
PROCESS_IMAGE_SPACE_SHADERS = 0x00B55AC0
RENDER_END_OF_FRAME_EFFECTS = 0x00B97900
BS_RENDER_STATE_SET = 0x00B97D90
SHADER_APPLY_RENDER_STATE_LIST = 0x00BE0EB0
IMAGE_SPACE_PRESET_STAGES = 0x00C04120
RENDER_STATE_NODE_BUILDER = 0x00E7F430
CURRENT_RENDER_TARGET = 0x011F9438

KNOWN = {
	MAIN_OWNER_A: "Main world/image-space owner A",
	MAIN_OWNER_B: "Main world/image-space owner B",
	RENDER_WORLD_SCENE_GRAPH: "Main::RenderWorldSceneGraph",
	RENDER_FIRST_PERSON: "Main::RenderFirstPerson",
	IMAGE_SPACE_OWNER: "Main image-space owner",
	PROCESS_IMAGE_SPACE_SHADERS: "ImageSpaceManager::ProcessImageSpaceShaders",
	RENDER_END_OF_FRAME_EFFECTS: "ImageSpaceManager::RenderEndOfFrameEffects",
	BS_RENDER_STATE_SET: "BSRenderState::SetRenderState",
	SHADER_APPLY_RENDER_STATE_LIST: "BSShader apply render-state list",
	IMAGE_SPACE_PRESET_STAGES: "ImageSpaceShader::PresetStages",
	RENDER_STATE_NODE_BUILDER: "render-state node builder",
	CURRENT_RENDER_TARGET: "BSShaderManager::pCurrentRenderTarget",
}

FUNCTIONS = [
	MAIN_OWNER_A,
	MAIN_OWNER_B,
	RENDER_WORLD_SCENE_GRAPH,
	RENDER_FIRST_PERSON,
	IMAGE_SPACE_OWNER,
	PROCESS_IMAGE_SPACE_SHADERS,
	RENDER_END_OF_FRAME_EFFECTS,
	SHADER_APPLY_RENDER_STATE_LIST,
	IMAGE_SPACE_PRESET_STAGES,
	RENDER_STATE_NODE_BUILDER,
	BS_RENDER_STATE_SET,
]

CALLSITE_WINDOWS = [
	0x00870AE8,
	0x00870B21,
	0x00870B89,
	0x00870E18,
	0x00870F74,
	0x008710E4,
]

STATE_IDS = {
	7: "D3DRS_ZWRITEENABLE",
	14: "D3DRS_ZENABLE",
	15: "D3DRS_ALPHATESTENABLE",
	27: "D3DRS_ALPHABLENDENABLE",
	52: "D3DRS_STENCILENABLE",
	152: "D3DRS_CLIPPLANEENABLE",
	161: "D3DRS_MULTISAMPLEANTIALIAS",
	162: "D3DRS_MULTISAMPLEMASK",
	168: "D3DRS_COLORWRITEENABLE",
	174: "D3DRS_SCISSORTESTENABLE",
	181: "D3DRS_ADAPTIVETESS_Y",
	206: "D3DRS_SEPARATEALPHABLENDENABLE",
}

def write(msg):
	output.append(msg)
	print(msg)

def decompile_at(addr_int, label, max_len=20000):
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

def label_for(addr_int):
	label = KNOWN.get(addr_int)
	if label is not None:
		return label
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is not None:
		return func.getName()
	func = fm.getFunctionContaining(toAddr(addr_int))
	if func is not None:
		return "%s+0x%x" % (func.getName(), addr_int - func.getEntryPoint().getOffset())
	return "unknown"

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
		extra = ""
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				extra = "%s ; CALL 0x%08x %s" % (extra, tgt, label_for(tgt))
		write("  0x%08x: %-52s%s%s" % (addr_int, inst.toString(), marker, extra))
		inst = inst.getNext()
		idx += 1

def instruction_has_scalar(inst, expected):
	op_index = 0
	while op_index < inst.getNumOperands():
		try:
			scalar = inst.getScalar(op_index)
		except:
			scalar = None
		if scalar is not None and scalar.getUnsignedValue() == expected:
			return True
		op_index += 1
	return False

def state_ids_near_call(call_addr, lookback):
	matched = []
	inst = listing.getInstructionAt(toAddr(call_addr))
	count = 0
	while inst is not None and count <= lookback:
		for state_id in STATE_IDS.keys():
			if state_id not in matched and instruction_has_scalar(inst, state_id):
				matched.append(state_id)
		inst = inst.getPrevious()
		count += 1
	return matched

def format_state_ids(state_ids):
	parts = []
	for state_id in sorted(state_ids):
		parts.append("%d/%s" % (state_id, STATE_IDS.get(state_id, "unknown")))
	return ", ".join(parts)

def scan_state_builder_constant_calls():
	write("")
	write("=" * 70)
	write("RENDER-STATE NODE BUILDER CONSTANT-ID CALLS")
	write("=" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(RENDER_STATE_NODE_BUILDER))
	ref_count = 0
	match_count = 0
	while refs.hasNext():
		ref = refs.next()
		if not ref.getReferenceType().isCall():
			continue
		ref_count += 1
		call_addr = ref.getFromAddress().getOffset()
		matched = state_ids_near_call(call_addr, 8)
		if len(matched) == 0:
			continue
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		fname = from_func.getName() if from_func else "???"
		write("")
		write("Call 0x%08x in %s: %s" % (call_addr, fname, format_state_ids(matched)))
		disasm_window(call_addr, 10, 8, "render-state builder constant match")
		match_count += 1
		if match_count >= 120:
			write("  ... constant-call scan truncated")
			break
	write("Total builder call refs: %d, constant-ID matches shown: %d" % (ref_count, match_count))

def audit_functions():
	index = 0
	while index < len(FUNCTIONS):
		addr = FUNCTIONS[index]
		decompile_at(addr, label_for(addr))
		find_and_print_calls_from(addr, label_for(addr))
		index += 1

def audit_callsites():
	index = 0
	while index < len(CALLSITE_WINDOWS):
		addr = CALLSITE_WINDOWS[index]
		disasm_window(addr, 28, 56, label_for(addr))
		index += 1

def audit_references():
	find_refs_to(RENDER_WORLD_SCENE_GRAPH, label_for(RENDER_WORLD_SCENE_GRAPH))
	find_refs_to(RENDER_FIRST_PERSON, label_for(RENDER_FIRST_PERSON))
	find_refs_to(IMAGE_SPACE_OWNER, label_for(IMAGE_SPACE_OWNER))
	find_refs_to(PROCESS_IMAGE_SPACE_SHADERS, label_for(PROCESS_IMAGE_SPACE_SHADERS))
	find_refs_to(SHADER_APPLY_RENDER_STATE_LIST, label_for(SHADER_APPLY_RENDER_STATE_LIST))
	find_refs_to(RENDER_STATE_NODE_BUILDER, label_for(RENDER_STATE_NODE_BUILDER))
	find_refs_to(CURRENT_RENDER_TARGET, label_for(CURRENT_RENDER_TARGET))

def print_header():
	write("FNV ATMOSPHERE DEBUG BLINK STATE CONTRACT AUDIT")
	write("")
	write("Questions:")
	write("1. What executes between phase-1 world return, first-person rendering, and outer image space?")
	write("2. Can a supported Main path replace, copy, or rebind world color after OMV's hook?")
	write("3. Which render-state list functions own world and native image-space state?")
	write("4. Do native state builders mention MSAA mask/enable, vendor alpha coverage, clip, stencil, or scissor states?")
	write("5. Which state and presentation facts remain runtime-only under DXVK?")
	write("")
	write("State IDs of interest:")
	write(format_state_ids(STATE_IDS.keys()))
	write("")
	write("Static limitation:")
	write("This audit proves native code shape and constant state construction only. It cannot prove the inherited D3D state or pixel contents on the blinking DXVK frame.")

def main():
	print_header()
	audit_callsites()
	audit_references()
	audit_functions()
	scan_state_builder_constant_calls()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_atmosphere_debug_blink_state_contract_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("")
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
