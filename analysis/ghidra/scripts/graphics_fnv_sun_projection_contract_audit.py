# @category Analysis
# @description Audit FNV sky sun and camera projection contract for Psycho Graphics sunshafts

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x0044FB20: "NewTES",
	0x0045C670: "CurrentCameraGetter_0045C670",
	0x00595EA0: "Sky::GetSunriseBegin",
	0x00595F50: "Sky::GetSunriseEnd",
	0x00595FC0: "Sky::GetSunsetBegin",
	0x00596030: "Sky::GetSunsetEnd",
	0x0063B9B0: "Sky::GetSunriseColorBegin",
	0x0063BA30: "Sky::GetSunsetColorEnd",
	0x006629F0: "CameraOrSceneGetter_006629F0",
	0x00710AB0: "NiCamera/FOV setup candidate",
	0x008706B0: "Main::Render",
	0x00870A00: "Main render world caller A",
	0x00870BD0: "Main render world caller B",
	0x00870AE8: "RenderWorldSceneGraph callsite A",
	0x00870E18: "RenderWorldSceneGraph callsite B",
	0x00873200: "Main::RenderWorldSceneGraph",
	0x00876125: "pCurrentCamera write before image-space",
	0x00876136: "ProcessImageSpaceShaders callsite",
	0x011DEA20: "Sky::singleton",
	0x011F426C: "CameraLocation",
	0x011F474C: "CameraWorldTranslate",
	0x011F917C: "BSShaderManager::pCurrentCamera",
}

TARGETS = [
	0x0044FB20,
	0x0045C670,
	0x00595EA0,
	0x00595F50,
	0x00595FC0,
	0x00596030,
	0x0063B9B0,
	0x0063BA30,
	0x006629F0,
	0x00710AB0,
	0x008706B0,
	0x00870A00,
	0x00870BD0,
	0x00873200,
]

GLOBAL_REFS = [
	0x011DEA20,
	0x011F426C,
	0x011F474C,
	0x011F917C,
]

DISASM_WINDOWS = [
	0x00870AE8,
	0x00870E18,
	0x00876125,
	0x00876136,
]

def write(msg):
	output.append(msg)
	print(msg)

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

def decompile_at(addr_int, label, max_len=16000):
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
		extra = ""
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				extra = "%s ; CALL 0x%08x %s" % (extra, tgt, label_for(tgt))
		write("  0x%08x: %-52s%s%s" % (addr_int, inst.toString(), marker, extra))
		inst = inst.getNext()
		idx += 1

def print_data_layout_notes():
	write("")
	write("=" * 70)
	write("EXPECTED LAYOUTS TO VERIFY AGAINST DECOMPILE/DISASM")
	write("=" * 70)
	write("Sky singleton candidate: *(Sky**)0x011DEA20")
	write("Sky::sun candidate: Sky + 0x28")
	write("SkyObject::RootNode candidate: Sun + 0x04")
	write("NiAVObject::m_localTransform.pos candidate: RootNode + 0x34 + 0x24 = RootNode + 0x58")
	write("NiAVObject::m_worldTransform.pos candidate: RootNode + 0x68 + 0x24 = RootNode + 0x8C")
	write("NiCamera::WorldToCam candidate: Camera + 0x94")
	write("NiCamera::Frustum candidate: Camera + 0xD4")
	write("NiFrustum: left/right/top/bottom/near/far at +0x00/+0x04/+0x08/+0x0C/+0x10/+0x14")
	write("Projection goal: sun direction -> camera/view space -> UV. Do not implement until these offsets are proven here.")

def print_global_refs():
	idx = 0
	while idx < len(GLOBAL_REFS):
		addr = GLOBAL_REFS[idx]
		find_refs_to(addr, label_for(addr))
		idx += 1

def print_disasm_windows():
	idx = 0
	while idx < len(DISASM_WINDOWS):
		addr = DISASM_WINDOWS[idx]
		disasm_window(addr, 18, 42, label_for(addr))
		idx += 1

def print_target_functions():
	idx = 0
	while idx < len(TARGETS):
		addr = TARGETS[idx]
		decompile_at(addr, label_for(addr))
		find_and_print_calls_from(addr, label_for(addr))
		idx += 1

def main():
	write("FNV SUN PROJECTION CONTRACT AUDIT")
	write("")
	write("Questions:")
	write("1. Can Psycho read a real FNV sun direction without depending on TESReloaded?")
	write("2. Which object/offset chain exposes Sky -> Sun -> RootNode -> transform?")
	write("3. Which camera fields are valid at scene/final shader boundaries for projecting sun direction to UV?")
	write("4. Can the sun constants be read without colliding with DepthResolve, TESReloaded, or Shader Loader?")
	print_data_layout_notes()
	print_global_refs()
	print_disasm_windows()
	print_target_functions()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_sun_projection_contract_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))

main()
decomp.dispose()
