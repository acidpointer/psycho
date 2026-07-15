# @category Analysis
# @description Audit FNV vanilla DOF activation, image-space ordering, state layout, and non-invasive OMV coexistence contract

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.address import AddressSet

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x00875E40: "DepthResolve RenderDepthOfField jump site",
	0x00876136: "Main render ProcessImageSpaceShaders callsite",
	0x00B54090: "ImageSpaceManager::GetDepthTexture",
	0x00B54280: "ImageSpaceManager lifecycle candidate A",
	0x00B54630: "ImageSpaceManager lifecycle candidate B",
	0x00B55AC0: "ImageSpaceManager::ProcessImageSpaceShaders",
	0x00B57420: "ImageSpaceManager lifecycle candidate C",
	0x00B578A0: "ImageSpaceManager lifecycle candidate D",
	0x00B8C830: "ImageSpaceManager::RenderEffect object/rendered texture",
	0x00B97550: "ImageSpaceManager::RenderEffect id/rendered texture",
	0x00B97900: "ImageSpaceManager::RenderEndOfFrameEffects",
	0x00B9F780: "ImageSpaceManager state update candidate",
	0x00BA0900: "Image-space state consumer candidate",
	0x00BADB90: "Image-space state consumer candidate",
	0x0102D2A4: "ImageSpaceModifierInstanceDOF vtable",
	0x011CE6B4: "fIronSightsDOFStrengthCap setting",
	0x011CEDF4: "fIronSightsDOFSwitchSeconds setting",
	0x011CF4F8: "fVATSDOFSwitchSeconds setting",
	0x011CF5B8: "fDOFDistanceMult setting",
	0x011CF8C8: "fIronSightsDOFDistance setting",
	0x011CFD70: "fIronSightsDOFRange setting",
	0x011CFE20: "fVATSDOFRange setting",
	0x011CE924: "fVATSDOFStrengthCap setting",
	0x011D318C: "fDialogFocalDepthStrength setting",
	0x011D46FC: "fDialogFocalDepthRange setting",
	0x011F91AC: "ImageSpaceManager singleton pointer",
}

DOF_MANAGER_OFFSETS = {
	0x2A4: "highest/current DOF strength candidate",
	0x2A8: "current DOF distance candidate",
	0x2AC: "current DOF range candidate",
	0x2B0: "current DOF mask constant candidate",
	0x2B4: "weather DOF strength candidate",
	0x2B8: "weather DOF distance candidate",
	0x2BC: "weather DOF range candidate",
	0x2C0: "weather DOF mask constant candidate",
	0x2C4: "current DOF mode candidate",
	0x2C8: "weather DOF mode candidate",
	0x2CC: "current DOF use-mask candidate",
	0x2CD: "weather DOF use-mask candidate",
}

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
		extra = ""
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				target = ref.getToAddress().getOffset()
				extra = " ; CALL 0x%08x %s" % (target, label_for(target))
		write("  0x%08x: %-52s%s%s" % (addr_int, inst.toString(), marker, extra))
		inst = inst.getNext()
		index += 1

def operand_scalar_int(inst, index):
	try:
		scalar = inst.getScalar(index)
		if scalar is None:
			return None
		return int(scalar.getUnsignedValue() & 0xffffffff)
	except:
		return None

def instruction_mentions_dof_offset(inst):
	index = 0
	while index < inst.getNumOperands():
		value = operand_scalar_int(inst, index)
		if value in DOF_MANAGER_OFFSETS:
			return value
		index += 1
	return None

def scan_dof_manager_offset_users(start_int, end_int, label, max_functions):
	write("")
	write("=" * 70)
	write("DOF MANAGER OFFSET USERS: %s 0x%08x-0x%08x" % (label, start_int, end_int))
	write("=" * 70)
	address_set = AddressSet(toAddr(start_int), toAddr(end_int))
	inst_iter = listing.getInstructions(address_set, True)
	functions = {}
	match_count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		offset = instruction_mentions_dof_offset(inst)
		if offset is None:
			continue
		func = fm.getFunctionContaining(inst.getAddress())
		if func is None:
			continue
		entry = func.getEntryPoint().getOffset()
		functions[entry] = func.getName()
		write("  0x%08x in %s: %-44s ; +0x%x %s" % (inst.getAddress().getOffset(), func.getName(), inst.toString(), offset, DOF_MANAGER_OFFSETS[offset]))
		match_count += 1
	write("  Total matching instructions: %d" % match_count)
	entries = functions.keys()
	entries.sort()
	write("  Unique containing functions: %d" % len(entries))
	count = 0
	for entry in entries:
		if count >= max_functions:
			write("  ... function decompilation truncated")
			break
		decompile_at(entry, "DOF offset user %s" % functions[entry], 16000)
		find_and_print_calls_from(entry, functions[entry])
		count += 1

def audit_known_functions():
	functions = [
		(0x00B54280, "ImageSpaceManager lifecycle candidate A"),
		(0x00B54630, "ImageSpaceManager lifecycle candidate B"),
		(0x00B55AC0, "ImageSpaceManager::ProcessImageSpaceShaders"),
		(0x00B57420, "ImageSpaceManager lifecycle candidate C"),
		(0x00B578A0, "ImageSpaceManager lifecycle candidate D"),
		(0x00B8C830, "ImageSpaceManager::RenderEffect object/rendered texture"),
		(0x00B97550, "ImageSpaceManager::RenderEffect id/rendered texture"),
		(0x00B97900, "ImageSpaceManager::RenderEndOfFrameEffects"),
		(0x00B9F780, "ImageSpaceManager state update candidate"),
		(0x00BA0900, "Image-space state consumer candidate"),
		(0x00BADB90, "Image-space state consumer candidate"),
	]
	for item in functions:
		decompile_at(item[0], item[1], 20000)
		find_and_print_calls_from(item[0], item[1])

def audit_references():
	targets = [
		(0x011F91AC, "ImageSpaceManager singleton pointer"),
		(0x0102D2A4, "ImageSpaceModifierInstanceDOF vtable"),
		(0x011CF5B8, "fDOFDistanceMult setting"),
		(0x011D46FC, "fDialogFocalDepthRange setting"),
		(0x011D318C, "fDialogFocalDepthStrength setting"),
		(0x011CF8C8, "fIronSightsDOFDistance setting"),
		(0x011CFD70, "fIronSightsDOFRange setting"),
		(0x011CE6B4, "fIronSightsDOFStrengthCap setting"),
		(0x011CEDF4, "fIronSightsDOFSwitchSeconds setting"),
		(0x011CFE20, "fVATSDOFRange setting"),
		(0x011CE924, "fVATSDOFStrengthCap setting"),
		(0x011CF4F8, "fVATSDOFSwitchSeconds setting"),
	]
	for item in targets:
		find_refs_to(item[0], item[1])

def print_contract_questions():
	write("FNV DOF ENGINE CONTRACT AUDIT")
	write("")
	write("Questions:")
	write("1. How does ImageSpaceManager decide that effect ID 4 is active, and is its read-only active state stable after RenderEndOfFrameEffects?")
	write("2. Which exact +0x2A4..+0x2CD fields represent current/weather DOF strength, distance, range, mode, and mask?")
	write("3. Which gameplay systems write dialogue, iron-sight, VATS, and weather DOF state?")
	write("4. Can OMV detect native DOF without patching RenderEndOfFrameEffects or ImageSpaceManager::GetDepthTexture?")
	write("5. Does the existing post-ProcessImageSpaceShaders phase necessarily see vanilla DOF already composited?")
	write("")
	write("Known source layout to verify, not assume:")
	write("  ImageSpaceManager +0x08: effect pointer array data; ID 4 is vanilla DOF")
	write("  ImageSpaceEffect vtable +0x18: IsActive; object +0x04: bIsActive candidate")
	write("  ImageSpaceManager +0x2A4..+0x2CD: current/weather DOF parameter candidates")
	write("")
	write("Compatibility boundary:")
	write("  Keep 0x00B97900 RenderEndOfFrameEffects unpatched; Fallout Shader Loader replaces it.")
	write("  Keep 0x00B54090 GetDepthTexture and 0x00875E40 DepthResolve DOF site unpatched.")
	write("  Reuse OMV's existing ProcessImageSpaceShaders wrapper and independent world/first-person depth captures.")

def audit_windows():
	windows = [
		(0x00876136, 12, 18, "Main image-space callsite"),
		(0x00B55AD6, 8, 16, "ProcessImageSpaceShaders call to EOF effects"),
		(0x00B97A01, 18, 24, "EOF effect dispatch loop"),
		(0x00B54090, 4, 18, "GetDepthTexture off-limits entry"),
		(0x00875E40, 8, 20, "DepthResolve DOF off-limits site"),
	]
	for item in windows:
		disasm_window(item[0], item[1], item[2], item[3])

def main():
	print_contract_questions()
	audit_windows()
	audit_references()
	scan_dof_manager_offset_users(0x00B4F000, 0x00B5C000, "ImageSpaceManager core", 30)
	scan_dof_manager_offset_users(0x00B8B000, 0x00BA5000, "image-space effect code", 40)
	audit_known_functions()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_dof_engine_contract_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("")
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
