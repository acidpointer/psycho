# @category Analysis
# @description Audit FNV projection jitter ownership, temporal invalidation, and UI composition boundaries for OMV TAA

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

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

def print_header():
	write("FNV TAA PROJECTION AND UI CONTRACT AUDIT")
	write("")
	write("Questions:")
	write("1. Which exact function builds or uploads the world projection matrix each frame?")
	write("2. Where can a subpixel X/Y projection jitter be applied before every world draw and restored before first-person/UI draws?")
	write("3. Do world depth, first-person depth, and image-space color observe the same jittered projection in a frame?")
	write("4. Which calls after ProcessImageSpaceShaders draw HUD, menus, subtitles, or other interface content?")
	write("5. Which engine flags identify loading screens, camera mode changes, teleports, and other history-invalidating cuts?")
	write("6. Is there a hook site that can pair jitter apply/restore without patching Fallout Shader Loader ownership?")

def audit_projection():
	write("")
	write("PROJECTION CONSTRUCTION AND CAMERA WRITERS")
	decompile_at(0x00B5A220, "Current-camera near/far projection consumer", 18000)
	find_and_print_calls_from(0x00B5A220, "Current-camera near/far projection consumer")
	decompile_at(0x00BD66C0, "Current-camera frustum/projection consumer", 18000)
	find_and_print_calls_from(0x00BD66C0, "Current-camera frustum/projection consumer")
	decompile_at(0x00B54280, "Camera writer and render setup", 20000)
	find_and_print_calls_from(0x00B54280, "Camera writer and render setup")
	decompile_at(0x00B54630, "Camera render teardown", 16000)
	decompile_at(0x00B5E870, "Alternate camera render setup", 20000)
	decompile_at(0x00B6BA20, "Rendered-texture camera setup", 16000)
	decompile_at(0x00B6C0D0, "Rendered-texture camera restore", 16000)
	find_refs_to(0x011F917C, "BSShaderManager::pCurrentCamera")

def audit_world_first_person_pairing():
	write("")
	write("WORLD/FIRST-PERSON/IMAGE-SPACE PAIRING")
	decompile_at(0x00870A00, "Main render path A", 24000)
	find_and_print_calls_from(0x00870A00, "Main render path A")
	decompile_at(0x00870BD0, "Main render path B", 30000)
	find_and_print_calls_from(0x00870BD0, "Main render path B")
	decompile_at(0x00873200, "Main::RenderWorldSceneGraph", 24000)
	find_and_print_calls_from(0x00873200, "Main::RenderWorldSceneGraph")
	decompile_at(0x00874C10, "RenderFirstPerson setup", 24000)
	decompile_at(0x00875110, "Main::RenderFirstPerson", 30000)
	find_and_print_calls_from(0x00875110, "Main::RenderFirstPerson")
	decompile_at(0x00875FD0, "Image-space caller", 20000)
	find_and_print_calls_from(0x00875FD0, "Image-space caller")

def audit_ui_and_cut_boundaries():
	write("")
	write("POST-IMAGE-SPACE UI AND HISTORY INVALIDATION")
	decompile_at(0x008707C0, "Image-space caller owner A", 24000)
	find_and_print_calls_from(0x008707C0, "Image-space caller owner A")
	decompile_at(0x008761E0, "Post-image-space path A", 22000)
	find_and_print_calls_from(0x008761E0, "Post-image-space path A")
	decompile_at(0x00876830, "Alternate post-image-space path", 22000)
	find_and_print_calls_from(0x00876830, "Alternate post-image-space path")
	decompile_at(0x00876850, "Final composition path", 26000)
	find_and_print_calls_from(0x00876850, "Final composition path")
	decompile_at(0x00876A20, "Post-image-space interface candidate", 24000)
	find_and_print_calls_from(0x00876A20, "Post-image-space interface candidate")
	decompile_at(0x00872940, "Alternate render owner", 26000)
	find_and_print_calls_from(0x00872940, "Alternate render owner")
	find_refs_to(0x00B55AC0, "ImageSpaceManager::ProcessImageSpaceShaders")
	find_refs_to(0x00B97900, "ImageSpaceManager::RenderEndOfFrameEffects")

def main():
	print_header()
	audit_projection()
	audit_world_first_person_pairing()
	audit_ui_and_cut_boundaries()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_taa_projection_ui_contract_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("")
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
