# @category Analysis
# @description Audit FNV TAA projection refresh boundaries and world render-target alpha consumers

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

def disassemble_window(center_int, before_count, after_count, label):
	listing = currentProgram.getListing()
	center = toAddr(center_int)
	inst = listing.getInstructionContaining(center)
	write("")
	write("-" * 70)
	write("Disassembly %s around 0x%08x" % (label, center_int))
	write("-" * 70)
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
		marker = " <<" if current.getAddress().getOffset() == inst.getAddress().getOffset() else ""
		write("  0x%08x: %-58s%s" % (current.getAddress().getOffset(), current.toString(), marker))
		current = current.getNext()
		remaining -= 1

def audit_projection_contract():
	write("PROJECTION REFRESH CONTRACT")
	write("")
	write("Goal: prove whether the persistent world NiCamera frustum is consumed after the OMV entry hook and before all world draws, and identify every later camera replacement before first-person/UI.")
	decompile_at(0x004E9BB0, "NiRenderer::SetCameraData candidate", 22000)
	find_refs_to(0x004E9BB0, "NiRenderer::SetCameraData candidate")
	find_and_print_calls_from(0x004E9BB0, "NiRenderer::SetCameraData candidate")
	decompile_at(0x00B5E870, "BSShaderManager current-camera writer", 22000)
	find_refs_to(0x00B5E870, "BSShaderManager current-camera writer")
	find_and_print_calls_from(0x00B5E870, "BSShaderManager current-camera writer")
	decompile_at(0x00710AB0, "NiCamera FOV/frustum setup candidate", 18000)
	find_refs_to(0x00710AB0, "NiCamera FOV/frustum setup candidate")
	find_refs_to(0x011F917C, "BSShaderManager pCurrentCamera")
	decompile_at(0x00870A00, "Main world render path A", 26000)
	decompile_at(0x00870BD0, "Main world render path B", 30000)
	disassemble_window(0x00870AE8, 30, 55, "world callsite A")
	disassemble_window(0x00870E18, 30, 70, "world callsite B")
	disassemble_window(0x00870F74, 35, 45, "first-person call after world path B")

def audit_alpha_contract():
	write("")
	write("WORLD COLOR/ALPHA CONSUMER CONTRACT")
	write("")
	write("Goal: identify engine stages between world completion and image-space/UI that preserve, replace, blend with, or sample the current world render target. Shader channel semantics still require package disassembly or runtime telemetry.")
	find_refs_to(0x011F9438, "BSShaderManager current render target")
	decompile_at(0x00875110, "Main::RenderFirstPerson", 30000)
	find_and_print_calls_from(0x00875110, "Main::RenderFirstPerson")
	decompile_at(0x00875FD0, "Main image-space owner", 26000)
	find_and_print_calls_from(0x00875FD0, "Main image-space owner")
	decompile_at(0x00B55AC0, "ImageSpaceManager::ProcessImageSpaceShaders", 26000)
	find_and_print_calls_from(0x00B55AC0, "ImageSpaceManager::ProcessImageSpaceShaders")
	disassemble_window(0x00876136, 30, 70, "ProcessImageSpaceShaders callsite")
	decompile_at(0x00BA9420, "final camera/render setup", 18000)
	find_and_print_calls_from(0x00BA9420, "final camera/render setup")

def main():
	write("FNV TAA PROJECTION/ALPHA PERFORMANCE CONTRACT AUDIT")
	write("")
	write("Questions:")
	write("1. Does RenderWorldSceneGraph rebuild all world projection state from the persistent NiCamera after its entry hook?")
	write("2. Which function replaces/restores camera projection before first-person and UI?")
	write("3. Which engine stages consume or preserve world-target alpha after world rendering?")
	write("4. Is there a statically proven point where an MRT TAA resolve can preserve engine alpha without changing composition?")
	audit_projection_contract()
	audit_alpha_contract()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_taa_projection_alpha_perf_contract_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("")
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
