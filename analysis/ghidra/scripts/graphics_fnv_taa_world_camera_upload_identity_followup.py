# @category Analysis
# @description Prove the FNV world scene-graph camera identity passed to SetCameraData after the TAA jitter hook

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

def print_offset_operands(addr_int, label, offsets):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	write("")
	write("-" * 70)
	write("Field-offset operands in %s" % label)
	write("-" * 70)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = currentProgram.getListing().getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		text = inst.toString().lower()
		matched = False
		for offset in offsets:
			if offset in text:
				matched = True
				break
		if matched:
			write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
			count += 1
	write("  Total: %d matched instructions" % count)

def main():
	write("FNV TAA WORLD CAMERA UPLOAD IDENTITY FOLLOWUP")
	write("")
	write("Questions:")
	write("1. What exact object is held in RenderWorldSceneGraph local [EBP-0x24]?")
	write("2. Does FUN_006629F0 return that object's World NiCamera at SceneGraph +0xAC?")
	write("3. Is the returned camera passed unchanged through FUN_00B6BA20 to SetCameraData?")
	write("4. Does SetCameraData consume camera +0xDC after the OMV entry hook and before world draws?")
	find_refs_to(0x011DEB7C, "Main World SceneGraph pointer")
	decompile_at(0x00559450, "single-pointer slot getter", 6000)
	disassemble_window(0x00559450, 0, 10, "single-pointer slot getter raw body")
	decompile_at(0x0045C670, "Main World SceneGraph getter", 6000)
	disassemble_window(0x0045C670, 0, 12, "Main World SceneGraph getter raw body")
	decompile_at(0x006629F0, "RenderWorld camera/scene getter wrapper", 8000)
	disassemble_window(0x006629F0, 0, 14, "SceneGraph camera getter raw body")
	find_refs_to(0x006629F0, "RenderWorld camera/scene getter wrapper")
	decompile_at(0x00B6BA20, "rendered-texture camera setup", 12000)
	decompile_at(0x004E9BB0, "NiRenderer::SetCameraData", 12000)
	decompile_at(0x0045BBE0, "NiCamera frustum getter", 6000)
	disassemble_window(0x00873F5F, 70, 150, "current-camera writer and local provenance")
	disassemble_window(0x00874180, 100, 140, "world camera upload and following draws")
	print_offset_operands(0x00873200, "Main::RenderWorldSceneGraph", ["0xac", "+ 0xac", "0x11deb7c", "0x011deb7c"])
	print_offset_operands(0x00B6BA20, "rendered-texture camera setup", ["0xdc", "+ 0xdc", "0x100", "+ 0x100"])
	find_and_print_calls_from(0x00B6BA20, "rendered-texture camera setup")
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_taa_world_camera_upload_identity_followup.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("")
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
