# @category Analysis
# @description Close the FNV TAA contract by tracing current-camera projection consumers and post-image-space composition callees

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

def find_callers_in_range(target_addr, range_start, range_end, label):
	write("")
	write("-" * 70)
	write("%s callers from 0x%08x-0x%08x" % (label, range_start, range_end))
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(target_addr))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		src = ref.getFromAddress().getOffset()
		if range_start <= src <= range_end and ref.getReferenceType().isCall():
			func = fm.getFunctionContaining(ref.getFromAddress())
			name = func.getName() if func else "???"
			write("  0x%08x in %s" % (src, name))
			count += 1
	write("  Total: %d callers" % count)

def audit_projection_consumers():
	write("FNV TAA PROJECTION UPLOAD FOLLOWUP")
	write("")
	write("The first audit did not identify the projection upload or a paired jitter boundary.")
	write("This followup traces every remaining pCurrentCamera reader and its callers.")
	decompile_at(0x00B8A790, "Image-space shader constant/vector upload", 18000)
	find_and_print_calls_from(0x00B8A790, "Image-space shader constant/vector upload")
	find_refs_to(0x00B8A790, "Image-space shader constant/vector upload")
	decompile_at(0x00B8B7D0, "Current-camera reader A", 18000)
	decompile_at(0x00B8B8D0, "Current-camera reader B", 18000)
	decompile_at(0x00B8BB70, "Current-camera reader C", 18000)
	decompile_at(0x00BB1A90, "Current-camera reader D", 18000)
	decompile_at(0x00C04C2C, "Unassigned current-camera reader", 18000)
	find_refs_to(0x00B8B7D0, "Current-camera reader A")
	find_refs_to(0x00B8B8D0, "Current-camera reader B")
	find_refs_to(0x00B8BB70, "Current-camera reader C")
	find_refs_to(0x00BB1A90, "Current-camera reader D")
	find_callers_in_range(0x00B54280, 0x00400000, 0x00E00000, "Camera render setup")

def audit_final_composition():
	write("")
	write("FINAL COMPOSITION CALLEES")
	decompile_at(0x00BA9420, "Final camera/render setup", 18000)
	decompile_at(0x00B65660, "Final accumulator path A", 22000)
	decompile_at(0x00B630C0, "Final accumulator path B", 22000)
	decompile_at(0x00B4F510, "Final render-state path", 18000)
	decompile_at(0x00876A00, "Final interface helper", 18000)
	decompile_at(0x00BAD4A0, "Conditional final overlay", 18000)
	decompile_at(0x004A0E90, "Final scene-graph helper", 18000)
	decompile_at(0x004DC020, "Final interface object getter", 18000)
	find_and_print_calls_from(0x00B65660, "Final accumulator path A")
	find_and_print_calls_from(0x00B630C0, "Final accumulator path B")
	find_and_print_calls_from(0x00876A00, "Final interface helper")

def main():
	audit_projection_consumers()
	audit_final_composition()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_taa_projection_upload_followup.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("")
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
