# @category Analysis
# @description Audit Radio::GetNearbyStations output ownership and safe optimization surfaces

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
ref_mgr = currentProgram.getReferenceManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def write(msg):
	output.append(msg)
	print(msg)

def func_for(addr_int):
	addr = toAddr(addr_int)
	func = fm.getFunctionAt(addr)
	if func is None:
		func = fm.getFunctionContaining(addr)
	return func

def name_for_func(func):
	if func is None:
		return "???"
	return "%s @ 0x%08x" % (func.getName(), func.getEntryPoint().getOffset())

def decompile_at(addr_int, label, max_len=16000):
	addr = toAddr(addr_int)
	func = func_for(addr_int)
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
		if len(code) > max_len:
			write("  [decompile truncated at %d chars, total %d]" % (max_len, len(code)))
	else:
		write("  [decompilation failed]")

def find_refs_to(addr_int, label, limit=220):
	write("")
	write("-" * 70)
	write("References TO 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		write("  %s @ 0x%08x (in %s)" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), name_for_func(from_func)))
		count += 1
		if count >= limit:
			write("  ... (truncated at %d)" % limit)
			break
	write("  Total printed: %d" % count)

def find_and_print_calls_from(addr_int, label, limit=260):
	func = func_for(addr_int)
	write("")
	write("-" * 70)
	write("Calls FROM %s (0x%08x)" % (label, addr_int))
	write("-" * 70)
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
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, name_for_func(func_for(tgt))))
				count += 1
				if count >= limit:
					write("  ... (truncated at %d)" % limit)
					write("  Total printed: %d" % count)
					return
	write("  Total printed: %d" % count)

def disasm_window(center_int, before_count, after_count, label):
	write("")
	write("-" * 70)
	write("Disassembly: %s around 0x%08x" % (label, center_int))
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
		off = inst.getAddress().getOffset()
		marker = " << target" if off == center_int else ""
		write("  0x%08x: %-58s%s" % (off, inst.toString(), marker))
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				write("      call -> 0x%08x %s" % (tgt, name_for_func(func_for(tgt))))
		inst = inst.getNext()
		idx += 1

def scan_function_text(addr_int, terms, label, limit=260):
	func = func_for(addr_int)
	write("")
	write("=" * 70)
	write("Instruction text scan: %s" % label)
	write("=" * 70)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		text = inst.toString().lower()
		hit = None
		for term in terms:
			if term in text:
				hit = term
				break
		if hit is not None:
			write("  hit=%-12s 0x%08x %s" % (hit, inst.getAddress().getOffset(), inst.toString()))
			count += 1
			if count >= limit:
				write("  ... (truncated at %d)" % limit)
				break
	write("  Total printed: %d" % count)

def audit_decompiles():
	targets = [
		(0x004ff1a0, "Radio::GetNearbyStations / nearby signal scan", 36000),
		(0x00833d00, "Periodic radio availability consumer", 30000),
		(0x00832240, "Radio::SetStation / active station selection", 22000),
		(0x004ff980, "Parallel float metadata list append helper", 14000),
		(0x005ae3d0, "tList prepend/value append helper", 14000),
		(0x00470440, "tList node allocation helper", 14000),
		(0x00470470, "tList RemoveAll helper", 14000),
		(0x0046ffb0, "tList destructor wrapper", 8000),
		(0x005f65d0, "tList Contains helper", 8000),
		(0x006d4d20, "Connected-interior/path membership check", 24000),
		(0x006d4eb0, "Exterior distance/range check", 20000),
		(0x006dcd70, "Coordinate/context builder used by scan", 16000),
		(0x006f48b0, "CMemoryDC/list constructor used before geometry check", 16000),
		(0x004ff7e0, "Coordinate/context cleanup helper", 16000),
		(0x0044ddc0, "Geometry result count helper", 12000),
		(0x006a7af0, "Geometry result entry accessor", 12000),
		(0x0056b140, "Radio exterior position ref getter", 12000),
		(0x0056b190, "Radio radius getter", 12000),
		(0x0056b1d0, "Radio fade/static distance getter", 12000),
		(0x0056b210, "Radio range mode getter", 12000),
		(0x00575d70, "Worldspace/exterior resolver", 16000),
		(0x00832830, "RadioEntry lookup by activator/base", 16000),
		(0x00832cb0, "RadioEntry create/find helper", 16000),
	]
	for item in targets:
		decompile_at(item[0], item[1], item[2])
		find_and_print_calls_from(item[0], item[1], 220)

def audit_references():
	targets = [
		(0x004ff1a0, "Radio::GetNearbyStations callers"),
		(0x004ff980, "float metadata append helper callers"),
		(0x005ae3d0, "tList append helper callers"),
		(0x00470470, "tList RemoveAll helper callers"),
		(0x00470440, "tList node allocation helper callers"),
		(0x006d4d20, "connected-interior/path check callers"),
		(0x006d4eb0, "distance/range check callers"),
		(0x011c8264, "global talking-activator/radio station scan list"),
		(0x011dd554, "global registered radio entry list"),
		(0x011dd59c, "global found radio station list"),
		(0x011dd42c, "current radio entry global"),
		(0x011dd430, "lost radio entry global"),
		(0x011dd434, "radio enabled global"),
		(0x011dd436, "radio disabled/loading gate global"),
		(0x011dd437, "radio transition gate global"),
		(0x011dea3c, "player/current ref global used by scan"),
		(0x011a179c, "radio discovery popup suppression global"),
	]
	for item in targets:
		find_refs_to(item[0], item[1], 260)

def audit_hot_windows():
	windows = [
		(0x00833d86, 22, 28, "periodic worker call to Radio::GetNearbyStations"),
		(0x00833ec4, 18, 28, "periodic worker found-station list update"),
		(0x008322bf, 18, 30, "SetStation cold path call to Radio::GetNearbyStations"),
		(0x004ff1a0, 20, 34, "Radio::GetNearbyStations function entry"),
		(0x004ff234, 18, 28, "scan-list empty/end check"),
		(0x004ff27a, 24, 42, "radio station mode dispatch"),
		(0x004ff397, 24, 30, "mode 0 exterior distance call"),
		(0x004ff4c6, 28, 34, "mode 2 connected-interior check"),
		(0x004ff645, 32, 38, "mode 3 connected-interior check"),
		(0x004ff50d, 18, 34, "mode 2 geometry result count"),
		(0x004ff536, 18, 32, "mode 2 geometry result iteration"),
		(0x004ff6dc, 18, 34, "mode 3 geometry result count"),
		(0x004ff71d, 18, 32, "mode 3 geometry result iteration"),
		(0x004ff78e, 20, 28, "station output append"),
		(0x004ff7a0, 18, 28, "parallel distance/strength output append"),
		(0x004ff9d3, 18, 28, "float metadata helper node allocation"),
	]
	for item in windows:
		disasm_window(item[0], item[1], item[2], item[3])

def audit_instruction_scans():
	radio_terms = ["011dd", "011de", "011c8264", "011a179c", "4ff1a0", "5ae3d0", "470470"]
	hot_terms = ["6d4d20", "6d4eb0", "6dcd70", "6f48b0", "4ff7e0", "44ddc0", "6a7af0"]
	scan_function_text(0x004ff1a0, radio_terms, "Radio::GetNearbyStations radio globals/list scan", 360)
	scan_function_text(0x004ff1a0, hot_terms, "Radio::GetNearbyStations expensive helper scan", 360)
	scan_function_text(0x00833d00, radio_terms, "periodic radio consumer globals/list scan", 360)
	scan_function_text(0x00832240, radio_terms, "SetStation globals/list scan", 260)

def main():
	write("Radio signal scan fix surface audit")
	write("")
	write("Purpose:")
	write("  Runtime telemetry isolated Capital Wasteland stutter to 0x004FF1A0.")
	write("  Stewie Tweaks names this function Radio::GetNearbyStations.")
	write("  This audit focuses on whether a cache/throttle can safely replay its")
	write("  output lists, which globals must invalidate the cache, and which")
	write("  geometry helpers are the likely 40-50 ms cost source.")
	audit_decompiles()
	audit_references()
	audit_hot_windows()
	audit_instruction_scans()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/radio_signal_scan_fix_surface_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
