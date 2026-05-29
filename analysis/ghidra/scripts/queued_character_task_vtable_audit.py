# @category Analysis
# @description Identify queued-character task classes, vtables, and 80-byte task lifetime around crash vtable 0x01097314

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
ref_mgr = currentProgram.getReferenceManager()
mem = currentProgram.getMemory()
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

def label_for_addr(addr_int):
	func = func_for(addr_int)
	if func is None:
		return "0x%08x ???" % addr_int
	return "0x%08x %s" % (addr_int, name_for_func(func))

def decompile_at(addr_int, label, max_len=11000):
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
			write("  [decompile truncated at %d chars]" % max_len)
	else:
		write("  [decompilation failed]")

def find_refs_to(addr_int, label, limit=80):
	write("")
	write("-" * 70)
	write("References TO 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		faddr = from_func.getEntryPoint().getOffset() if from_func else 0
		fname = from_func.getName() if from_func else "???"
		write("  %s @ 0x%08x (in %s @ 0x%08x)" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname, faddr))
		count += 1
		if count >= limit:
			write("  ... (truncated at %d)" % limit)
			break
	write("  Total printed: %d" % count)

def find_and_print_calls_from(addr_int, label, limit=140):
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
				write("  0x%08x -> %s" % (inst.getAddress().getOffset(), label_for_addr(tgt)))
				count += 1
				if count >= limit:
					write("  ... (truncated at %d)" % limit)
					write("  Total printed: %d" % count)
					return
	write("  Total printed: %d" % count)

def safe_u32(addr_int):
	try:
		addr = toAddr(addr_int)
		if not mem.contains(addr):
			return None
		return getInt(addr) & 0xffffffff
	except:
		return None

def is_text_ptr(value):
	return value >= 0x00400000 and value < 0x00e00000

def print_vtable(base, label, slots=28):
	write("")
	write("-" * 70)
	write("VTable/dword table %s @ 0x%08x" % (label, base))
	write("-" * 70)
	for i in range(slots):
		slot = base + i * 4
		value = safe_u32(slot)
		if value is None:
			write("  [%02d] +0x%02x: <unreadable>" % (i, i * 4))
			continue
		write("  [%02d] +0x%02x: 0x%08x -> %s" % (i, i * 4, value, label_for_addr(value)))

def disasm_window(start_int, length, label, highlights, max_inst=140):
	end_int = start_int + length
	write("")
	write("-" * 70)
	write("Disassembly: %s 0x%08x..0x%08x" % (label, start_int, end_int))
	write("-" * 70)
	inst = listing.getInstructionAt(toAddr(start_int))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(start_int))
	count = 0
	while inst is not None and inst.getAddress().getOffset() < end_int:
		off = inst.getAddress().getOffset()
		mark = "   "
		for item in highlights:
			if off == item:
				mark = "=> "
		write("%s0x%08x: %s" % (mark, off, inst.toString()))
		inst = inst.getNext()
		count += 1
		if count >= max_inst:
			write("  ... (truncated at %d instructions)" % max_inst)
			break
	write("  Instructions printed: %d" % count)

def scan_function_for_constants(addr_int, label, needles, limit=120):
	func = func_for(addr_int)
	write("")
	write("-" * 70)
	write("Instruction scan: %s" % label)
	write("-" * 70)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		text = inst.toString().lower()
		matched = False
		for needle in needles:
			if needle.lower() in text:
				matched = True
		if matched:
			write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
			count += 1
			if count >= limit:
				write("  ... (truncated at %d)" % limit)
				break
	write("  Total matches: %d" % count)

def scan_rdata_for_text_runs(start_int, end_int, label, min_run=3, limit=80):
	write("")
	write("-" * 70)
	write("Potential vtable text-pointer runs: %s 0x%08x..0x%08x" % (label, start_int, end_int))
	write("-" * 70)
	addr = start_int
	run_start = 0
	run_len = 0
	count = 0
	while addr < end_int:
		value = safe_u32(addr)
		if value is not None and is_text_ptr(value):
			if run_len == 0:
				run_start = addr
			run_len += 1
		else:
			if run_len >= min_run:
				write("  run @ 0x%08x len=%d first=0x%08x %s" % (run_start, run_len, safe_u32(run_start), label_for_addr(safe_u32(run_start))))
				count += 1
				if count >= limit:
					write("  ... (truncated at %d)" % limit)
					return
			run_len = 0
		addr += 4
	if run_len >= min_run:
		write("  run @ 0x%08x len=%d first=0x%08x %s" % (run_start, run_len, safe_u32(run_start), label_for_addr(safe_u32(run_start))))
		count += 1
	write("  Total runs: %d" % count)

def audit_constructor(item):
	addr = item[0]
	label = item[1]
	decompile_at(addr, label, 12000)
	find_refs_to(addr, label, 60)
	find_and_print_calls_from(addr, label, 120)
	scan_function_for_constants(addr, label, ["0x01097314", "01097314", "0x0101dce4", "0101dce4", "0x40", "0x48", "0x50", "0x8", "0x1c", "0x20", "0x24"], 120)

def audit_constructors(items):
	for item in items:
		audit_constructor(item)

def main():
	constructors = [
		(0x00440e50, "candidate queued-character task ctor: 0x40 allocation branch type 0x25"),
		(0x00441440, "candidate queued-character task ctor: 0x48 allocation branch type 0x2a"),
		(0x00441920, "candidate queued-character task ctor: 0x40 allocation branch type 0x2b"),
		(0x0043fd40, "candidate queued-character task ctor: 0x40 allocation default branch"),
		(0x00441b20, "candidate queued-character task ctor: player branch 0x48 allocation"),
		(0x004411d0, "shared base ctor used by queued-character task constructors")
	]
	write("=" * 70)
	write("QUEUED CHARACTER TASK VTABLE / 80B LIFETIME AUDIT")
	write("=" * 70)
	write("")
	write("Goal:")
	write("  Identify what vtable 0x01097314 is, whether it belongs to an 80-byte queued task, and which constructor/destructor path owns it.")
	write("  Runtime cell 0x1f7c5f10 is pool #15 class #11 80B, so 0x40/0x48/0x50 constructors are all relevant.")
	disasm_window(0x004448e0, 0x210, "CreateQueuedCharacter task construction and call section", [0x00444957, 0x00444961, 0x00444ab7, 0x00444ad9], 220)
	print_vtable(0x01097314, "suspicious task vtable from TASK_RELEASE log", 32)
	print_vtable(0x0101dce4, "NiRefObject vtable seen in EDX at AV", 24)
	find_refs_to(0x01097314, "suspicious task vtable", 160)
	find_refs_to(0x0101dce4, "NiRefObject vtable", 100)
	scan_rdata_for_text_runs(0x01096f00, 0x01097700, "near 0x01097314", 3, 120)
	audit_constructors(constructors)
	write("")
	write("=" * 70)
	write("END QUEUED CHARACTER TASK VTABLE / 80B LIFETIME AUDIT")
	write("=" * 70)

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/queued_character_task_vtable_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
