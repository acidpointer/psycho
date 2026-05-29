# @category Analysis
# @description Audit stale queued-task virtual dispatch contracts and dead-vtable feasibility

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

def decompile_at(addr_int, label, max_len=8000):
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

def print_vtable_slots(base, label, offsets):
	write("")
	write("-" * 70)
	write("Selected vtable slots: %s @ 0x%08x" % (label, base))
	write("-" * 70)
	for off in offsets:
		value = safe_u32(base + off)
		if value is None:
			write("  +0x%02x: <unreadable>" % off)
			continue
		write("  +0x%02x: 0x%08x -> %s" % (off, value, label_for_addr(value)))

def decompile_selected_slots(base, label, offsets):
	seen = []
	for off in offsets:
		value = safe_u32(base + off)
		if value is None:
			continue
		if not is_text_ptr(value):
			write("")
			write("%s +0x%02x points outside text: 0x%08x" % (label, off, value))
			continue
		if value in seen:
			continue
		seen.append(value)
		decompile_at(value, "%s slot +0x%02x" % (label, off), 5500)

def disasm_window(start_int, length, label, highlights, max_inst=160):
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

def print_ascii_dwords(start_int, count, label):
	write("")
	write("-" * 70)
	write("ASCII-adjacent dwords: %s @ 0x%08x" % (label, start_int))
	write("-" * 70)
	for i in range(count):
		addr = start_int + i * 4
		value = safe_u32(addr)
		if value is None:
			write("  0x%08x: <unreadable>" % addr)
			continue
		b0 = value & 0xff
		b1 = (value >> 8) & 0xff
		b2 = (value >> 16) & 0xff
		b3 = (value >> 24) & 0xff
		text = ""
		for b in [b0, b1, b2, b3]:
			if b >= 32 and b < 127:
				text += chr(b)
			else:
				text += "."
		write("  0x%08x: 0x%08x  '%s'" % (addr, value, text))

def audit_vtable(item):
	base = item[0]
	label = item[1]
	offsets = [0x00, 0x04, 0x08, 0x0c, 0x10, 0x14, 0x18, 0x1c, 0x20, 0x24, 0x28, 0x2c]
	print_vtable_slots(base, label, offsets)
	decompile_selected_slots(base, label, [0x00, 0x1c, 0x20])
	find_refs_to(base, label, 50)

def audit_vtables(items):
	for item in items:
		audit_vtable(item)

def main():
	vtables = [
		(0x01016ba4, "queued task default vtable"),
		(0x01016c5c, "queued task type 0x25 vtable"),
		(0x01016ca4, "queued task shared base vtable"),
		(0x01016cec, "queued task type 0x2a vtable"),
		(0x01016d34, "queued task type 0x2b vtable"),
		(0x01016d7c, "queued task player vtable"),
		(0x010c1554, "IOTask base vtable"),
		(0x0101dce4, "NiRefObject/base vtable seen at crash"),
		(0x01097314, "reused object vtable observed before crash")
	]
	write("=" * 70)
	write("STALE TASK VIRTUAL DISPATCH CONTRACT AUDIT")
	write("=" * 70)
	write("")
	write("Goal:")
	write("  Confirm which virtual slots are called on queued-task holders and whether a dead-vtable/no-op strategy is ABI-safe.")
	write("  Crash site loads EAX from [vtable+0x1c] and CALLs it; base NiRefObject +0x1c points into string data.")
	disasm_window(0x00444920, 0x50, "CreateQueuedCharacter slot +0x1c crash call", [0x00444952, 0x00444955, 0x00444957], 80)
	disasm_window(0x00444c20, 0x40, "CreateQueuedCharacter slot +0x20 call", [0x00444c3d], 80)
	disasm_window(0x00c3e2b0, 0x45, "IO task helper slot +0x1c call", [0x00c3e2cd], 80)
	disasm_window(0x00c42670, 0x60, "task-manager holder replace/release call #1", [0x00c4268c], 90)
	disasm_window(0x00c42830, 0x60, "task-manager holder replace/release call #2", [0x00c4284d], 90)
	print_ascii_dwords(0x0101dce4, 28, "NiRefObject/base vtable and following string")
	audit_vtables(vtables)
	decompile_at(0x0043fd40, "default queued task ctor, sets vtable 0x01016ba4", 9000)
	decompile_at(0x004411d0, "queued task shared base ctor, sets vtable 0x01016ca4", 7000)
	decompile_at(0x00441440, "queued task 0x2a ctor, sets vtable 0x01016cec", 7000)
	decompile_at(0x0044dd60, "IOTask_Release final dtor call", 7000)
	decompile_at(0x00c3c590, "IOTask/NiRefObject base ctor", 7000)
	write("")
	write("=" * 70)
	write("END STALE TASK VIRTUAL DISPATCH CONTRACT AUDIT")
	write("=" * 70)

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/stale_task_virtual_dispatch_contract_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
