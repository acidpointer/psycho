# @category Analysis
# @description Proves the null-owner dataflow and missing serialization contract in the two-worker ExteriorCellLoaderTask stress crash.

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
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
	inst_iter = listing.getInstructions(body, True)
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

def print_instruction_window(addr_int, label, before_count=16, after_count=24):
	write("")
	write("=" * 70)
	write("Instruction window %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	center = listing.getInstructionContaining(toAddr(addr_int))
	if center is None:
		center = listing.getInstructionAt(toAddr(addr_int))
	if center is None:
		write("  [instruction not found]")
		return
	items = []
	current = center
	count = 0
	while current is not None and count < before_count:
		current = listing.getInstructionBefore(current.getAddress())
		if current is not None:
			items.insert(0, current)
		count += 1
	items.append(center)
	current = center
	count = 0
	while current is not None and count < after_count:
		current = listing.getInstructionAfter(current.getAddress())
		if current is not None:
			items.append(current)
		count += 1
	for inst in items:
		marker = ">>" if inst.getAddress().getOffset() == center.getAddress().getOffset() else "  "
		write("%s 0x%08x  %s" % (marker, inst.getAddress().getOffset(), inst.toString()))

def print_pointer_table(addr_int, count, label):
	write("")
	write("=" * 70)
	write("Pointer table %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	index = 0
	while index < count:
		entry_addr = toAddr(addr_int + index * 4)
		try:
			target = memory.getInt(entry_addr) & 0xffffffff
		except:
			target = 0
		func = fm.getFunctionAt(toAddr(target))
		name = func.getName() if func else "???"
		write("  [%02d] +0x%02x -> 0x%08x %s" % (index, index * 4, target, name))
		index += 1

def audit_function(addr_int, label, max_len=8000):
	decompile_at(addr_int, label, max_len)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)

write("LOD EXTERIOR CELL MULTI-WORKER NULL-OWNER CRASH AUDIT")
write("Program: %s" % currentProgram.getName())
write("Image base: %s" % currentProgram.getImageBase())
write("")
write("Observed C0000005 chain:")
write("  0x00C42DBF -> 0x00C41257 -> 0x00C3FC94 -> 0x00527CC9")
write("  -> 0x00528654 -> 0x00585D2B -> 0x005507C2 -> 0x004686FF")
write("  -> 0x005516CF -> 0x0044DDC0")
write("Crash registers: ECX=0 EAX=0 EDX=0 on BSTaskManagerThread")
write("Runtime object evidence: ExteriorCellLoaderTask, unloaded exterior cell, NavMesh, TESObjectTREE")

write("")
write("# EXACT NULL ORIGIN AND CALL-SITE DATAFLOW")
audit_function(0x0044DDC0, "Null dereference leaf")
audit_function(0x005516C0, "Immediate null-producing caller")
print_instruction_window(0x005516CA, "Call into null dereference leaf", 12, 18)
print_instruction_window(0x004686FA, "TESDataHandler caller passes owner to 0x005516C0", 28, 28)
print_instruction_window(0x005507C2, "Cell form-processing return site", 30, 30)
print_instruction_window(0x00585D2B, "Exterior cell placement return site", 30, 30)

write("")
write("# GLOBAL CURRENT-CELL OWNER AND FORM-PROCESSING CONTRACT")
find_refs_to(0x011C3F34, "Global current cell/form owner")
find_refs_to(0x011C3F30, "Adjacent global load owner")
find_refs_to(0x011C3F2C, "TESDataHandler/global form owner")
audit_function(0x00585B30, "Exterior cell form placement and current-owner publication", 18000)
audit_function(0x00550500, "Per-form insertion owner", 14000)
audit_function(0x00467BD0, "TESDataHandler form construction owner", 24000)
audit_function(0x00551420, "Existing cell load-state predicate")
audit_function(0x00551440, "Cell load-state publication")
audit_function(0x005508B0, "Cell reset/unload owner", 12000)
find_refs_to(0x011CA60C, "Native cell-reference critical section")

write("")
write("# EXTERIOR CELL LOADER TASK IDENTITY, LIFETIME, AND SUBMISSION")
print_pointer_table(0x0102D028, 12, "ExteriorCellLoaderTask vtable")
find_refs_to(0x0102D028, "ExteriorCellLoaderTask vtable")
audit_function(0x00527C00, "ExteriorCellLoaderTask constructor")
audit_function(0x00527C40, "ExteriorCellLoaderTask scalar destructor")
audit_function(0x00527C70, "ExteriorCellLoaderTask destructor body")
audit_function(0x00527CB0, "ExteriorCellLoaderTask worker execute entry")
audit_function(0x005283C0, "ExteriorCellLoaderTask producer and submission", 14000)
audit_function(0x005285C0, "Exterior cell load payload producer", 12000)
audit_function(0x00528620, "ExteriorCellLoaderTask payload processor", 14000)
audit_function(0x00528CB0, "ExteriorCellLoaderTask intrusive holder assignment")

write("")
write("# TWO-WORKER OVERLAP AND NATIVE SERIALIZATION BOUNDARIES")
audit_function(0x00C3D910, "IOManager construction and worker-count owner", 14000)
print_instruction_window(0x00C3DA7A, "Vanilla worker-count instruction", 28, 28)
audit_function(0x00C3FC80, "Generic task virtual dispatch")
audit_function(0x00C41257, "BSTaskManagerThread dequeue/dispatch loop", 20000)
audit_function(0x00C42DA0, "BSTaskManagerThread entry")
audit_function(0x00877700, "Cell-transition IO wait boundary", 14000)
audit_function(0x00452580, "Exterior cell demand and task scheduling owner", 16000)
audit_function(0x00462290, "Cell destruction owner", 14000)
audit_function(0x00585E00, "Cell detach/unload owner", 12000)

write("")
write("# REQUIRED DECISION CONTRACT")
write("The output must establish:")
write("  1. Which exact pointer is zero at 0x005516CA and where it was sourced.")
write("  2. Whether 0x011C3F34 or another shared owner is process-global rather than task-local/TLS.")
write("  3. Whether two ExteriorCellLoaderTask execute bodies may overlap with two generic workers.")
write("  4. Whether vanilla's single worker is the only serialization around the shared form-load owner.")
write("  5. Whether serializing only 0x00527CB0 preserves parallel LOD tasks and all task lifetimes.")

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/lod_exterior_cell_multiworker_null_owner_crash_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
