# @category Analysis
# @description Close the concrete NiGeometryGroup allocation, release, failure, and synchronization contract behind the null VB chip crash.

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []
decompiled = {}

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
		if count > 60:
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

def decompile_once(addr_int, label, max_len=22000):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	if func is None:
		decompile_at(addr_int, label, max_len)
		return
	entry = func.getEntryPoint().getOffset()
	if entry in decompiled:
		write("  [already decompiled 0x%08x as %s]" % (entry, decompiled[entry]))
		return
	decompiled[entry] = label
	decompile_at(entry, label, max_len)

def audit_function(addr_int, label, max_len=22000):
	decompile_once(addr_int, label, max_len)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)

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

def read_pointer(addr_int):
	try:
		return memory.getInt(toAddr(addr_int)) & 0xffffffff
	except:
		return 0

def audit_vtable_slot(vtable_addr, slot, class_label, slot_label, max_len=26000):
	target = read_pointer(vtable_addr + slot * 4)
	label = "%s slot %d +0x%02x %s" % (class_label, slot, slot * 4, slot_label)
	write("")
	write("Resolved %s -> 0x%08x" % (label, target))
	if target != 0:
		audit_function(target, label, max_len)

def decompile_reference_owners(addr_int, label, limit=30):
	write("")
	write("=" * 70)
	write("Reference owners for %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	seen = set()
	count = 0
	while refs.hasNext() and count < limit:
		ref = refs.next()
		owner = fm.getFunctionContaining(ref.getFromAddress())
		if owner is not None:
			entry = owner.getEntryPoint().getOffset()
			if entry not in seen:
				seen.add(entry)
				decompile_once(entry, "%s reference owner" % label, 24000)
				find_and_print_calls_from(entry, "%s reference owner" % label)
				count += 1
	write("  Total unique reference owners: %d" % count)

write("LOD VERTEX-BUFFER GEOMETRY-GROUP ALLOCATION FOLLOWUP AUDIT")
write("Program: %s" % currentProgram.getName())
write("Image base: %s" % currentProgram.getImageBase())
write("")
write("Proven input from the prior audit:")
write("  0x00E8C00D faults on MOV ECX,[EAX] with EAX=0")
write("  EAX is the NiVBChip +0x08 IDirect3DVertexBuffer9 pointer")
write("  0x00E8BFA0 first calls GeometryGroup slot +0x1C, then slot +0x18")
write("  It reports success when slot +0x18 returns any non-null NiVBChip")
write("  The caller then fetches that chip and dereferences chip +0x08 without another guard")

write("")
write("# CONCRETE GEOMETRY GROUP VTABLES")
print_pointer_table(0x010F0FD4, 13, "NiStaticGeometryGroup")
find_refs_to(0x010F0FD4, "NiStaticGeometryGroup vtable")
print_pointer_table(0x010F1008, 13, "NiUnsharedGeometryGroup")
find_refs_to(0x010F1008, "NiUnsharedGeometryGroup vtable")
print_pointer_table(0x010F10C4, 13, "NiDynamicGeometryGroup")
find_refs_to(0x010F10C4, "NiDynamicGeometryGroup vtable")
print_pointer_table(0x010F1644, 13, "NiGeometryGroup base")
find_refs_to(0x010F1644, "NiGeometryGroup base vtable")
print_pointer_table(0x010EF718, 16, "NiD3DGeometryGroupManager")
find_refs_to(0x010EF718, "NiD3DGeometryGroupManager vtable")

write("")
write("# SLOT +0X18 CHIP ALLOCATION AND +0X1C RETIREMENT")
audit_vtable_slot(0x010F0FD4, 6, "NiStaticGeometryGroup", "allocate or acquire NiVBChip")
audit_vtable_slot(0x010F0FD4, 7, "NiStaticGeometryGroup", "retire or release NiVBChip")
audit_vtable_slot(0x010F0FD4, 8, "NiStaticGeometryGroup", "post-allocation validity or mode")
audit_vtable_slot(0x010F1008, 6, "NiUnsharedGeometryGroup", "allocate or acquire NiVBChip")
audit_vtable_slot(0x010F1008, 7, "NiUnsharedGeometryGroup", "retire or release NiVBChip")
audit_vtable_slot(0x010F1008, 8, "NiUnsharedGeometryGroup", "post-allocation validity or mode")
audit_vtable_slot(0x010F10C4, 6, "NiDynamicGeometryGroup", "allocate or acquire NiVBChip")
audit_vtable_slot(0x010F10C4, 7, "NiDynamicGeometryGroup", "retire or release NiVBChip")
audit_vtable_slot(0x010F10C4, 8, "NiDynamicGeometryGroup", "post-allocation validity or mode")
audit_vtable_slot(0x010F1644, 6, "NiGeometryGroup base", "allocate or acquire NiVBChip")
audit_vtable_slot(0x010F1644, 7, "NiGeometryGroup base", "retire or release NiVBChip")
audit_vtable_slot(0x010F1644, 8, "NiGeometryGroup base", "post-allocation validity or mode")

write("")
write("# CHIP STORAGE, FETCH, CONSTRUCTION, AND DESTRUCTION")
audit_function(0x00E8BFA0, "Common release-then-allocate wrapper", 18000)
audit_function(0x00E69B40, "Geometry-buffer stream chip getter", 16000)
audit_function(0x00E8F010, "Geometry-buffer stream stride setter", 16000)
audit_function(0x00E947C0, "NiGeometryBufferData constructor", 22000)
audit_function(0x00E95B80, "NiVBBlock or chip destruction helper", 26000)
decompile_reference_owners(0x010F0FD4, "NiStaticGeometryGroup vtable")
decompile_reference_owners(0x010F1008, "NiUnsharedGeometryGroup vtable")
decompile_reference_owners(0x010F10C4, "NiDynamicGeometryGroup vtable")

write("")
write("# DEVICE CREATION, LOSS, RESET, AND RESOURCE RELEASE")
audit_function(0x00E736B0, "Renderer vertex-buffer manager teardown caller", 26000)
audit_function(0x00E72E60, "D3D device creation or reset owner", 36000)
audit_function(0x00E74120, "Renderer geometry prepack owner", 36000)
find_refs_to(0x00E8CD60, "Vertex-buffer manager global teardown")

write("")
write("# REQUIRED DECISION CONTRACT")
write("The output must establish:")
write("  1. Which concrete slot +0x18 implementation produced the crash chip.")
write("  2. Whether CreateVertexBuffer failure returns null or a chip whose +0x08 field is null.")
write("  3. Whether slot +0x1C may clear or destroy a chip concurrently with another packer.")
write("  4. Which critical section or thread-affinity rule protects allocation and retirement.")
write("  5. Whether device-loss/reset paths clear chip +0x08 while geometry remains publishable.")
write("  6. Whether validating chip +0x08 in 0x00E8BFA0 is race-free and makes callers fail safely.")
write("  7. If validation is racy, which full pack operation is the narrow serialization boundary.")
write("  8. The fix that preserves two IO workers, LandLOD visibility, and retry after transient failure.")

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/lod_vertex_buffer_geometry_group_allocation_followup_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
