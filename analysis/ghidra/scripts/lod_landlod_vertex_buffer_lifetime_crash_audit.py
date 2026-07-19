# @category Analysis
# @description Prove the LandLOD vertex-buffer lifetime, locking, and task-thread contract behind the long-run 0x00E8C00D crash.

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

def decompile_once(addr_int, label, max_len=18000):
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

def audit_function(addr_int, label, max_len=18000):
	decompile_once(addr_int, label, max_len)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)

def print_instruction_window(addr_int, label, before_count=20, after_count=28):
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
		write("  [%03d] +0x%03x -> 0x%08x %s" % (index, index * 4, target, name))
		index += 1

def audit_containing_callsite(addr_int, label, max_len=24000):
	decompile_once(addr_int, label, max_len)
	find_and_print_calls_from(addr_int, label)
	print_instruction_window(addr_int, label, 18, 24)

write("LOD LANDLOD VERTEX-BUFFER LIFETIME CRASH AUDIT")
write("Program: %s" % currentProgram.getName())
write("Image base: %s" % currentProgram.getImageBase())
write("")
write("Observed long-run C0000005 after 00:10:29 of high-speed LOD stress:")
write("  EIP=0x00E8C00D EAX=0 EDX=0 ECX=ESI=NiDX9VertexBufferManager")
write("  Return site=0x00E768DA; stack includes NiGeometryBufferData and NiTriShapeData")
write("  Scene evidence includes BSSegmentedTriShape below the LandLOD root")
write("  A zero-ref NiRefObject and corrupt unwind entries make stale ownership plausible")
write("  Final runtime telemetry retained about 323 MB free VAS and reported no allocation failure")

write("")
write("# EXACT FAULTING OPERAND AND SHADER-DECLARATION DATAFLOW")
audit_function(0x00E8BFF0, "Vertex-buffer lock/copy helper containing crash", 18000)
print_instruction_window(0x00E8C00D, "Exact crash instruction", 28, 36)
print_instruction_window(0x00E768D5, "Immediate caller into vertex-buffer helper", 36, 36)
audit_function(0x00E76770, "NiDX9ShaderDeclaration vertex packing owner", 30000)
audit_function(0x00E76700, "NiDX9ShaderDeclaration factory", 16000)
audit_function(0x00E78840, "NiDX9ShaderDeclaration constructor chain", 18000)
audit_function(0x00E78C60, "NiDX9ShaderDeclaration renderer initialization", 22000)
audit_function(0x00E78510, "NiDX9ShaderDeclaration destruction/free owner", 18000)
print_pointer_table(0x010EE70C, 56, "NiDX9ShaderDeclaration vtable")
find_refs_to(0x010EE70C, "NiDX9ShaderDeclaration vtable")

write("")
write("# NIGEOMETRYBUFFERDATA AND NIVBCHIP VALIDITY CONTRACT")
audit_function(0x00E8EEB0, "Vanilla NiGeometryBufferData IsVBChipValid predicate", 14000)
audit_containing_callsite(0x00E6D7A3, "Stewie rendering-inline callsite 1")
audit_containing_callsite(0x00E72003, "Stewie rendering-inline callsite 2")
audit_containing_callsite(0x00E7298E, "Stewie rendering-inline callsite 3")
audit_containing_callsite(0x00E72AD6, "Stewie rendering-inline callsite 4")
audit_containing_callsite(0x00E74CD6, "Stewie rendering-inline callsite 5")
audit_containing_callsite(0x00E7CADC, "Stewie rendering-inline callsite 6")
audit_function(0x00E8F080, "NiGeometryBufferData virtual free", 18000)
print_instruction_window(0x00E8F080, "NiGeometryBufferData virtual free raw entry", 8, 36)
audit_function(0x00E8F0F0, "NiGeometryBufferData destructor body", 26000)
audit_function(0x00E8F170, "NiGeometryBufferData scalar destructor", 14000)
audit_function(0x00E8F200, "Index-buffer create or replacement owner", 22000)
audit_function(0x00E8EEE0, "Index-buffer retirement helper", 16000)
audit_function(0x00E8EF10, "Geometry stream/chip array resize or retirement", 22000)
print_pointer_table(0x010F017C, 2, "NiGeometryBufferData vtable")
find_refs_to(0x010F017C, "NiGeometryBufferData vtable")

write("")
write("# VERTEX-BUFFER MANAGER ALLOCATION, RELEASE, AND LOCK COVERAGE")
audit_function(0x00E8BFA0, "Vertex-buffer manager pre-lock or chip selection", 14000)
audit_function(0x00E8C0D0, "Vertex-buffer unlock helper", 16000)
audit_function(0x00E8C120, "Vertex layout and source analysis helper", 22000)
audit_function(0x00E8C1E0, "Vertex-buffer pack path A", 32000)
audit_function(0x00E8C570, "Vertex-buffer pack path B", 32000)
audit_function(0x00E8C820, "Vertex-buffer pack path C", 36000)
audit_function(0x00E8CD60, "Vertex-buffer manager global teardown entry", 20000)
audit_function(0x00E8CEB0, "Vertex-buffer manager constructor or destructor", 26000)
print_pointer_table(0x010EFE94, 24, "NiDX9VertexBufferManager vtable")
find_refs_to(0x010EFE94, "NiDX9VertexBufferManager vtable")
find_refs_to(0x00E8BFF0, "All direct users of vertex-buffer lock helper")
find_refs_to(0x00E8C0D0, "All direct users of vertex-buffer unlock helper")

write("")
write("# LANDLOD TASK PUBLICATION, RENDER CONSUMPTION, AND RETIREMENT")
audit_function(0x006FBD00, "BGSTerrainChunkLoadTask worker execute", 30000)
audit_function(0x006FC020, "BGSTerrainChunkLoadTask main-thread completion", 30000)
audit_function(0x006FA990, "Terrain chunk completion publication", 18000)
audit_function(0x006FCE00, "Terrain manager worldspace reset and teardown", 28000)
audit_function(0x006FDAA0, "Terrain chunk request and retirement owner", 32000)
audit_function(0x006FEA70, "Terrain post-update morph and scene publication", 32000)
audit_function(0x006FF3F0, "Terrain texture fade finalization", 22000)
audit_function(0x00B791F0, "LandLOD render consumer", 30000)
audit_function(0x00B7DAB0, "LandLOD render consumer caller", 30000)
find_refs_to(0x011AD808, "LandLOD root publication global")

write("")
write("# WORKER VERSUS MAIN-THREAD EXECUTION CONTRACT")
audit_function(0x00C410B0, "BSTaskManagerThread worker loop", 28000)
audit_function(0x00C3FC80, "Generic worker virtual dispatch", 14000)
audit_function(0x00C3DBF0, "Main-thread completed-task processing", 32000)
audit_function(0x00452580, "Exterior and distant cell scheduling owner", 26000)

write("")
write("# REQUIRED DECISION CONTRACT")
write("The output must establish:")
write("  1. Which pointer is null or stale at 0x00E8C00D and its exact source fields.")
write("  2. Whether the crash is before IDirect3DVertexBuffer9::Lock, inside Lock, or after Lock.")
write("  3. Whether a NiVBChip can retain a released D3D vertex buffer and which path must clear it.")
write("  4. Whether vanilla IsVBChipValid proves more than the active Stewie inline replacement.")
write("  5. Which locks cover chip selection, D3D Lock, copy, Unlock, release, and manager teardown.")
write("  6. Whether two IO workers can reach any renderer buffer path concurrently.")
write("  7. Whether terrain completion publishes and retires LandLOD geometry only on the main thread.")
write("  8. Whether gheap reuse can explain the observed object identities or only exposes an engine UAF.")
write("  9. The narrow safe fix point that preserves two workers, LOD visibility, and renderer features.")

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/lod_landlod_vertex_buffer_lifetime_crash_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
