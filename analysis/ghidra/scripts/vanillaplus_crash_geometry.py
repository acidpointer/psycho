# @category Analysis
# @description Research VanillaPlusSkin crash on BSTaskManagerThread

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
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
	write("  Function: %s, Size: %d bytes" % (func.getName(), func.getBody().getNumAddresses()))
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		write(code[:max_len])
	else:
		write("  [decompilation failed]")

def find_xrefs_to(addr_int, label, limit=30):
	addr = toAddr(addr_int)
	refs = getReferencesTo(addr)
	write("")
	write("--- XRefs to %s (0x%08x) ---" % (label, addr_int))
	count = 0
	for ref in refs:
		from_addr = ref.getFromAddress()
		func = fm.getFunctionContaining(from_addr)
		fname = func.getName() if func else "???"
		write("  %s @ 0x%s (in %s)" % (ref.getReferenceType(), from_addr, fname))
		count += 1
		if count >= limit:
			write("  ... (truncated at %d)" % limit)
			break
	write("  Total: %d refs" % count)

def read_vtable(vtable_addr_int, label, num_entries=12):
	write("")
	write("--- %s vtable @ 0x%08x ---" % (label, vtable_addr_int))
	mem = currentProgram.getMemory()
	for i in range(num_entries):
		addr = toAddr(vtable_addr_int + i * 4)
		buf = bytearray(4)
		mem.getBytes(addr, buf)
		val = (buf[3] << 24) | (buf[2] << 16) | (buf[1] << 8) | buf[0]
		func = fm.getFunctionAt(toAddr(val))
		fname = func.getName() if func else "???"
		write("  [%d] +0x%02x: 0x%08x (%s)" % (i, i*4, val, fname))

write("=" * 70)
write("VANILLAPLUS SKIN CRASH - GEOMETRY ON BSTASKMANAGERTHREAD")
write("=" * 70)
write("")
write("VanillaPlusSkin callstack:")
write("  FalloutNV 0x00BE08DB -> VanillaPlusSkin::SetupGeometryVirtEx<0>")
write("  -> SubsurfaceScattering::AddCurvatureDataToGeometry")
write("  -> ProcessTriangleForCurvature -> TransformCurvatureToVertexSpace")
write("  ACCESS_VIOLATION, edx=0x6B03F000 (page-aligned)")

# SECTION 1: Game function calling SetupGeometry
write("")
write("#" * 70)
write("# SECTION 1: FUN_00BE08DB caller of SetupGeometry")
write("#" * 70)

decompile_at(0x00BE08DB, "SetupGeometry_caller", 10000)
find_xrefs_to(0x00BE08DB, "SetupGeometry_return_addr")

# SECTION 2: How geometry setup reaches BSTaskManagerThread
write("")
write("#" * 70)
write("# SECTION 2: QueuedModel and QueuedCharacter vtables")
write("#" * 70)

read_vtable(0x01016CCC, "QueuedModel_RTTI_area")
read_vtable(0x01016CEC, "QueuedCharacter_RTTI_area")

# SECTION 3: NiTriShapeData lifecycle
write("")
write("#" * 70)
write("# SECTION 3: NiTriShapeData RTTI 0x0109DAC4")
write("#" * 70)

find_xrefs_to(0x0109DAC4, "NiTriShapeData_RTTI", 20)
decompile_at(0x00A68840, "NiTriShapeData_dtor_approx")
decompile_at(0x0040FA60, "NiObject_delete_helper")

# SECTION 4: Cell unload geometry invalidation
write("")
write("#" * 70)
write("# SECTION 4: ProcessDeferredDestruction and PDD queues")
write("#" * 70)

decompile_at(0x00868D70, "ProcessDeferredDestruction")

# SECTION 5: BSShaderPPLightingProperty SetupGeometry
write("")
write("#" * 70)
write("# SECTION 5: BSShaderPPLighting SetupGeometry original")
write("#" * 70)

decompile_at(0x00BE0800, "BSShaderPPLighting_SetupGeometry_approx", 10000)

# SECTION 6: NiTriShapeData memory layout
write("")
write("#" * 70)
write("# SECTION 6: NiTriShapeData vertex buffer allocation")
write("#" * 70)

decompile_at(0x00A684C0, "NiTriShapeData_Create_approx")
decompile_at(0x00A68500, "NiTriShapeData_Init_approx")
decompile_at(0x00A61A00, "NiGeometryData_AllocVertices_approx")

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/vanillaplus_crash_geometry.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
print("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
