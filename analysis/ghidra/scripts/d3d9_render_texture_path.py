# @category Analysis
# @description Research D3D9 rendering path - fast travel crash with LandLOD
#
# Goal: Understand D3D9 AV crash during fast travel.
# Stack has: NiGeometryBufferData, NiDX9Renderer, BSSegmentedTriShape, LandLOD
# Game address 0x0046B5D0 on stack. eax=0, edx=0 (NULL deref in D3D9).

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
	entry = func.getEntryPoint().getOffset()
	sz = func.getBody().getNumAddresses()
	write("  Function: %s, Size: %d bytes" % (func.getName(), sz))
	write("  Entry: 0x%08x" % entry)
	result = decomp.decompileFunction(func, 60, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		write(code[:max_len])
	else:
		write("  [decompilation failed]")

def disasm_range(start_int, count=20):
	listing = currentProgram.getListing()
	inst = listing.getInstructionAfter(toAddr(start_int - 1))
	for i in range(count):
		if inst is None:
			break
		write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
		inst = inst.getNext()

def find_xrefs_to(addr_int, label, limit=15):
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
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)

def find_calls_from(addr_int, label):
	addr = toAddr(addr_int)
	func = fm.getFunctionAt(addr)
	if func is None:
		func = fm.getFunctionContaining(addr)
	write("")
	write("--- Calls FROM %s (0x%08x) ---" % (label, addr_int))
	if func is None:
		write("  [function not found]")
		return
	listing = currentProgram.getListing()
	body = func.getBody()
	addr_iter = body.getAddresses(True)
	count = 0
	while addr_iter.hasNext():
		a = addr_iter.next()
		inst = listing.getInstructionAt(a)
		if inst is None:
			continue
		if not inst.getFlowType().isCall():
			continue
		refs_from = inst.getReferencesFrom()
		for r in refs_from:
			target = r.getToAddress().getOffset()
			target_func = fm.getFunctionAt(toAddr(target))
			target_name = target_func.getName() if target_func else "unknown_0x%08x" % target
			write("  CALL 0x%08x -> %s (from 0x%08x)" % (target, target_name, a.getOffset()))
			count += 1
	write("  Total: %d calls" % count)

def read_vtable(vtable_addr, label, count=8):
	write("")
	write("--- %s vtable (0x%08x) ---" % (label, vtable_addr))
	for i in range(count):
		addr = toAddr(vtable_addr + i * 4)
		raw = getInt(addr) & 0xFFFFFFFF
		target_func = fm.getFunctionAt(toAddr(raw))
		fname = target_func.getName() if target_func else "unknown"
		write("  [%d] +0x%02x: 0x%08x -> %s" % (i, i * 4, raw, fname))


write("=" * 70)
write("D3D9 RENDER PATH - FAST TRAVEL CRASH")
write("=" * 70)

# SECTION 1: Game code on crash stack
write("")
write("# SECTION 1: 0x0046B5D0 - game caller into D3D9")
decompile_at(0x0046B5D0, "GameCode_crash_stack")
find_calls_from(0x0046B5D0, "GameCode_crash_stack")

# SECTION 2: NiSourceTexture destructor - D3D9 cleanup
write("")
write("# SECTION 2: NiSourceTexture destructor - D3D9 resource release")
decompile_at(0x00A5FCA0, "NiSourceTexture_dtor")

# SECTION 3: NiDX9SourceTextureData destructor
write("")
write("# SECTION 3: NiDX9SourceTextureData dtor - releases IDirect3DTexture9?")
dx9tex_dtor = getInt(toAddr(0x010ED380)) & 0xFFFFFFFF
decompile_at(dx9tex_dtor, "NiDX9SourceTextureData_dtor")

# SECTION 4: NiGeometryBufferData destructor
write("")
write("# SECTION 4: NiGeometryBufferData dtor - releases vertex/index buffers?")
geobuf_dtor = getInt(toAddr(0x010F0180)) & 0xFFFFFFFF
decompile_at(geobuf_dtor, "NiGeometryBufferData_dtor")

# SECTION 5: Key vtables
write("")
write("# SECTION 5: Key vtables from crash stack")
read_vtable(0x010EE4BC, "NiDX9Renderer")
read_vtable(0x010F017C, "NiGeometryBufferData")
read_vtable(0x010ED37C, "NiDX9SourceTextureData")

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/d3d9_render_texture_path.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
