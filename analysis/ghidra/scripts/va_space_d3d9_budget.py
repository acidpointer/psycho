# @category Analysis
# @description Research D3D9 VA budget and game memory layout
#
# We keep crashing in D3D9 but don't understand the VA layout.
# Need to find:
# 1. How does the game initialize D3D9? What VA does it reserve?
# 2. Does D3D9 use VirtualAlloc directly? Or CreateTexture/CreateVertexBuffer?
# 3. What is NiDX9Renderer and how does it manage GPU memory?
# 4. Is there a D3D9 device reset or resource eviction we can call?
# 5. What does the crash function at 0x7AAF0931 (d3d9.dll offset 0x100A0931) do?
# 6. FUN_00e747a8 was on a previous D3D9 crash stack - what is it?

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)
listing = currentProgram.getListing()

output = []

def write(msg):
	output.append(msg)
	print(msg)

def decompile_at(addr_int, label, max_len=6000):
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

def disasm_range(start_int, count=25):
	inst = listing.getInstructionAt(toAddr(start_int))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(start_int - 1))
	for i in range(count):
		if inst is None:
			break
		write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
		inst = inst.getNext()

def find_xrefs_to(addr_int, label, limit=10):
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


write("=" * 70)
write("D3D9 VA BUDGET + GAME MEMORY ARCHITECTURE")
write("=" * 70)

# SECTION 1: FUN_00e747a8 - game code on D3D9 crash stack
# This was in the first D3D9 crash calltrace. What does it do?
write("")
write("# SECTION 1: FUN_00e747a8 - game D3D9 caller")
decompile_at(0x00E747A8, "GameD3D9Caller")
find_calls_from(0x00E747A8, "GameD3D9Caller")

# SECTION 2: NiDX9Renderer - how does it create textures/buffers?
# vtable 0x010EE4BC. Look for CreateTexture/CreateVertexBuffer wrappers
write("")
write("# SECTION 2: NiDX9Renderer texture/buffer creation")
write("# FUN_00e762f0 = vtable[0]")
decompile_at(0x00E762F0, "NiDX9Renderer_vtable0")

# SECTION 3: How does the game create LOD terrain geometry?
# BSSegmentedTriShape was on the crash stack
# NiGeometryBufferData is the D3D9 buffer wrapper
write("")
write("# SECTION 3: NiGeometryBufferData creation")
write("# FUN_00e8f170 = vtable[0] of NiGeometryBufferData (0x010F017C)")
decompile_at(0x00E8F170, "NiGeomBufData_vtable0")

# SECTION 4: How does the game handle D3D9 device lost / resource eviction?
# Is there a "purge D3D9 resources" function?
write("")
write("# SECTION 4: D3D9 resource management functions")
write("# Search for IDirect3DDevice9 pointer")
write("# NiDX9Renderer stores the device. What offset?")
# NiDX9Renderer is at DAT_... let's find the singleton
find_xrefs_to(0x010EE4BC, "NiDX9Renderer_vtable_refs")

# SECTION 5: FUN_00866a90 - HeapCompact stage executor
# This is what runs per stage. Stage 2 = BSA/texture cleanup.
# We need to know EXACTLY what Stage 2 does with D3D9 resources.
write("")
write("# SECTION 5: FUN_00866a90 - HeapCompact stage executor")
decompile_at(0x00866A90, "HeapCompact_StageExec")
find_calls_from(0x00866A90, "HeapCompact_StageExec")

# SECTION 6: The game's OOM handler in original allocator
# FUN_00aa3e40 has a retry loop calling FUN_00866a90
# What does FUN_00866a90 do when called from the allocator?
write("")
write("# SECTION 6: FUN_00878110 / FUN_00878130 - HeapCompact get/set stage")
decompile_at(0x00878110, "HeapCompact_GetStage")
decompile_at(0x00878130, "HeapCompact_SetStage")

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/va_space_d3d9_budget.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
