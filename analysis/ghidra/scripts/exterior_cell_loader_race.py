# @category Analysis
# @description Research ExteriorCellLoaderTask vs cell unload race

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
write("EXTERIOR CELL LOADER TASK vs CELL UNLOAD RACE ANALYSIS")
write("=" * 70)
write("")
write("Crash: BSTaskManagerThread loads cell -> AddReference -> cell NotLoaded")
write("NiTexturingProperty RefCount=13898 (corrupt zombie)")
write("Callstack: C42DBF->C41257->C3FC94->527CC9->528654->585D9D->")
write("  5881D6->lodfix::AddRef->54832E->905340 (crash)")

# SECTION 1: Crash callstack
write("")
write("#" * 70)
write("# SECTION 1: Crash callstack - cell loading on BSTaskManagerThread")
write("#" * 70)

decompile_at(0x00527CC9, "CellLoader_Outer")
decompile_at(0x00528654, "CellLoader_ProcessCell")
decompile_at(0x00585D9D, "CellLoader_PlaceRefs")
decompile_at(0x005881D6, "CellLoader_AddRef")
decompile_at(0x0054832E, "Form_Process_PostAddRef")
decompile_at(0x00905340, "CRASH_SITE")

# SECTION 2: ExteriorCellLoaderTask
write("")
write("#" * 70)
write("# SECTION 2: ExteriorCellLoaderTask RTTI 0x0102D028")
write("#" * 70)

find_xrefs_to(0x0102D028, "ExteriorCellLoaderTask_RTTI")
read_vtable(0x0102D028, "ExteriorCellLoaderTask_RTTI_area")

# SECTION 3: FindCellToUnload
write("")
write("#" * 70)
write("# SECTION 3: FindCellToUnload 0x00453A80")
write("# Does it cancel pending ExteriorCellLoaderTasks?")
write("#" * 70)

decompile_at(0x00453A80, "FindCellToUnload", 12000)

# SECTION 4: AsyncQueueFlush scope
write("")
write("#" * 70)
write("# SECTION 4: AsyncQueueFlush + inner functions")
write("# Does it drain ExteriorCellLoaderTask or only QueuedTexture?")
write("#" * 70)

decompile_at(0x00C459D0, "AsyncQueueFlush")
decompile_at(0x00C46080, "AsyncFlush_Inner1")
decompile_at(0x00C45A80, "AsyncFlush_Inner2")

# SECTION 5: DeferredCleanupSmall full sequence
write("")
write("#" * 70)
write("# SECTION 5: DeferredCleanupSmall 0x00878250")
write("#" * 70)

decompile_at(0x00878250, "DeferredCleanupSmall", 10000)

# SECTION 6: Cell state transitions
write("")
write("#" * 70)
write("# SECTION 6: Cell unload internals")
write("#" * 70)

decompile_at(0x00585890, "Cell_SetNotLoaded_area")
decompile_at(0x004556D0, "GamePDD_Caller")

# SECTION 7: PreDestruction/PostDestruction
write("")
write("#" * 70)
write("# SECTION 7: PreDestruction + PostDestruction")
write("#" * 70)

decompile_at(0x00878160, "PreDestructionSetup")
decompile_at(0x00878200, "PostDestructionRestore")

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/exterior_cell_loader_race.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
print("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
