# @category Analysis
# @description AUDIT: Thread safety of all hooked functions.
# For each hook target, find what threads call it.
# Game threads: Main, AI Linear Task x4, BSTaskManager, Render, Audio
# Critical: if a hooked function is called from multiple threads,
# our hook must be thread-safe.

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

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
	write("  Function: %s, Size: %d bytes" % (func.getName(), func.getBody().getNumAddresses()))
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		write(code[:max_len])
	else:
		write("  [decompilation failed]")

def trace_thread_entry(addr_int, label):
	"""Check if a function is reachable from known thread entry points."""
	write("")
	write("--- Thread reachability for %s (0x%08x) ---" % (label, addr_int))

write("=" * 70)
write("AUDIT: THREAD SAFETY OF HOOKED FUNCTIONS")
write("=" * 70)

# Known thread entry points
write("")
write("### Known game thread entries:")
write("  Main thread: WinMain -> main loop (FUN_0086a850)")
write("  AI Linear Task: 0x00AA64E0 -> FUN_008c7764")
write("  BSTaskManager: 0x00C42DA0 -> FUN_00c410b0")
write("  Render: via Direct3D Present")
write("  Audio: BSAudioManager thread")

# Section 1: GameHeap hooks — called from ALL threads
write("")
write("#" * 70)
write("# SECTION 1: GameHeap alloc/free — multi-thread hot path")
write("# These are called from EVERY thread. Our hooks MUST be thread-safe.")
write("#" * 70)

write("")
write("GameHeap::Allocate (0x00AA3E40):")
write("  Our hook: Gheap::alloc -> mi_malloc_aligned + pressure check")
write("  Thread safety: mi_malloc is thread-safe. Pressure check uses")
write("  thread-local counter + atomic requested flag.")
write("  RISK: PressureRelief::check() writes HEAP_COMPACT_TRIGGER from any thread")

write("")
write("GameHeap::Free (0x00AA4060):")
write("  Our hook: Gheap::free -> quarantine_free (thread-local) or trampoline")
write("  Thread safety: quarantine is thread-local. mi_is_in_heap_region is safe.")
write("  RISK: original trampoline calls into game code — thread-safe?")

# Section 2: CRT hooks — called from ALL threads including NVSE plugins
write("")
write("#" * 70)
write("# SECTION 2: CRT malloc/free — NVSE plugins use these")
write("#" * 70)

write("CRT hooks route to mi_malloc/mi_free (thread-safe).")
write("CRT realloc has a cross-heap copy path — is it safe?")
decompile_at(0x00AA4150, "GameHeap_Realloc_1 (trampoline target)")
decompile_at(0x00AA4200, "GameHeap_Realloc_2 (trampoline target)")

# Section 3: ScrapHeap hooks — per-thread heaps
write("")
write("#" * 70)
write("# SECTION 3: ScrapHeap hooks — supposed to be per-thread")
write("# Game uses TLS for scrap heap. Our hooks replace with Runtime.")
write("# Is Runtime::alloc/free thread-safe?")
write("#" * 70)

write("")
write("ScrapHeap::GetThreadLocal (0x00AA42E0):")
write("  Our hook returns a dummy SheapStruct per thread (thread_local)")

write("")
write("ScrapHeap::Alloc (0x00AA54A0):")
write("  Our hook: Runtime::alloc -> ClashMap lookup + Heap::alloc")
write("  ClashMap is concurrent. But Heap::alloc uses Mutex internally.")
decompile_at(0x00AA54A0, "ScrapHeap_Alloc_Original")

write("")
write("ScrapHeap::Free (0x00AA5610):")
write("  Our hook: Runtime::free -> ClashMap lookup + Region free")
decompile_at(0x00AA5610, "ScrapHeap_Free_Original")

# Section 4: Main loop hook — MUST be main thread only
write("")
write("#" * 70)
write("# SECTION 4: Main loop hook (0x008705D0) — called from where?")
write("#" * 70)

decompile_at(0x008705D0, "MainLoop_Maintenance (our hook target)")

# Verify it's only called from main loop
addr = toAddr(0x008705D0)
refs = getReferencesTo(addr)
write("")
write("Callers of 0x008705D0:")
for ref in refs:
	from_addr = ref.getFromAddress()
	func = fm.getFunctionContaining(from_addr)
	fname = func.getName() if func else "???"
	write("  %s @ 0x%s in %s" % (ref.getReferenceType(), from_addr, fname))

# Section 5: Per-frame queue drain hook — called from where?
write("")
write("#" * 70)
write("# SECTION 5: Per-frame queue drain (0x00868850) — callers")
write("#" * 70)

addr = toAddr(0x00868850)
refs = getReferencesTo(addr)
write("")
write("Callers of 0x00868850:")
for ref in refs:
	from_addr = ref.getFromAddress()
	func = fm.getFunctionContaining(from_addr)
	fname = func.getName() if func else "???"
	write("  %s @ 0x%s in %s" % (ref.getReferenceType(), from_addr, fname))

# Section 6: CellTransitionHandler hook — callers
write("")
write("#" * 70)
write("# SECTION 6: CellTransitionHandler (0x008774A0) — callers")
write("#" * 70)

addr = toAddr(0x008774A0)
refs = getReferencesTo(addr)
write("")
write("Callers of 0x008774A0:")
for ref in refs:
	from_addr = ref.getFromAddress()
	func = fm.getFunctionContaining(from_addr)
	fname = func.getName() if func else "???"
	write("  %s @ 0x%s in %s" % (ref.getReferenceType(), from_addr, fname))

decompile_at(0x008774A0, "CellTransitionHandler (our hook target)")

# Section 7: AI thread dispatch — what exactly does it call?
write("")
write("#" * 70)
write("# SECTION 7: AI thread main loop — what allocations does it do?")
write("#" * 70)

decompile_at(0x008C7764, "AI_ThreadDispatch")
decompile_at(0x00886580, "AI_ActorProcess")

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/audit_thread_safety.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
print("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
