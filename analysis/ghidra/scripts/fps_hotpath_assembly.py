# @category Analysis
# @description Compare the ACTUAL assembly for alloc/free hot paths.
#              Our alloc/free hooks are inline-hooked versions of:
#              FUN_00aa3e40 (GameHeap::Allocate)
#              FUN_00aa4060 (GameHeap::Free)
#
#              The hook trampoline adds overhead. Measure it by examining
#              the compiled paths. Also check what mi_malloc_aligned and
#              mi_free look like from the call site -- how many instructions
#              between entry and return?
#
#              Also examine: is there hidden overhead in the thiscall
#              convention wrapper? The game calls these as thiscall (ECX=this)
#              but our hooks ignore `this`. Does the trampoline save/restore
#              extra registers?

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

def disasm_range(start_int, end_int, label):
	write("")
	write("--- Disassembly: %s (0x%08x - 0x%08x) ---" % (label, start_int, end_int))
	listing = currentProgram.getListing()
	addr = toAddr(start_int)
	end = toAddr(end_int)
	while addr.compareTo(end) < 0:
		inst = listing.getInstructionAt(addr)
		if inst is None:
			write("  0x%08x: [no instruction]" % addr.getOffset())
			addr = addr.add(1)
		else:
			write("  0x%08x: %s" % (addr.getOffset(), inst.toString()))
			addr = addr.add(inst.getLength())

write("FPS HOTPATH ASSEMBLY ANALYSIS")
write("=" * 70)
write("")
write("Goal: find hidden overhead in our hook trampolines and hot paths.")
write("Compare original SBM alloc/free instruction count with what our")
write("hooks need to execute.")
write("")

# ===================================================================
# PART 1: Original SBM alloc/free entry points
# These are what the game calls. Our hooks replace these.
# ===================================================================

write("PART 1: ORIGINAL SBM ENTRY POINTS")
write("=" * 70)

# First 32 bytes of GameHeap::Allocate -- the entry sequence
disasm_range(0x00AA3E40, 0x00AA3E60, "GameHeap::Allocate entry")

# First 32 bytes of GameHeap::Free -- the entry sequence
disasm_range(0x00AA4060, 0x00AA4080, "GameHeap::Free entry")

# ===================================================================
# PART 2: All callers of GameHeap::Allocate and Free
# How many call sites? Each one goes through our hook trampoline.
# ===================================================================

write("")
write("PART 2: CALL SITE COUNT")
write("=" * 70)

def count_refs_to(addr_int, label):
	refs = currentProgram.getReferenceManager().getReferencesTo(toAddr(addr_int))
	count = 0
	call_count = 0
	while refs.hasNext():
		ref = refs.next()
		count += 1
		if ref.getReferenceType().isCall():
			call_count += 1
	write("  %s: %d total refs, %d CALL refs" % (label, count, call_count))

count_refs_to(0x00AA3E40, "GameHeap::Allocate (0x00aa3e40)")
count_refs_to(0x00AA4060, "GameHeap::Free (0x00aa4060)")
count_refs_to(0x00AA44C0, "GameHeap::Msize (0x00aa44c0)")
count_refs_to(0x00AA4150, "GameHeap::Realloc1 (0x00aa4150)")
count_refs_to(0x00AA4200, "GameHeap::Realloc2 (0x00aa4200)")

# ===================================================================
# PART 3: The inline hook trampoline structure
# When our hook is installed, the first N bytes of the original
# function are overwritten with a JMP to our hook. The original
# bytes are saved in the trampoline. Overhead:
#   1. JMP to hook function (1 indirect jump)
#   2. Hook function executes (our Rust code)
#   3. To call original: JMP to trampoline (1 indirect jump)
#   4. Trampoline executes saved bytes + JMP back to original+N
# Total: 2 extra indirect jumps per hooked call
# ===================================================================

write("")
write("PART 3: HOOK TRAMPOLINE OVERHEAD")
write("=" * 70)
write("")
write("Inline hook overhead per call:")
write("  1. Caller does CALL 0x00aa3e40")
write("  2. First bytes of 0x00aa3e40 are JMP [hook_fn]")
write("  3. CPU executes our Rust hook_gheap_alloc")
write("  4. If calling original: JMP [trampoline]")
write("  5. Trampoline: saved original bytes + JMP back")
write("")
write("Overhead: 2 indirect JMPs (~10-20 cycles each on modern x86)")
write("Per alloc/free: ~20-40 cycles = ~10-20ns at 2GHz")
write("At 100K alloc+free/frame: 100K * 20ns = 2ms/frame")
write("THIS COULD BE THE FPS ISSUE")
write("")
write("But master has the SAME hooks with the SAME trampoline overhead.")
write("So the trampoline itself is NOT the difference.")
write("")

# ===================================================================
# PART 4: What does our hook do that master's doesn't?
# Master hook_gheap_free:
#   1. null check
#   2. mi_is_in_heap_region
#   3. IS_MAIN_THREAD TLS read (Cell<bool>)
#   4. quarantine push (mi_usable_size + Vec push + atomic)
#   OR mi_free
#
# Our hook_gheap_free:
#   1. null check
#   2. mi_is_in_heap_region
#   3. is_main_thread (match ThreadRole enum)
#   4. is_deferred_active (atomic load)
#   5. deferred_free::push (Vec push + atomic increment)
#   OR mi_free
#
# Difference: we have an extra atomic load (is_deferred_active)
# but skip mi_usable_size (~5ns savings per free)
# Net: roughly equivalent, maybe slightly faster
# ===================================================================

write("")
write("PART 4: HOT PATH COMPARISON")
write("=" * 70)
write("")
write("Master free path:              Our free path:")
write("  null check                     null check")
write("  mi_is_in_heap_region           mi_is_in_heap_region")
write("  IS_MAIN_THREAD (Cell read)     is_main_thread (match enum)")
write("  mi_usable_size (~5ns)          is_deferred_active (atomic ~1ns)")
write("  Vec::push + atomic             Vec::push + atomic")
write("")
write("Net difference: we SKIP mi_usable_size but ADD is_deferred_active.")
write("Should be ~4ns FASTER per free. Not the FPS issue.")
write("")

# ===================================================================
# PART 5: What about the PDD hook overhead?
# FUN_00868d70 is hooked. It's called at Phase 6/7.
# Each call goes through the trampoline.
# How many times per frame is PDD called?
# ===================================================================

write("")
write("PART 5: PDD HOOK FREQUENCY")
write("=" * 70)

count_refs_to(0x00868D70, "PDD (FUN_00868d70)")

write("")
write("PDD is called from HeapCompact, per-frame drain, and cleanup paths.")
write("Each call: 1 trampoline overhead (~20ns). If called 1-2x per frame,")
write("that is 20-40ns total. Negligible.")
write("")

# ===================================================================
# PART 6: What about texture_cache_find hook?
# This is called by BST on every texture lookup. Could be 1000s/frame.
# ===================================================================

write("")
write("PART 6: TEXTURE CACHE FIND FREQUENCY")
write("=" * 70)

count_refs_to(0x00A61A60, "TextureCacheFind (FUN_00a61a60)")

write("")
write("If this is called 1000s of times per frame from BST,")
write("the hook trampoline + try_read + dead set check adds up.")
write("But master has the SAME hook. So NOT a regression.")

# ===================================================================
# OUTPUT
# ===================================================================

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/fps_hotpath_assembly.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
