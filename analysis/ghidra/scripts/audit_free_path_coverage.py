# @category Analysis
# @description AUDIT: Find ALL memory free paths in the game.
# Our quarantine only covers GameHeap::Free. CRT free goes direct mi_free.
# Are there OTHER free paths that bypass both? (Havok, NiMemObject, etc.)
# If so, those frees could cause UAF with quarantined GameHeap pointers.

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

def count_callers(addr_int, label):
	addr = toAddr(addr_int)
	refs = getReferencesTo(addr)
	count = 0
	callers = []
	for ref in refs:
		if ref.getReferenceType().isCall() or str(ref.getReferenceType()) == "UNCONDITIONAL_CALL":
			from_addr = ref.getFromAddress()
			func = fm.getFunctionContaining(from_addr)
			fname = func.getName() if func else "???"
			callers.append((from_addr, fname))
			count += 1
	write("  %s (0x%08x): %d callers" % (label, addr_int, count))
	for from_addr, fname in callers[:10]:
		write("    @ 0x%s in %s" % (from_addr, fname))
	if count > 10:
		write("    ... (%d more)" % (count - 10))
	return callers

write("=" * 70)
write("AUDIT: MEMORY FREE PATH COVERAGE")
write("=" * 70)

# Section 1: All known free entry points
write("")
write("#" * 70)
write("# SECTION 1: Known free entry points and their caller counts")
write("#" * 70)

write("")
write("### GameHeap free paths (HOOKED -> quarantine):")
count_callers(0x00AA4060, "GameHeap::Free")
count_callers(0x00AA42C0, "GameHeap::FallbackFree")

write("")
write("### CRT free paths (HOOKED -> mi_free direct):")
count_callers(0x00ECD291, "CRT_free_inline")

write("")
write("### Havok allocator (routes through GameHeap?):")
count_callers(0x00C3E170, "hkDeallocate")
count_callers(0x00C3E0D0, "hkAllocate")

write("")
write("### NiObject/Gamebryo delete paths:")
count_callers(0x00401030, "operator_delete_1")
count_callers(0x00401050, "operator_delete_2")
count_callers(0x0040FA60, "NiDelete_helper")

write("")
write("### VirtualFree / HeapFree (OS-level, bypasses everything):")
# These would bypass our hooks entirely
mem = currentProgram.getMemory()
write("  Checking for direct VirtualFree/HeapFree calls...")

# Section 2: Havok allocator deep dive
write("")
write("#" * 70)
write("# SECTION 2: Havok allocator — does it use GameHeap or its own?")
write("#" * 70)

decompile_at(0x00C3E0D0, "hkAllocate_GameHeap")
decompile_at(0x00C3E170, "hkDeallocate_GameHeap")

# hkFreeListAllocator — seen in crash logs, separate from GameHeap?
write("")
write("### hkFreeListAllocator (RTTI 0x010D1464):")
decompile_at(0x00C3D270, "hkFreeListAllocator_alloc_approx")
decompile_at(0x00C3D2D0, "hkFreeListAllocator_free_approx")

# Section 3: NiMemObject allocation
write("")
write("#" * 70)
write("# SECTION 3: NiMemObject new/delete — GameHeap or CRT?")
write("#" * 70)

decompile_at(0x00AA3E40, "GameHeap_Allocate (our hook target)")
decompile_at(0x00401000, "operator_new")
decompile_at(0x00401030, "operator_delete")

# Section 4: BSResource/Archive allocator (BSA file loading)
write("")
write("#" * 70)
write("# SECTION 4: BSResource allocator — separate heap?")
write("#" * 70)

decompile_at(0x00AF8D70, "BSResource_Alloc_approx")
decompile_at(0x00AF8DB0, "BSResource_Free_approx")

# Section 5: ScrapHeap original paths — do any bypass our hooks?
write("")
write("#" * 70)
write("# SECTION 5: ScrapHeap — any paths that bypass our hooks?")
write("#" * 70)

count_callers(0x00AA54A0, "ScrapHeap_Alloc (our hook)")
count_callers(0x00AA5610, "ScrapHeap_Free (our hook)")
count_callers(0x00AA5460, "ScrapHeap_Purge (our hook)")

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/audit_free_path_coverage.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
print("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
