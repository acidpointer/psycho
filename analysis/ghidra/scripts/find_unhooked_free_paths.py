# @category Analysis
# @description Find all callers of unhooked GameHeap free/alloc functions to identify leak sources

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

# Hooked functions (these are intercepted - calls here go through our hooks):
HOOKED = {
	0x00AA3E40: "GameHeap::Allocate (HOOKED)",
	0x00AA4060: "GameHeap::Free (HOOKED)",
	0x00AA4150: "GameHeap::Realloc1 (HOOKED)",
	0x00AA4200: "GameHeap::Realloc2 (HOOKED)",
	0x00AA44C0: "GameHeap::Msize (HOOKED)",
}

# Potentially UNHOOKED functions that could bypass our hooks:
UNHOOKED = {
	0x00AA42C0: "FallbackFree (NOT HOOKED)",
	0x00AA4290: "FallbackAlloc (NOT HOOKED)",
	0x00AA6C70: "SBM_ArenaFree (NOT HOOKED)",
	0x00AA6AA0: "SBM_ArenaAlloc (NOT HOOKED)",
	0x00AA45A0: "FindAllocator (NOT HOOKED)",
	0x00AA4610: "FindAllocator2 (NOT HOOKED)",
	0x00AA4960: "SBM_GetPool (NOT HOOKED)",
}

def decompile_func(addr_int, label, max_len=4000):
	addr = toAddr(addr_int)
	func = fm.getFunctionAt(addr)
	if func is None:
		func = fm.getFunctionContaining(addr)
	output.append("\n--- %s @ 0x%08x ---" % (label, addr_int))
	if func is None:
		output.append("  [function not found]")
		return
	output.append("  Function: %s, size: %d bytes" % (func.getName(), func.getBody().getNumAddresses()))
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		if len(code) > max_len:
			output.append(code[:max_len])
		else:
			output.append(code)
	output.append("")

def get_xrefs(addr_int):
	addr = toAddr(addr_int)
	refs = ref_mgr.getReferencesTo(addr)
	callers = []
	for ref in refs:
		from_addr = ref.getFromAddress()
		from_func = fm.getFunctionContaining(from_addr)
		if from_func is not None:
			caller_name = from_func.getName()
			caller_addr = from_func.getEntryPoint().getOffset()
		else:
			caller_name = "unknown"
			caller_addr = 0
		is_internal = caller_addr in HOOKED or caller_addr in UNHOOKED
		callers.append((from_addr.getOffset(), caller_name, caller_addr, is_internal))
	return callers

# =====================================================================
# 1. Decompile unhooked functions
# =====================================================================
output.append("=" * 80)
output.append("SECTION 1: DECOMPILATION OF UNHOOKED FUNCTIONS")
output.append("=" * 80)

for addr_int in sorted(UNHOOKED.keys()):
	label = UNHOOKED[addr_int]
	decompile_func(addr_int, label)

# =====================================================================
# 2. Find ALL xrefs to unhooked functions
# =====================================================================
output.append("=" * 80)
output.append("SECTION 2: CALLERS OF UNHOOKED FUNCTIONS")
output.append("(These callers bypass our hooks - potential leak sources)")
output.append("=" * 80)

for addr_int in sorted(UNHOOKED.keys()):
	label = UNHOOKED[addr_int]
	callers = get_xrefs(addr_int)
	output.append("\n--- %s @ 0x%08x: %d xrefs ---" % (label, addr_int, len(callers)))
	for item in sorted(callers):
		from_off = item[0]
		name = item[1]
		func_off = item[2]
		internal = item[3]
		if internal:
			tag = "[INTERNAL]"
		else:
			tag = "[EXTERNAL - POTENTIAL LEAK]"
		output.append("  %s 0x%08x in %s (0x%08x)" % (tag, from_off, name, func_off))

# =====================================================================
# 3. GameHeap vtable analysis
# =====================================================================
output.append("")
output.append("=" * 80)
output.append("SECTION 3: GAMEHEAP VTABLE / SINGLETON ANALYSIS")
output.append("=" * 80)

singleton_addr = toAddr(0x011F6238)
output.append("")
output.append("GameHeap singleton at 0x011F6238")

try:
	vtable_ptr = getInt(singleton_addr) & 0xFFFFFFFF
	output.append("Vtable pointer: 0x%08x" % vtable_ptr)
	output.append("")
	output.append("Vtable entries:")
	for i in range(20):
		entry_addr = toAddr(vtable_ptr + i * 4)
		try:
			func_ptr = getInt(entry_addr) & 0xFFFFFFFF
			func_at = fm.getFunctionAt(toAddr(func_ptr))
			if func_at is not None:
				func_name = func_at.getName()
			else:
				func_name = "???"
			if func_ptr in HOOKED:
				hooked_tag = " [HOOKED]"
			else:
				hooked_tag = ""
			output.append("  vtable[%2d] = 0x%08x  %s%s" % (i, func_ptr, func_name, hooked_tag))
		except:
			output.append("  vtable[%2d] = [read error]" % i)
			break
except:
	output.append("[Could not read vtable - singleton may not be initialized in static analysis]")
	output.append("Attempting to find vtable via code references...")

# =====================================================================
# 4. References to GameHeap singleton
# =====================================================================
output.append("")
output.append("=" * 80)
output.append("SECTION 4: REFERENCES TO GAMEHEAP SINGLETON (0x011F6238)")
output.append("=" * 80)

singleton_refs = ref_mgr.getReferencesTo(toAddr(0x011F6238))
singleton_callers = {}
for ref in singleton_refs:
	from_addr = ref.getFromAddress()
	from_func = fm.getFunctionContaining(from_addr)
	if from_func is not None:
		func_addr = from_func.getEntryPoint().getOffset()
		if func_addr not in singleton_callers:
			singleton_callers[func_addr] = (from_func.getName(), [])
		singleton_callers[func_addr][1].append(from_addr.getOffset())

output.append("")
output.append("%d unique functions reference the GameHeap singleton:" % len(singleton_callers))
for func_addr in sorted(singleton_callers.keys()):
	entry = singleton_callers[func_addr]
	name = entry[0]
	refs = entry[1]
	if func_addr in HOOKED:
		hooked_tag = " [HOOKED]"
	else:
		hooked_tag = ""
	refs_sorted = sorted(refs)[:5]
	refs_str = ", ".join(["0x%08x" % r for r in refs_sorted])
	if len(refs) > 5:
		refs_str = refs_str + " (+%d more)" % (len(refs) - 5)
	output.append("  0x%08x %s%s  refs: %s" % (func_addr, name, hooked_tag, refs_str))

# =====================================================================
# 5. Decompile key external callers of unhooked free paths
# =====================================================================
output.append("")
output.append("=" * 80)
output.append("SECTION 5: DECOMPILATION OF KEY EXTERNAL CALLERS")
output.append("=" * 80)

external_callers = set()
FREE_RELATED = [0x00AA42C0, 0x00AA6C70]
for addr_int in FREE_RELATED:
	callers = get_xrefs(addr_int)
	for item in callers:
		func_off = item[2]
		internal = item[3]
		if not internal:
			external_callers.add(func_off)

count = 0
for func_addr in sorted(external_callers):
	if count >= 15:
		break
	func = fm.getFunctionAt(toAddr(func_addr))
	if func is None:
		continue
	decompile_func(func_addr, func.getName(), 3000)
	count = count + 1

# Write output
text = "\n".join(output)
outpath = "/tmp/unhooked_free_paths.txt"
fout = open(outpath, "w")
fout.write(text)
fout.close()
print("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
