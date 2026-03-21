# @category Analysis
# @description Audit FUN_00a61a60 refcount logic for find_skipping_dead verification

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
write("TEXTURE CACHE FIND - REFCOUNT AUDIT")
write("FUN_00a61a60 (103 bytes, thiscall)")
write("=" * 70)

# SECTION 1: Full disassembly of FUN_00a61a60 (with LOCK prefix markers)
write("")
write("# SECTION 1: Full disasm of FUN_00a61a60")
write("# LOCK prefixed instructions marked with <<<ATOMIC>>>")
inst = listing.getInstructionAt(toAddr(0x00A61A60))
count = 0
while inst is not None and count < 45:
	off = inst.getAddress().getOffset()
	if off >= 0x00A61AC8:
		break
	s = inst.toString()
	marker = ""
	if "LOCK" in s.upper():
		marker = "  <<<ATOMIC>>>"
	write("  0x%08x: %s%s" % (off, s, marker))
	count += 1
	inst = inst.getNext()

# SECTION 2: Decompiled
write("")
write("# SECTION 2: Decompiled FUN_00a61a60")
decompile_at(0x00A61A60, "TextureCacheFind")

# SECTION 4: Functions called by find
write("")
write("# SECTION 4: Calls from FUN_00a61a60")
find_calls_from(0x00A61A60, "TextureCacheFind")

# SECTION 5: NiRefObject refcount helpers
write("")
write("# SECTION 5: NiRefObject DecRef / IncRef")
decompile_at(0x00401EA0, "Possible_DecRef")
decompile_at(0x00770060, "Possible_IncRef")

# SECTION 6: Hash table insert for layout verification
write("")
write("# SECTION 6: FUN_00a61920 - hash table insert")
decompile_at(0x00A61920, "HashTable_Insert")

# SECTION 7: Callers of find
write("")
write("# SECTION 7: All callers of FUN_00a61a60")
find_xrefs_to(0x00A61A60, "TextureCacheFind_callers")

# SECTION 8: Texture cache lock
write("")
write("# SECTION 8: Texture cache lock DAT_011f4480")
find_xrefs_to(0x011F4480, "TextureCache_lock")

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/hashtable_find_refcount_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
