# @category Analysis
# @description Research texture hash table DAT_011f4468 cleanup mechanism

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def write(msg):
	output.append(msg)
	print(msg)

def decompile_at(addr_int, label, max_len=10000):
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
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		write(code[:max_len])
	else:
		write("  [decompilation failed]")

def find_xrefs_to(addr_int, label, limit=25):
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


write("=" * 70)
write("TEXTURE HASH TABLE (DAT_011f4468) CLEANUP RESEARCH")
write("Goal: Find what cleans stale entries after NiSourceTexture freed")
write("=" * 70)

# SECTION 1: Who reads/writes DAT_011f4468?
write("")
write("#" * 70)
write("# SECTION 1: DAT_011f4468 — texture hash table xrefs")
write("# Who adds entries? Who removes entries?")
write("#" * 70)

find_xrefs_to(0x011F4468, "DAT_011f4468_TextureHashTable")

# SECTION 2: FUN_00b5fd60 — resource flush (from DeferredCleanupSmall)
# Does it clean the texture hash table?
write("")
write("#" * 70)
write("# SECTION 2: FUN_00b5fd60 — resource flush")
write("# Called by DeferredCleanupSmall between PDD and AsyncFlush")
write("# Does it reference DAT_011f4468?")
write("#" * 70)

decompile_at(0x00B5FD60, "ResourceFlush", 15000)
find_calls_from(0x00B5FD60, "ResourceFlush")

# SECTION 3: Hash table removal function — FUN_00a61a60 sibling
# The hash table has add/remove/find functions. Find the REMOVE function.
write("")
write("#" * 70)
write("# SECTION 3: Hash table functions near FUN_00a61a60 (find)")
write("# Look for add/remove functions on same hash table class")
write("#" * 70)

# FUN_00a61a60 is the 'find' function (103 bytes)
# Check nearby functions for add/remove operations
decompile_at(0x00A619F0, "HashTable_func1")
decompile_at(0x00A61AC8, "HashTable_func_after_find")
decompile_at(0x00A61B30, "HashTable_func3")
decompile_at(0x00A61B90, "HashTable_func4")

# SECTION 4: FUN_0043c4c0 — who else calls this texture lookup?
# And what is the REMOVE counterpart?
write("")
write("#" * 70)
write("# SECTION 4: Texture lookup callers + removal counterpart")
write("#" * 70)

find_xrefs_to(0x0043C4C0, "TextureLookup_FUN_0043c4c0")
find_xrefs_to(0x0043C4F0, "HashLookupWrapper_FUN_0043c4f0")

# Is there a removal function for DAT_011f4468?
# Search for functions that WRITE to DAT_011f4468
# These would be add/remove/clear operations

# SECTION 5: FUN_0066b0d0 — called from texture processing
# Sets param_1+0x30 to param_2. Might be a refcounted pointer swap.
write("")
write("#" * 70)
write("# SECTION 5: FUN_0066b0d0 — refcount pointer swap?")
write("#" * 70)

decompile_at(0x0066B0D0, "RefPtrSwap")

# SECTION 6: FUN_00450b80 returns DAT_011f91c8 — what object is this?
# It's passed to FUN_00b5fd60
write("")
write("#" * 70)
write("# SECTION 6: DAT_011f91c8 — resource manager singleton")
write("#" * 70)

find_xrefs_to(0x011F91C8, "DAT_011f91c8_ResourceMgr")

# SECTION 7: DAT_011f4748 — returned by FUN_0043c4b0, used in texture processing
write("")
write("#" * 70)
write("# SECTION 7: DAT_011f4748 — another texture global")
write("#" * 70)

find_xrefs_to(0x011F4748, "DAT_011f4748")

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/texture_hashtable_cleanup.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
