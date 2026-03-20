# @category Analysis
# @description Research PLChangeEvent dispatch path on AI threads.
# Crash: AI thread fires JohnnyGuitar HandlePLChangeEvent during cell unload,
# accesses corrupt bhkWorldM. Need to understand:
# 1. What FUN_00548580 does (dispatches events)
# 2. Does it check LOADING_STATE_COUNTER (DAT_01202d6c)?
# 3. What FUN_00882578 does (calls JohnnyGuitar handler)
# 4. Can we suppress event dispatch on AI threads during cell unload?

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
	write("  Function: %s, Size: %d bytes" % (func.getName(), func.getBody().getNumAddresses()))
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		write(code[:max_len])
	else:
		write("  [decompilation failed]")

def find_xrefs_to(addr_int, label, limit=20):
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

def find_xrefs_from(addr_int, label):
	addr = toAddr(addr_int)
	func = fm.getFunctionAt(addr)
	if func is None:
		func = fm.getFunctionContaining(addr)
	if func is None:
		write("  [function not found at 0x%08x]" % addr_int)
		return
	write("")
	write("--- Calls FROM %s (0x%08x) ---" % (label, addr_int))
	body = func.getBody()
	count = 0
	seen = set()
	for rng in body:
		addr_iter = rng.getMinAddress()
		while addr_iter is not None and addr_iter.compareTo(rng.getMaxAddress()) <= 0:
			refs = getReferencesFrom(addr_iter)
			for ref in refs:
				if ref.getReferenceType().isCall():
					to_addr = ref.getToAddress()
					key = str(to_addr)
					if key not in seen:
						seen.add(key)
						target_func = fm.getFunctionAt(to_addr)
						tname = target_func.getName() if target_func else "???"
						write("  CALL 0x%s -> %s" % (to_addr, tname))
						count += 1
			addr_iter = addr_iter.next()
	write("  Total unique calls: %d" % count)

write("=" * 70)
write("PLCHANGEEVENT DISPATCH ON AI THREAD")
write("=" * 70)
write("")
write("Crash: AI thread -> 0x00882578 -> JohnnyGuitar HandlePLChangeEvent")
write("  -> 0x00C6757A (Havok bhkRigidBodyT access, corrupt bhkWorldM)")
write("")
write("LOADING_STATE_COUNTER = DAT_01202d6c")
write("Question: does the event dispatch path check this counter?")

# SECTION 1: The event dispatch function
write("")
write("#" * 70)
write("# SECTION 1: FUN_00548580 - dispatches PLChangeEvent?")
write("#" * 70)

decompile_at(0x00548580, "EventDispatch_0x548580")
find_xrefs_from(0x00548580, "EventDispatch_0x548580")

# SECTION 2: The function that calls JohnnyGuitar
write("")
write("#" * 70)
write("# SECTION 2: FUN_00882578 - calls JohnnyGuitar handler")
write("#" * 70)

decompile_at(0x00882578, "PLChange_Caller_0x882578")
find_xrefs_from(0x00882578, "PLChange_Caller_0x882578")

# SECTION 3: What checks LOADING_STATE_COUNTER?
write("")
write("#" * 70)
write("# SECTION 3: Who reads DAT_01202d6c (LOADING_STATE_COUNTER)?")
write("# If the event dispatch checks it, we can suppress on AI threads")
write("#" * 70)

find_xrefs_to(0x01202D6C, "LOADING_STATE_COUNTER")

# SECTION 4: FUN_0043b2b0 - the inc/dec function for LOADING_STATE_COUNTER
write("")
write("#" * 70)
write("# SECTION 4: FUN_0043b2b0 - LOADING_STATE_COUNTER inc/dec")
write("#" * 70)

decompile_at(0x0043B2B0, "LoadingState_IncDec")
find_xrefs_to(0x0043B2B0, "LoadingState_IncDec")

# SECTION 5: The Havok crash path
write("")
write("#" * 70)
write("# SECTION 5: FUN_00C6757A crash site (Havok)")
write("#" * 70)

decompile_at(0x00C6757A, "HavokCrash_0xC6757A")

# SECTION 6: Actor process level change dispatch
write("")
write("#" * 70)
write("# SECTION 6: Actor process level change chain")
write("# 0x009EACCC -> 0x009DC5C0 -> 0x009DC2E4 -> 0x008B336A")
write("#" * 70)

decompile_at(0x009EACCC, "ActorProcess_0x9EACCC")
decompile_at(0x008B336A, "ProcessManager_0x8B336A")

# SECTION 7: Does the game skip event dispatch during loading?
write("")
write("#" * 70)
write("# SECTION 7: FUN_00573B4F - in the dispatch chain before PLChangeEvent")
write("#" * 70)

decompile_at(0x00573B4F, "PreEventDispatch_0x573B4F")

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/plchange_event_dispatch.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
print("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
