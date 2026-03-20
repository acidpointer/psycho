# @category Analysis
# @description AUDIT: Side effects of every game function we call.
# Our pressure relief calls: PreDestructionSetup, FindCellToUnload,
# DeferredCleanupSmall, PostDestructionRestore.
# What are ALL side effects? What global state do they modify?
# What preconditions do they expect?

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
write("AUDIT: PRESSURE RELIEF FUNCTION SIDE EFFECTS")
write("=" * 70)

# Section 1: PreDestructionSetup — what EXACTLY does it do?
write("")
write("#" * 70)
write("# SECTION 1: PreDestructionSetup (0x00878160)")
write("# We call: pre_destruction(state_ptr, 1, 1, 1)")
write("# What do params 1,1,1 enable? What globals does it modify?")
write("#" * 70)

decompile_at(0x00878160, "PreDestructionSetup")
find_xrefs_from(0x00878160, "PreDestructionSetup")

# FUN_00c3e310 = hkWorld_Lock
decompile_at(0x00C3E310, "hkWorld_Lock")
# FUN_004a0370 = SceneGraph operation
decompile_at(0x004A0370, "SceneGraph_Op_from_PreDestruction")
# FUN_008781f0/008781e0 = state save/restore
decompile_at(0x008781F0, "SaveState_008781f0")
decompile_at(0x008781E0, "SetState_008781e0")
# FUN_00703980 = SceneGraphInvalidate
decompile_at(0x00703980, "SceneGraphInvalidate")
# FUN_00652160 = condition check
decompile_at(0x00652160, "PreDestruction_CondCheck")

# Section 2: PostDestructionRestore — what does it restore?
write("")
write("#" * 70)
write("# SECTION 2: PostDestructionRestore (0x00878200)")
write("# Calls FUN_00aa7030 (GlobalCleanup) which we RET-patched!")
write("# What else does it do?")
write("#" * 70)

decompile_at(0x00878200, "PostDestructionRestore")
find_xrefs_from(0x00878200, "PostDestructionRestore")

# FUN_00a5b460 — called first in PostDestruction
decompile_at(0x00A5B460, "PostDestruction_First")
decompile_at(0x00A5B3C0, "PostDestruction_First_Inner")
# FUN_00652190 — conditional restore
decompile_at(0x00652190, "PostDestruction_CondRestore")
# FUN_004a03c0 — SceneGraph restore
decompile_at(0x004A03C0, "SceneGraph_Restore")
# FUN_00c3e340 = hkWorld_Unlock
decompile_at(0x00C3E340, "hkWorld_Unlock")

# Section 3: DeferredCleanupSmall internals
write("")
write("#" * 70)
write("# SECTION 3: DeferredCleanupSmall (0x00878250) deep")
write("# What does FUN_00b5fd60 do? (called between PDD and AsyncFlush)")
write("#" * 70)

decompile_at(0x00878250, "DeferredCleanupSmall")
decompile_at(0x00B5FD60, "DCS_Middle_FUN_00b5fd60")

# The conditional cleanup functions
decompile_at(0x00651E30, "DCS_Conditional_1")
decompile_at(0x00651F40, "DCS_Conditional_2")

# FUN_00448620 — near end
decompile_at(0x00448620, "DCS_NearEnd_00448620")

# Section 4: FindCellToUnload preconditions
write("")
write("#" * 70)
write("# SECTION 4: FindCellToUnload (0x00453A80) callers")
write("# Who else calls it? Under what conditions?")
write("#" * 70)

addr = toAddr(0x00453A80)
refs = getReferencesTo(addr)
write("")
write("Callers of FindCellToUnload (0x00453A80):")
for ref in refs:
	from_addr = ref.getFromAddress()
	func = fm.getFunctionContaining(from_addr)
	fname = func.getName() if func else "???"
	write("  %s @ 0x%s in %s" % (ref.getReferenceType(), from_addr, fname))

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/audit_pressure_side_effects.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
print("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
