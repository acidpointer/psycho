# @category Analysis
# @description Find what flag/state indicates ragdoll is fully initialized.
# The skeleton update at FUN_00c79680 reads bone entries from the array
# at param_1+0xa4. The array exists (non-NULL) but entries are zero
# (virgin slab page). Need to find a readiness check.
#
# FUN_00c79680 line 103: local_88 = *(*(*(param_1+0x2a4)+0xc)+0x1c)
# This is the bone COUNT. If the count check chain has a NULL, it would
# crash BEFORE reaching the +0xa4 read. Since we crash at +0xa4's
# content, the count chain is valid but the bone data isn't.
#
# Key question: does the ragdoll have a "ready" state at some offset
# that the game checks elsewhere? What offset gets set LAST during init?

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
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

def find_and_print_calls_from(addr_int, label):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	if func is None:
		write("  [function not found at 0x%08x]" % addr_int)
		return
	body = func.getBody()
	inst_iter = currentProgram.getListing().getInstructions(body, True)
	write("")
	write("--- Calls FROM %s (0x%08x) ---" % (label, addr_int))
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				tgt_func = fm.getFunctionAt(toAddr(tgt))
				name = tgt_func.getName() if tgt_func else "???"
				write("  CALL @ 0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, name))
				count += 1
	write("  Total: %d calls" % count)

def find_refs_to(addr_int, label):
	write("")
	write("-" * 70)
	write("References TO 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		fname = from_func.getName() if from_func else "???"
		write("  %s @ 0x%08x (in %s)" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname))
		count += 1
		if count > 40:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)


write("######################################################################")
write("# RAGDOLL INITIALIZATION FLAG / READINESS CHECK")
write("######################################################################")


write("")
write("######################################################################")
write("# PART 1: Who calls FUN_00c79680 (skeleton update)?")
write("# Is FUN_00c7d810 the ONLY caller? Or are there others?")
write("######################################################################")

find_refs_to(0x00C79680, "Ragdoll_SkeletonUpdate callers")


write("")
write("######################################################################")
write("# PART 2: Who calls FUN_00c7d810 (bone transform update)?")
write("# Our hook is here. What other code calls it?")
write("######################################################################")

find_refs_to(0x00C7D810, "Ragdoll_BoneTransformUpdate callers")


write("")
write("######################################################################")
write("# PART 3: FUN_00930b5c area - NEW frame in crash stack")
write("# Frame #3 (0x00930B5C). Between actor process and our hook.")
write("# What is this function? Does it check ragdoll state?")
write("######################################################################")

decompile_at(0x00930B5C, "NewFrame_930B5C")


write("")
write("######################################################################")
write("# PART 4: The bhkRagdollController constructor again")
write("# We know it sets +0xa4=0, +0x2a4=0, etc.")
write("# What is the LAST field set? That might be the ready flag.")
write("# Also: offset +0x0C (from bone transform update line 346:")
write("#   *(undefined4 *)((int)param_1 + 0xc) = 1")
write("# This sets +0xc to 1. Is this the ready flag?")
write("######################################################################")

decompile_at(0x00C7F060, "bhkRagdollController_Constructor (re-check)")


write("")
write("######################################################################")
write("# PART 5: What callers of FUN_00c7d810 check before calling?")
write("# If there is a guard like 'if (ragdoll->ready) update()'")
write("# then the game already has a readiness check somewhere.")
write("######################################################################")

write("")
write("# From FUN_00c7d810 decompile (line 345-346):")
write("#   uVar1 = *(undefined4 *)((int)param_1 + 0xc);")
write("#   *(undefined4 *)((int)param_1 + 0xc) = 1;")
write("#   FUN_00c7d030(param_1,(undefined4 *)0x0);")
write("#   *(undefined4 *)((int)param_1 + 0xc) = uVar1;")
write("#")
write("# +0xc is saved, set to 1, then restored. This is a temporary flag.")
write("# Not a readiness indicator.")


write("")
write("######################################################################")
write("# PART 6: The bone array at +0xa4 - who ALLOCATES it?")
write("# Constructor sets +0xa4=0. Someone later allocates the array")
write("# and writes the pointer to +0xa4. Who?")
write("# Search for writes to offset 0xa4 in ragdoll-related code.")
write("######################################################################")

write("")
write("# The constructor (FUN_00c7f060) sets +0xa4=0 at construction.")
write("# After construction, some init function allocates the bone array")
write("# and sets +0xa4 to point to it. But the bone array entries")
write("# themselves are zero (virgin page). The skeleton update reads")
write("# *(bone_array + local_94) which is 0 -> *(0 + 0x34) -> crash.")
write("")
write("# With SBM, the bone array allocation gets recycled memory with")
write("# old bone pointers. These point to still-committed memory.")
write("# With our slab Tier 3, the array is zeroed by VirtualAlloc.")


write("")
write("######################################################################")
write("# PART 7: The bone count chain")
write("# local_88 = *(*(*(param_1+0x2a4)+0xc)+0x1c)")
write("# +0x2a4 is set to 0 by constructor. If skeleton update runs")
write("# with +0x2a4=0, it would crash at *(0+0xc). But the crash is")
write("# at +0xa4 data, meaning +0x2a4 is valid. So +0x2a4 was")
write("# initialized before +0xa4's bone array entries were filled.")
write("######################################################################")

write("")
write("# Conclusion: The initialization order is:")
write("#   1. Constructor: +0xa4=0, +0x2a4=0")
write("#   2. Init step A: +0x2a4 = valid pointer (bone hierarchy)")
write("#   3. Init step B: +0xa4 = allocated bone array (but entries=0)")
write("#   4. Init step C: bone array entries filled with bone pointers")
write("#   5. Skeleton update runs (FUN_00c79680)")
write("#")
write("# The crash: skeleton update runs between step 3 and step 4.")
write("# The bone array exists but its entries are zero.")
write("#")
write("# With SBM: the bone array allocation in step 3 returns memory")
write("# with old bone pointers (zombie data). Step 5 reads valid-ish")
write("# pointers even before step 4 runs. No crash.")


outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/ragdoll_init_flag.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
