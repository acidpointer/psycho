# @category Analysis
# @description Check ragdoll controller vtable addresses. Are they all in RDATA (0x01000000-0x01300000)?

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()

output = []

def write(msg):
	output.append(msg)
	print(msg)

def check_vtable_range(addr_int, label):
	write("")
	write("=" * 70)
	write("%s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	mem = currentProgram.getMemory()
	try:
		val = mem.getInt(toAddr(addr_int))
		vtable = val & 0xFFFFFFFF
		in_rdata = 0x01000000 <= vtable < 0x01300000
		write("  Vtable ptr: 0x%08x  In RDATA: %s" % (vtable, in_rdata))
	except:
		write("  [could not read memory at 0x%08x]" % addr_int)

def find_vtable_writes(func_addr, label):
	write("")
	write("-" * 70)
	write("Vtable assignments in %s (0x%08x)" % (label, func_addr))
	write("-" * 70)
	listing = currentProgram.getListing()
	func = fm.getFunctionAt(toAddr(func_addr))
	if func is None:
		func = fm.getFunctionContaining(toAddr(func_addr))
	if func is None:
		write("  [function not found]")
		return
	body = func.getBody()
	inst_iter = listing.getInstructions(body, True)
	while inst_iter.hasNext():
		inst = inst_iter.next()
		mnem = inst.getMnemonicString()
		s = str(inst)
		# Look for MOV [reg], imm32 patterns (vtable assignments)
		if mnem == "MOV" and "PTR" in s:
			refs = inst.getReferencesFrom()
			for ref in refs:
				tgt = ref.getToAddress().getOffset()
				if 0x01000000 <= tgt < 0x01300000:
					write("  0x%08x: %s  (vtable = 0x%08x)" % (inst.getAddress().getOffset(), s, tgt))

write("=" * 70)
write("RAGDOLL VTABLE ANALYSIS")
write("RDATA range: 0x01000000 - 0x01300000")
write("=" * 70)

write("")
write("#" * 70)
write("# PART 1: FUN_00c79680 (skeleton update) -- what calls it?")
write("# The ragdoll ptr passed to this function -- where does it come from?")
write("#" * 70)

def find_refs(addr_int, label):
	write("")
	write("References TO 0x%08x (%s)" % (addr_int, label))
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		fname = from_func.getName() if from_func else "???"
		write("  %s @ 0x%08x (in %s)" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname))
		count += 1
		if count > 30:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)

find_refs(0x00c79680, "SkeletonUpdate")

write("")
write("#" * 70)
write("# PART 2: Known Havok/ragdoll vtable addresses")
write("# Check bhkRagdollController and related classes")
write("#" * 70)

# Known Havok class vtables from FNV (common ones)
# These are typically in the 0x0109xxxx - 0x010Axxxx range
havok_classes = [
	(0x0109A5CC, "bhkRagdollController"),
	(0x0109A68C, "bhkRagdollController_alt"),
	(0x010A2E7C, "bhkCharacterController"),
	(0x010A03FC, "bhkRigidBody"),
	(0x0109B5AC, "NiNode_Bip01"),
	(0x01096784, "NiBlendAccumTransformInterpolator"),
	(0x010A8F90, "BSFadeNode"),
]

def check_class(addr, name):
	mem = currentProgram.getMemory()
	try:
		val = mem.getInt(toAddr(addr))
		in_rdata = 0x01000000 <= (val & 0xFFFFFFFF) < 0x01300000
		write("  0x%08x (%s): first dword = 0x%08x, in RDATA: %s" % (addr, name, val & 0xFFFFFFFF, in_rdata))
	except:
		write("  0x%08x (%s): [unreadable]" % (addr, name))

def print_havok_classes():
	for item in havok_classes:
		check_class(item[0], item[1])

print_havok_classes()

write("")
write("#" * 70)
write("# PART 3: Search for bhkRagdollController RTTI")
write("# Find the actual vtable address from RTTI data")
write("#" * 70)

# Search for "bhkRagdollController" string in memory
listing = currentProgram.getListing()
mem = currentProgram.getMemory()

def search_rtti(class_name):
	write("")
	write("Searching RTTI for '%s'..." % class_name)
	# Search in .rdata section for the class name string
	block = mem.getBlock(".rdata")
	if block is None:
		# Try without dot
		block = mem.getBlock("rdata")
	if block is None:
		write("  [.rdata block not found, trying full memory search]")
		# Search all blocks
		blocks = mem.getBlocks()
		for b in blocks:
			write("  Memory block: %s @ 0x%08x - 0x%08x (%s)" % (b.getName(), b.getStart().getOffset(), b.getEnd().getOffset(), "R" if b.isRead() else "-"))
		return
	write("  .rdata: 0x%08x - 0x%08x" % (block.getStart().getOffset(), block.getEnd().getOffset()))

search_rtti("bhkRagdollController")

write("")
write("#" * 70)
write("# PART 4: FUN_00c79680 decompilation")
write("# What does the ORIGINAL skeleton update do?")
write("# What fields does it read from the ragdoll controller?")
write("#" * 70)

decomp = DecompInterface()
decomp.openProgram(currentProgram)

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
	sig = func.getSignature()
	write("  Convention: %s" % func.getCallingConventionName())
	write("  Signature: %s" % sig)
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		write(code[:max_len])
	else:
		write("  [decompilation failed]")

decompile_at(0x00c79680, "SkeletonUpdate_00c79680")

write("")
write("#" * 70)
write("# PART 5: What objects get passed to FUN_00c79680?")
write("# Decompile callers to see what ragdoll ptr is")
write("#" * 70)

# Find callers and decompile them
refs2 = ref_mgr.getReferencesTo(toAddr(0x00c79680))
seen = set()
while refs2.hasNext():
	ref = refs2.next()
	if not ref.getReferenceType().isCall():
		continue
	caller = fm.getFunctionContaining(ref.getFromAddress())
	if caller is None:
		continue
	caddr = caller.getEntryPoint().getOffset()
	if caddr in seen:
		continue
	seen.add(caddr)
	decompile_at(caddr, "Caller_of_SkeletonUpdate_%08x" % caddr)

decomp.dispose()


outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/ragdoll_vtable_check.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
