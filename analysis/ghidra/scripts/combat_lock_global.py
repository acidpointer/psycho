# @category Analysis
# @description Investigate DAT_011dea2a (combat lock global) and what sets/clears it. If stuck non-zero, all player attacks blocked.

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
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
	sig = func.getSignature()
	write("  Convention: %s" % func.getCallingConventionName())
	write("  Signature: %s" % sig)
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		write(code[:max_len])
	else:
		write("  [decompilation failed]")

def find_refs_to(addr_int, label):
	write("")
	write("-" * 70)
	write("References TO 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		from_addr = ref.getFromAddress().getOffset()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		fname = from_func.getName() if from_func else "???"
		rtype = ref.getReferenceType()
		write("  %s @ 0x%08x (in %s)" % (rtype, from_addr, fname))
		count += 1
		if count > 80:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)

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
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, name))
				count += 1
	write("  Total: %d calls" % count)


write("=" * 70)
write("COMBAT LOCK GLOBAL INVESTIGATION")
write("DAT_011dea2a -- if non-zero, player attacks are blocked")
write("=" * 70)

write("")
write("#" * 70)
write("# PART 1: ALL references to DAT_011dea2a")
write("# Every read and write. This tells us who checks it and who sets it.")
write("#" * 70)

find_refs_to(0x011dea2a, "DAT_011dea2a (combat lock)")

write("")
write("#" * 70)
write("# PART 2: FUN_00525420 -- the reader (returns DAT_011dea2a)")
write("# Already known. 27 callers check this flag.")
write("# Now find who WRITES it.")
write("#" * 70)

# Scan all refs to find WRITE references
# We need to check instruction at each ref to see if it's a read or write
write("")
write("-" * 70)
write("Classifying references to DAT_011dea2a as READ/WRITE")
write("-" * 70)

listing = currentProgram.getListing()
refs = ref_mgr.getReferencesTo(toAddr(0x011dea2a))
read_sites = []
write_sites = []
count = 0
while refs.hasNext():
	ref = refs.next()
	from_addr = ref.getFromAddress()
	rtype = str(ref.getReferenceType())
	inst = listing.getInstructionAt(from_addr)
	from_func = fm.getFunctionContaining(from_addr)
	fname = from_func.getName() if from_func else "???"
	mnemonic = inst.getMnemonicString() if inst else "???"
	inst_str = str(inst) if inst else "???"
	if "WRITE" in rtype or "MOV" in mnemonic and "011dea2a" in inst_str.lower():
		write_sites.append((from_addr.getOffset(), fname, mnemonic, inst_str))
	entry = "  %s @ 0x%08x (in %s) -- %s -- %s" % (rtype, from_addr.getOffset(), fname, mnemonic, inst_str)
	write(entry)
	count += 1
	if count > 80:
		write("  ... (truncated)")
		break

write("")
write("Total refs: %d" % count)

write("")
write("#" * 70)
write("# PART 3: Decompile ALL functions that WRITE to DAT_011dea2a")
write("# These are the functions that can lock/unlock player combat.")
write("#" * 70)

# Find writes by checking instruction mnemonics at reference sites
refs2 = ref_mgr.getReferencesTo(toAddr(0x011dea2a))
seen_funcs = set()
while refs2.hasNext():
	ref = refs2.next()
	from_addr = ref.getFromAddress()
	rtype = str(ref.getReferenceType())
	inst = listing.getInstructionAt(from_addr)
	if inst is None:
		continue
	mnemonic = inst.getMnemonicString()
	# MOV to memory = write. CMP/TEST from memory = read.
	# Also check if it's a WRITE reference type
	if "WRITE" in rtype or mnemonic == "MOV":
		# Check if DAT_011dea2a is the destination (write) or source (read)
		# For MOV, check operand 0 (destination)
		inst_str = str(inst)
		# If the address appears in the first operand of MOV, it's a write
		# Quick heuristic: if MOV and the instruction string has the address early
		from_func = fm.getFunctionContaining(from_addr)
		if from_func and from_func.getName() not in seen_funcs:
			fname = from_func.getName()
			faddr = from_func.getEntryPoint().getOffset()
			# Skip the reader function FUN_00525420
			if faddr != 0x00525420:
				seen_funcs.add(fname)
				decompile_at(faddr, "WriterOf_011dea2a_%s" % fname)

write("")
write("#" * 70)
write("# PART 4: Context around DAT_011dea2a")
write("# What other globals are nearby? This might be part of a struct.")
write("# DAT_011dea10 = player reference (DAT_011dea3c nearby)")
write("#" * 70)

def count_refs(addr_int):
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	c = 0
	while refs.hasNext():
		refs.next()
		c += 1
	return c

def print_nearby_globals():
	write("")
	write("Nearby globals in 011dea00-011deb00 range:")
	c1 = count_refs(0x011dea10)
	write("  DAT_011dea10: %d refs (known: player world ref)" % c1)
	c2 = count_refs(0x011dea3c)
	write("  DAT_011dea3c: %d refs (known: player reference)" % c2)
	write("  DAT_011dea2a offset from DAT_011dea10: +0x1a (26 bytes)")
	write("  This is likely a field in the TES/DataHandler singleton")

print_nearby_globals()

write("")
write("#" * 70)
write("# PART 5: FUN_008c7bd0 -- single-threaded AI fallback")
write("# Calls our hooked functions. When is this used instead of")
write("# the multi-threaded path (FUN_008c7da0)?")
write("#" * 70)

decompile_at(0x008c7bd0, "SingleThreadAI_008c7bd0")
find_refs_to(0x008c7bd0, "SingleThreadAI")


outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/combat_lock_global.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
