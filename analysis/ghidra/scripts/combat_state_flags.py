# @category Analysis
# @description Analyze combat state flags at HighProcess+0x410. What sets/clears them, what reads them.

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
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		fname = from_func.getName() if from_func else "???"
		write("  %s @ 0x%08x (in %s)" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname))
		count += 1
		if count > 60:
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
write("COMBAT STATE FLAGS ANALYSIS (HighProcess+0x410)")
write("=" * 70)

write("")
write("#" * 70)
write("# PART 1: FUN_00621270 -- reads flags at this+4")
write("# Called as FUN_00621270(process+0x410, mask)")
write("# Returns *(process+0x414) & mask")
write("# What is the structure at +0x410?")
write("#" * 70)

decompile_at(0x00621270, "ReadFlags_00621270")
find_refs_to(0x00621270, "ReadFlags")

write("")
write("#" * 70)
write("# PART 2: FUN_00838750 -- combat flag check")
write("# Checks if flag 0x1000000 is set at process+0x410")
write("# Called from hit detection. What does this flag mean?")
write("#" * 70)

decompile_at(0x00838750, "CombatFlagCheck_00838750")
find_refs_to(0x00838750, "CombatFlagCheck")

write("")
write("#" * 70)
write("# PART 3: FUN_0059bb30 -- combat state reader")
write("# Called from FUN_00837cc0 with process+0x410 as arg")
write("# Returns a combat state value (compared to 0x24)")
write("#" * 70)

decompile_at(0x0059bb30, "CombatStateRead_0059bb30")
find_refs_to(0x0059bb30, "CombatStateRead")

write("")
write("#" * 70)
write("# PART 4: Who WRITES to the combat state structure?")
write("# Look for functions that SET flags at +0x410/+0x414")
write("# FUN_00621270 is a reader. Find the corresponding writer.")
write("#" * 70)

# The writer would be something like *(process+0x414) |= mask or = value
# Look for partner function -- FUN_00621290? or nearby
decompile_at(0x00621290, "WriteFlags_00621290_guess1")
decompile_at(0x006212a0, "WriteFlags_006212a0_guess2")
decompile_at(0x006212b0, "WriteFlags_006212b0_guess3")
decompile_at(0x006212c0, "WriteFlags_006212c0_guess4")

write("")
write("#" * 70)
write("# PART 5: FUN_009611e0 -- called from FUN_00888070 (AI combat)")
write("# Called right after getting process via vtable+0x1d0")
write("# Could be 'is in combat' or 'get combat controller'")
write("#" * 70)

decompile_at(0x009611e0, "CombatCheck_009611e0")
find_refs_to(0x009611e0, "CombatCheck")

write("")
write("#" * 70)
write("# PART 6: FUN_00567050 -- called early in AI combat processing")
write("# First call after the combat check in FUN_00888070")
write("#" * 70)

decompile_at(0x00567050, "EarlyCombat_00567050")
find_refs_to(0x00567050, "EarlyCombat")

write("")
write("#" * 70)
write("# PART 7: What sets 0x1000000 flag? Scan for OR with 0x1000000")
write("# on HighProcess combat state. This tells us what ENABLES combat.")
write("#" * 70)

# Look for the function that sets bit 0x1000000 in the combat flags
# The reader at FUN_00621270 does: return *(this+4) & param_1
# The setter would do: *(this+4) |= param_1 or *(this+4) = value
# Search for functions near 0x00621270 that WRITE to (this+4)

decompile_at(0x00621240, "NearbyFunc_00621240")
decompile_at(0x00621250, "NearbyFunc_00621250")
decompile_at(0x00621260, "NearbyFunc_00621260")

write("")
write("#" * 70)
write("# PART 8: HighProcess vtable +0x41c")
write("# Called from FUN_00888070: (**(process_vtable + 0x41c))(actor)")
write("# This is called during AI combat processing. What does it do?")
write("# If the vtable is at a known address, find this slot.")
write("#" * 70)

# HighProcess vtable is at 0x01087864 (from crash dump)
# Slot +0x41c / 4 = slot 0x107 (263rd entry)
# Read what's at vtable + 0x41c
write("  HighProcess vtable: 0x01087864 (from crash dump)")
write("  Slot +0x41c = vtable entry at 0x01087864 + 0x41c = 0x01087C80")

listing = currentProgram.getListing()
vtable_slot = toAddr(0x01087864 + 0x41c)
data = listing.getDataAt(vtable_slot)
if data is not None:
	write("  Data at vtable slot: %s" % data)
else:
	# Try reading raw bytes
	mem = currentProgram.getMemory()
	try:
		val = mem.getInt(vtable_slot)
		write("  Raw value at 0x%08x: 0x%08x" % (vtable_slot.getOffset(), val & 0xFFFFFFFF))
		decompile_at(val & 0xFFFFFFFF, "HighProcess_vtable_0x41c")
	except:
		write("  [could not read vtable slot]")


outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/combat_state_flags.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
