# @category Analysis
# @description Find ALL callers of FUN_005d4a30 (combat lock setter) and FUN_0086f670 (combat lock clearer). Who locks/unlocks player combat?

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

def decompile_callers(target_addr, label):
	write("")
	write("-" * 70)
	write("Decompiling ALL callers of 0x%08x (%s)" % (target_addr, label))
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(target_addr))
	seen = set()
	while refs.hasNext():
		ref = refs.next()
		if not ref.getReferenceType().isCall():
			continue
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		if from_func is None:
			continue
		faddr = from_func.getEntryPoint().getOffset()
		if faddr in seen:
			continue
		seen.add(faddr)
		fname = from_func.getName()
		decompile_at(faddr, "Caller_%s_%08x" % (label, faddr))


write("=" * 70)
write("COMBAT LOCK CALLERS -- WHO LOCKS/UNLOCKS PLAYER COMBAT?")
write("=" * 70)

write("")
write("#" * 70)
write("# PART 1: All callers of FUN_005d4a30 (the SETTER)")
write("# FUN_005d4a30(param_1) sets DAT_011dea2a = param_1")
write("# param_1 != 0 => combat LOCKED (player can't attack)")
write("# param_1 == 0 => combat UNLOCKED")
write("#" * 70)

find_refs_to(0x005d4a30, "CombatLockSetter")
decompile_callers(0x005d4a30, "Setter")

write("")
write("#" * 70)
write("# PART 2: All callers of FUN_0086f670 (the CLEARER)")
write("# FUN_0086f670 sets DAT_011dea2a = 0 (always clears)")
write("# Also clears DAT_012682f8 and DAT_011df678")
write("#" * 70)

find_refs_to(0x0086f670, "CombatLockClearer")
decompile_callers(0x0086f670, "Clearer")


outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/combat_lock_callers.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
