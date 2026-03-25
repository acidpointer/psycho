# @category Analysis
# @description Trace player attack -> hit -> damage application path. Find why player can't damage enemies.

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
write("PLAYER DAMAGE PATH ANALYSIS")
write("Why can't player damage enemies? Companion can.")
write("=" * 70)

write("")
write("#" * 70)
write("# PART 1: FUN_005f2b60 -- combat hit processing (from crash stack)")
write("# Called from FUN_00493686 -> FUN_005672B4 -> FUN_008880C3")
write("# This is the AI worker combat path. Player may use different path.")
write("#" * 70)

decompile_at(0x005f2b60, "CombatHitProcess_005f2b60")
find_refs_to(0x005f2b60, "CombatHitProcess")

write("")
write("#" * 70)
write("# PART 2: FUN_00837cc0 -- hit detection function")
write("# Contains the crash site: calls FUN_009306d0 (GetActorProcess)")
write("# then FUN_00838750 (check process+0x410 flags)")
write("# Who calls this? AI only or also main thread?")
write("#" * 70)

find_refs_to(0x00837cc0, "HitDetection_00837cc0")

write("")
write("#" * 70)
write("# PART 3: FUN_00493686 -- in crash stack between hit processing")
write("# Decompile the containing function to understand context")
write("#" * 70)

decompile_at(0x00493686, "CrashStack_00493686")

write("")
write("#" * 70)
write("# PART 4: FUN_005672B4 -- animation/combat dispatch")
write("# Another crash stack frame. How does it route to hit processing?")
write("#" * 70)

decompile_at(0x005672B4, "AnimCombatDispatch_005672B4")
find_refs_to(0x00567290, "AnimCombatDispatch_container")

write("")
write("#" * 70)
write("# PART 5: Player attack entry points")
write("# FUN_008a1800 -- seen in combat code (called from FUN_00888070)")
write("# Might be 'start attack' or 'apply hit'. Check what it does.")
write("#" * 70)

decompile_at(0x008a1800, "AttackStart_008a1800")
find_refs_to(0x008a1800, "AttackStart")

write("")
write("#" * 70)
write("# PART 6: FUN_0089f580 -- also called from combat code")
write("# Called after attack sequence in FUN_00888070")
write("#" * 70)

decompile_at(0x0089f580, "PostAttack_0089f580")
find_refs_to(0x0089f580, "PostAttack")

write("")
write("#" * 70)
write("# PART 7: Health modification -- who modifies actor health?")
write("# Look for functions that modify actor's health/damage values.")
write("# FUN_0049bdc0 -- called from combat code with damage float")
write("#" * 70)

decompile_at(0x0049bdc0, "ApplyDamage_0049bdc0")
find_refs_to(0x0049bdc0, "ApplyDamage")

write("")
write("#" * 70)
write("# PART 8: Main thread hit processing")
write("# FUN_00493900 -- called from FUN_00888070 after player attack")
write("# param_1 = weapon, param_2 = actor")
write("#" * 70)

decompile_at(0x00493900, "WeaponHit_00493900")
find_refs_to(0x00493900, "WeaponHit")


outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/player_damage_path.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
