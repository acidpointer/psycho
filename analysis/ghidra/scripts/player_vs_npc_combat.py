# @category Analysis
# @description Compare player attack path vs NPC/companion attack path. Find where player damage is blocked.

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
write("PLAYER vs NPC COMBAT PATH COMPARISON")
write("Player can't damage enemies. Companion can. Why?")
write("=" * 70)

write("")
write("#" * 70)
write("# PART 1: Main thread weapon fire / melee attack entry")
write("# When player attacks, main thread processes the input.")
write("# FUN_00524db0 -- looks like player action handler (calls GetActorProcess)")
write("# From actor_process_race refs: 0x00525036, 0x0052504d in FUN_00524db0")
write("#" * 70)

decompile_at(0x00524db0, "PlayerAction_00524db0")
find_refs_to(0x00524db0, "PlayerAction")

write("")
write("#" * 70)
write("# PART 2: Main thread combat controller")
write("# FUN_008190d0 -- refs to GetActorProcess at 0x008191ac, 0x008191b8")
write("# Could be main thread combat processing for player")
write("#" * 70)

decompile_at(0x008190d0, "MainCombatCtrl_008190d0")
find_refs_to(0x008190d0, "MainCombatCtrl")

write("")
write("#" * 70)
write("# PART 3: FUN_0094a0c0 -- heavy combat function")
write("# Refs to GetActorProcess at multiple points (0x0094a2e1, etc)")
write("# 5 GetActorProcess calls = lots of process state reading")
write("#" * 70)

decompile_at(0x0094a0c0, "HeavyCombat_0094a0c0", max_len=12000)
find_refs_to(0x0094a0c0, "HeavyCombat")

write("")
write("#" * 70)
write("# PART 4: FUN_006214d0 -- combat with GetActorProcess ref")
write("# Another function reading actor process during combat")
write("#" * 70)

decompile_at(0x006214d0, "CombatProcess_006214d0")
find_refs_to(0x006214d0, "CombatProcess")

write("")
write("#" * 70)
write("# PART 5: FUN_0095f930 -- combat with GetActorProcess")
write("# Large combat function (ref at 0x0095ffcd)")
write("#" * 70)

decompile_at(0x0095f930, "CombatLarge_0095f930", max_len=10000)
find_refs_to(0x0095f930, "CombatLarge")

write("")
write("#" * 70)
write("# PART 6: Player-specific: DAT_011dea3c (player reference)")
write("# In FUN_00837cc0: 'if (param_1 == DAT_011dea3c)'")
write("# This is the player check. What special handling exists?")
write("# FUN_00524d10 -- called when param_1 IS the player")
write("#" * 70)

decompile_at(0x00524d10, "IsPlayerCheck_00524d10")
find_refs_to(0x00524d10, "IsPlayerCheck")

write("")
write("#" * 70)
write("# PART 7: FUN_005a2030 -- called from FUN_00837cc0")
write("# cVar2 = FUN_005a2030((int)local_5c)")
write("# If returns non-zero, local_79 stays 0 affecting hit logic")
write("#" * 70)

decompile_at(0x005a2030, "CombatCondition_005a2030")
find_refs_to(0x005a2030, "CombatCondition")

write("")
write("#" * 70)
write("# PART 8: FUN_00425fd0 and FUN_004518e0 -- target validation")
write("# Called from FUN_00837cc0 to validate hit target")
write("# bVar1 = FUN_00425fd0((int)local_84)")
write("# bVar1 = FUN_004518e0((int)local_84)")
write("#" * 70)

decompile_at(0x00425fd0, "TargetValidate1_00425fd0")
decompile_at(0x004518e0, "TargetValidate2_004518e0")

write("")
write("#" * 70)
write("# PART 9: Main thread weapon hit raycast")
write("# How does the engine detect that a player's weapon/bullet")
write("# actually hit the target? Raycast from player?")
write("# FUN_0057b0a0 -- distance check, called from combat with actor")
write("#" * 70)

decompile_at(0x0057b0a0, "DistanceCheck_0057b0a0")
find_refs_to(0x0057b0a0, "DistanceCheck")

write("")
write("#" * 70)
write("# PART 10: FUN_00884730 -- combat state check")
write("# Called from FUN_00837cc0: if FUN_00884730(actor) != 0")
write("# Affects the local_6c combat result value (3 vs other)")
write("#" * 70)

decompile_at(0x00884730, "CombatState_00884730")
find_refs_to(0x00884730, "CombatState")


outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/player_vs_npc_combat.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
