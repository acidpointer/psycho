# @category Analysis
# @description Investigate why player attacks don't register. Focus on gate functions that block damage.

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
		if count > 40:
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
write("PLAYER ATTACK GATE FUNCTIONS")
write("Why do player attacks not register?")
write("=" * 70)

write("")
write("#" * 70)
write("# PART 1: FUN_00525420 -- combat lock check")
write("# In FUN_00524db0: if FUN_00525420() != 0, skip attack")
write("# What is this checking? Slow-mo? VATS? Combat freeze?")
write("#" * 70)

decompile_at(0x00525420, "CombatLock_00525420")
find_refs_to(0x00525420, "CombatLock")

write("")
write("#" * 70)
write("# PART 2: FUN_00950be0 -- player-specific process getter")
write("# Called with DAT_011dea3c (player ref). Gets combat data.")
write("# What does it return? Is it the same as GetActorProcess?")
write("#" * 70)

decompile_at(0x00950be0, "PlayerProcessGet_00950be0")
find_refs_to(0x00950be0, "PlayerProcessGet")

write("")
write("#" * 70)
write("# PART 3: FUN_004aae30 -- weapon/attack data getter")
write("# Called as FUN_004aae30(process, 0x102cb00)")
write("# Returns attack data ptr. If 0, no attack created.")
write("# What does it need from the process?")
write("#" * 70)

decompile_at(0x004aae30, "WeaponDataGet_004aae30")
find_refs_to(0x004aae30, "WeaponDataGet")

write("")
write("#" * 70)
write("# PART 4: FUN_0048cee0 -- combat controller getter")
write("# Called from player attack path: FUN_0048cee0(FUN_004600d0(this))")
write("# If returns 0, entire attack is skipped")
write("#" * 70)

decompile_at(0x0048cee0, "CombatCtrl_0048cee0")
decompile_at(0x004600d0, "WeaponGet_004600d0")

write("")
write("#" * 70)
write("# PART 5: FUN_00682c40 -- projectile/hit object creation")
write("# Creates the hit event. If this isn't called, no damage.")
write("# What are the params and what gates it?")
write("#" * 70)

decompile_at(0x00682c40, "ProjectileCreate_00682c40")
find_refs_to(0x00682c40, "ProjectileCreate")

write("")
write("#" * 70)
write("# PART 6: FUN_007e6580 -- hit event dispatch")
write("# Called after projectile creation in player attack path")
write("# Dispatches hit to damage system")
write("#" * 70)

decompile_at(0x007e6580, "HitDispatch_007e6580")
find_refs_to(0x007e6580, "HitDispatch")

write("")
write("#" * 70)
write("# PART 7: FUN_00523150 -- main caller of player attack")
write("# One of 2 callers of FUN_00524db0. Larger context.")
write("# This is the weapon use handler (fire/swing)")
write("#" * 70)

decompile_at(0x00523150, "WeaponUseHandler_00523150", max_len=12000)
find_and_print_calls_from(0x00523150, "WeaponUseHandler")

write("")
write("#" * 70)
write("# PART 8: FUN_00525430 -- third-person check?")
write("# Called from player attack: FUN_00525430(0x11f2250)")
write("# Affects which damage multiplier is used")
write("#" * 70)

decompile_at(0x00525430, "ThirdPersonCheck_00525430")

write("")
write("#" * 70)
write("# PART 9: FUN_004eaf60 -- another player gate")
write("# if param_1 == player && FUN_004eaf60(player) == 0")
write("# && !FUN_00525430 => different projectile creation")
write("#" * 70)

decompile_at(0x004eaf60, "PlayerGate_004eaf60")

write("")
write("#" * 70)
write("# PART 10: Who calls FUN_0096cca0 and FUN_0096cda0?")
write("# Are they ONLY called from Worker 1, or also main thread?")
write("# If main thread calls them too, our hooks affect main thread.")
write("#" * 70)

find_refs_to(0x0096cca0, "ActorIterate1")
find_refs_to(0x0096cda0, "ActorIterate2")
find_refs_to(0x009784c0, "ProcessMgrUpdate")
find_refs_to(0x0096e870, "ActorDowngrade")


outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/player_attack_gates.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
