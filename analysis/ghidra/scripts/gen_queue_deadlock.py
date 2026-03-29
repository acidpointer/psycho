# @category Analysis
# @description Research Gen queue deadlock -- why 7000+ entries cause permanent
#   freeze during PDD drain. Find hookable points to limit per-call processing.
#
# The game hard-freezes when blocking PDD (FUN_00868d70) processes 7000+
# Gen entries. Not a timeout -- permanent freeze. Either a deadlock in
# a destructor chain or infinite loop from corrupted memory.
#
# Questions:
#   1. FUN_00868d70 Gen queue loop -- exact code, where is the iteration?
#   2. What virtual function is called for each Gen entry? (vtable[4])
#   3. Can a Gen entry's destructor re-enter PDD? (reentrancy deadlock)
#   4. Can a Gen entry's destructor acquire a lock that PDD already holds?
#   5. What is the Gen entry type? What objects go into the Generic queue?
#   6. FUN_00868850 (per-frame drain) Gen loop -- same or different path?
#   7. Where can we hook to add a per-call limit on Gen processing?
#   8. FUN_0086f940 (cell transition checker) -- does it call blocking PDD?
#   9. What locks does CellTransition hold when calling PDD?

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def write(msg):
	output.append(msg)
	print(msg)

def decompile_at(addr_int, label, max_len=12000):
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
	fsize = func.getBody().getNumAddresses()
	write("  Function: %s @ 0x%08x, Size: %d bytes" % (func.getName(), faddr, fsize))
	if faddr != addr_int:
		write("  NOTE: Requested 0x%08x is inside %s (entry at 0x%08x)" % (addr_int, func.getName(), faddr))
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		if len(code) > max_len:
			write(code[:max_len])
			write("  ... [truncated at %d chars]" % max_len)
		else:
			write(code)
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
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, name))
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
		if count > 50:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)


write("Gen Queue Deadlock Research")
write("=" * 70)

# ===================================================================
# PART 1: Full PDD drain -- the Gen queue processing loop
# ===================================================================
write("")
write("#" * 70)
write("# PART 1: Full PDD Drain (FUN_00868d70) -- Gen queue loop")
write("#" * 70)
write("# From earlier research, the Gen queue (0x11de874) is processed")
write("# with a 'while count != 0' loop calling vtable[4] on each entry.")
write("# The loop for Generic queue in full PDD:")
write("#   uVar4 = FUN_00869180(1);  // check skip mask")
write("#   if ((uVar4 & 0xff) == 0) && FUN_00868250(...)) {")
write("#     while (count != 0) { vtable[0x10] on entry; }")
write("#   }")

# Already decompiled but let's get it again focused on the Gen loop
decompile_at(0x00868d70, "Full PDD drain (focus on Gen loop)", 20000)

# ===================================================================
# PART 2: Per-frame PDD drain -- Gen queue processing
# ===================================================================
write("")
write("#" * 70)
write("# PART 2: Per-frame PDD drain (FUN_00868850) -- Gen queue section")
write("#" * 70)
write("# Per-frame drain has rate limiting. What is the Gen limit?")

decompile_at(0x00868850, "Per-frame PDD drain (Gen section)", 20000)

# ===================================================================
# PART 3: What are Gen queue entries? What is vtable[4]?
# ===================================================================
write("")
write("#" * 70)
write("# PART 3: Gen Queue Entry Type")
write("#" * 70)
write("# Gen entries have vtable. vtable[4] = offset 0x10 = destructor/process.")
write("# What types of objects go into the Generic queue?")
write("# From per-frame PDD: (**(code **)(*(int *)*piVar7 + 0x10))(1);")

# FUN_008693c0 adds to PDD queues. Who calls it for Gen queue?
# Gen queue is at 0x11de874. FUN_00867f90 processes queue additions.
decompile_at(0x00867f90, "PDD queue router (FUN_00867f90)")
find_and_print_calls_from(0x00867f90, "PDD queue router")

# FUN_00868330 and FUN_00868560 also add to queues
decompile_at(0x00868330, "PDD queue add path 1 (FUN_00868330)")
decompile_at(0x00868560, "PDD queue add path 2 (FUN_00868560)")

# ===================================================================
# PART 4: FUN_00868250 -- the gate function for Generic queue
# ===================================================================
write("")
write("#" * 70)
write("# PART 4: PDD Gate (FUN_00868250)")
write("#" * 70)

decompile_at(0x00868250, "PDD processing gate")
decompile_at(0x008691b0, "FUN_008691b0 (called by gate)")

# ===================================================================
# PART 5: Can Gen destructors re-enter PDD or acquire PDD lock?
# ===================================================================
write("")
write("#" * 70)
write("# PART 5: Reentrancy Check")
write("#" * 70)
write("# DAT_011de958 = reentrancy guard. Set to 1 during PDD.")
write("# If a Gen destructor calls a function that enters PDD...")

find_refs_to(0x011de958, "PDD reentrancy guard readers/writers")

# FUN_00867f50 = blocking PDD lock. Who calls it?
find_refs_to(0x00867f50, "Blocking PDD lock acquire callers")

# FUN_00867f70 = try PDD lock. Who calls it?
find_refs_to(0x00867f70, "Try PDD lock acquire callers")

# ===================================================================
# PART 6: FUN_0086f940 -- cell transition checker
# ===================================================================
write("")
write("#" * 70)
write("# PART 6: Cell Transition Checker (FUN_0086f940)")
write("#" * 70)
write("# Does it call blocking PDD directly?")

decompile_at(0x0086f940, "Cell transition checker", 16000)
find_and_print_calls_from(0x0086f940, "Cell transition checker")

# FUN_0093bea0 -- the conditional transition function
decompile_at(0x0093bea0, "Conditional cell transition")
find_and_print_calls_from(0x0093bea0, "Conditional cell transition")

# ===================================================================
# PART 7: FUN_00564d80 -- Gen entry processing check
# ===================================================================
write("")
write("#" * 70)
write("# PART 7: Gen Entry Check (FUN_00564d80)")
write("#" * 70)
write("# Per-frame drain checks FUN_00564d80 before processing a Gen entry.")
write("# What does it check? Can it cause a skip?")

decompile_at(0x00564d80, "Gen entry check (before vtable call)")

# ===================================================================
# PART 8: What does FUN_004aaf10 do after Gen processing?
# ===================================================================
write("")
write("#" * 70)
write("# PART 8: Post-Gen-Processing")
write("#" * 70)

decompile_at(0x004aaf10, "Post-Gen processing (FUN_004aaf10)")
decompile_at(0x004afba0, "FUN_004afba0 (called by post-Gen)")

# ===================================================================
# PART 9: FUN_008782b0 -- vanilla per-frame cleanup internals
# ===================================================================
write("")
write("#" * 70)
write("# PART 9: Vanilla Cleanup (FUN_008782b0)")
write("#" * 70)
write("# Does it call blocking or try PDD?")

decompile_at(0x008782b0, "Vanilla per-frame cleanup")
find_and_print_calls_from(0x008782b0, "Vanilla per-frame cleanup")


write("")
write("=" * 70)
write("ANALYSIS COMPLETE")
write("=" * 70)

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/gen_queue_deadlock.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
