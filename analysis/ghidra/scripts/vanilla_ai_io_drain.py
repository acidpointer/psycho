# @category Analysis
# @description Trace FUN_00877700 (called before StopHavok_DrainAI in CellTransitionHandler) and FUN_00ad88f0/FUN_00ad8d10 (IO drain called by StopHavok). These are the vanilla AI+IO drain mechanisms that destruction_protocol should replicate.

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
	write(
		"  Function: %s @ 0x%08x, Size: %d bytes"
		% (func.getName(), faddr, func.getBody().getNumAddresses())
	)
	if faddr != addr_int:
		write(
			"  NOTE: Requested 0x%08x is inside %s (entry at 0x%08x)"
			% (addr_int, func.getName(), faddr)
		)
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
				write(
					"  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, name)
				)
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
		write(
			"  %s @ 0x%08x (in %s)"
			% (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname)
		)
		count += 1
		if count > 40:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)


# ======================================================================
write("VANILLA AI+IO DRAIN MECHANISM ANALYSIS")
write("Goal: What does FUN_00877700 do? Can destruction_protocol call it?")
write("      What do FUN_00ad88f0 and FUN_00ad8d10 drain?")
write("=" * 70)

# SECTION 1: FUN_00877700 — called before StopHavok in CellTransitionHandler
write("")
write("#" * 70)
write("# SECTION 1: FUN_00877700 — AI drain before StopHavok_DrainAI")
write("# CellTransitionHandler calls this at 0x008774e0 before StopHavok")
write("#" * 70)

decompile_at(0x00877700, "FUN_00877700_PreStopHavok")
find_and_print_calls_from(0x00877700, "FUN_00877700_PreStopHavok")
find_refs_to(0x00877700, "FUN_00877700_PreStopHavok")

# SECTION 2: FUN_00ad88f0 — IO queue drain (called by StopHavok_DrainAI)
write("")
write("#" * 70)
write("# SECTION 2: FUN_00ad88f0 — IO queue drain")
write("# Called twice by StopHavok_DrainAI with DAT_011dd5bc and DAT_011dd638")
write("#" * 70)

decompile_at(0x00AD88F0, "IO_QueueDrain")
find_and_print_calls_from(0x00AD88F0, "IO_QueueDrain")

# SECTION 3: FUN_00ad8d10 — second IO drain call
write("")
write("#" * 70)
write("# SECTION 3: FUN_00ad8d10 — second IO drain")
write("# Called after FUN_00ad88f0 by StopHavok_DrainAI")
write("#" * 70)

decompile_at(0x00AD8D10, "IO_QueueDrain2")
find_and_print_calls_from(0x00AD8D10, "IO_QueueDrain2")

# SECTION 4: FUN_00830ad0 — checked by StopHavok_DrainAI param_1=0 path
write("")
write("#" * 70)
write("# SECTION 4: FUN_00830ad0 — condition check in StopHavok path 0")
write("# If this returns non-zero, FUN_008304a0+FUN_008325a0(0) are called")
write("#" * 70)

decompile_at(0x00830AD0, "StopHavok_ConditionCheck")

# SECTION 5: FUN_00830490 — called by FUN_008300c0 (the wait function)
write("")
write("#" * 70)
write("# SECTION 5: FUN_00830490 — called after wait in FUN_008300c0")
write("# What does this do? Release a lock?")
write("#" * 70)

decompile_at(0x00830490, "FUN_00830490")

# SECTION 6: FUN_00830470 — called by FUN_008304a0
write("")
write("#" * 70)
write("# SECTION 6: FUN_00830470 — called by StopHavok_Step1")
write("#" * 70)

decompile_at(0x00830470, "FUN_00830470")

# SECTION 7: FUN_0082fa30 — called by StopHavok_Step1
write("")
write("#" * 70)
write("# SECTION 7: FUN_0082fa30 — called by StopHavok_Step1")
write("#" * 70)

decompile_at(0x0082FA30, "FUN_0082fa30")

# SECTION 8: What is DAT_011dd5bc and DAT_011dd638?
write("")
write("#" * 70)
write("# SECTION 8: DAT_011dd5bc and DAT_011dd638 — IO manager queue pointers?")
write("# Passed to FUN_00ad88f0/FUN_00ad8d10 by StopHavok_DrainAI")
write("#" * 70)

find_refs_to(0x011DD5BC, "DAT_011dd5bc")
find_refs_to(0x011DD638, "DAT_011dd638")

# SECTION 9: FUN_004f1540 and FUN_004f15a0 — called at start of CellTransitionHandler
write("")
write("#" * 70)
write("# SECTION 9: FUN_004f1540/FUN_004f15a0 — save/restore state")
write("# Called at start of CellTransitionHandler before all cleanup")
write("#" * 70)

decompile_at(0x004F1540, "SaveState")
decompile_at(0x004F15A0, "SetState")

# SECTION 10: Can destruction_protocol call FUN_00877700?
write("")
write("#" * 70)
write("# SECTION 10: Compatibility check")
write("# Does FUN_00877700 require any state that destruction_protocol")
write("# doesn't have? Does it conflict with pre_destruction_setup?")
write("#" * 70)

decompile_at(0x00877700, "FUN_00877700_DEEP", 12000)

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/vanilla_ai_io_drain.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
