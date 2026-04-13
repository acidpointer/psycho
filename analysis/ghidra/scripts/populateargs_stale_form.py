# @category Analysis
# @description Trace PopulateArgs crash: what EXACTLY does it read from the
# stale TESObjectCELL* that jip_nvse passes as lastCell?
#
# xNVSE source (FunctionScripts.cpp:547):
#   case Script::eVarType_Ref:
#     TESForm* form = (TESForm*)m_args[i];
#     *((UInt32*)&var->data) = form ? form->refID : 0;
#
# form->refID is at TESForm+0x0C. If the cell form itself is freed and
# its slab cell recycled, offset 0x0C has garbage -> crash.
#
# But TESObjectCELL forms might NOT be freed during unload. They might
# stay in the form table just marked as detached. Need to trace the
# cell lifecycle through unload.

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
write("# POPULATEARGS STALE FORM ANALYSIS")
write("# What does PopulateArgs read from the stale lastCell?")
write("# Is the TESObjectCELL form itself freed, or just its sub-data?")
write("######################################################################")


write("")
write("######################################################################")
write("# PART 1: TESObjectCELL lifecycle during cell unload")
write("# When a cell is unloaded, is the TESObjectCELL form freed?")
write("# Or does it stay in the form table (just marked detached)?")
write("# FUN_00462290 = DestroyCell. Does it free the cell form?")
write("######################################################################")

decompile_at(0x00462290, "DestroyCell")
find_and_print_calls_from(0x00462290, "DestroyCell")


write("")
write("######################################################################")
write("# PART 2: TESObjectCELL vtable/RTTI")
write("# vtable at 0x0102E9B4. Find destructor.")
write("# Does the destructor go through game heap (our slab)?")
write("######################################################################")

find_refs_to(0x0102E9B4, "TESObjectCELL_vtable")


write("")
write("######################################################################")
write("# PART 3: What is at TESForm+0x0C (refID)?")
write("# PopulateArgs reads form->refID. If the cell form is NOT freed")
write("# but some sub-object at a deeper offset is freed, the crash")
write("# could be from a DIFFERENT read, not refID itself.")
write("# ECX=4 in the crash. What instruction loads 4 into ECX?")
write("######################################################################")

write("")
write("# ECX=4 could mean:")
write("# 1. form->refID = 4 (refID is a small number - impossible for a cell)")
write("# 2. The crash is at a DIFFERENT point in PopulateArgs, not refID read")
write("# 3. The form pointer itself is 4 (m_args[i] = 4, not a valid pointer)")
write("")
write("# If m_args[i] = lastCell = 4, then lastCell was overwritten with 4.")
write("# jip_nvse stores lastCell in a static variable. If another piece of")
write("# code writes to the same memory location (data race or corruption)")
write("# lastCell could be overwritten with a small integer.")
write("")
write("# OR: lastCell IS a valid pointer but PopulateArgs dereferences it")
write("# at some offset and gets 4. ECX=4 might be the RESULT of reading")
write("# from the stale cell, not the pointer itself.")


write("")
write("######################################################################")
write("# PART 4: The CallFunction path from jip_nvse")
write("# LN_ProcessEvents calls CallFunction(callback, nullptr, 1, lastCell)")
write("# How does CallFunction pass lastCell to PopulateArgs?")
write("# Is it m_args[0] = lastCell?")
write("######################################################################")

write("")
write("# From jip_nvse source (lutana.h:355):")
write("# CallFunction(data().callback, nullptr, 1, lastCell)")
write("# This is PluginAPI::CallFunctionScriptAlt()")
write("# which creates InternalFunctionCaller with m_args[0] = lastCell")
write("# PopulateArgs reads m_args[0] as TESForm* form")
write("# Then reads form->refID (at form+0x0C)")


write("")
write("######################################################################")
write("# PART 5: g_thePlayer->parentCell - where lastCell comes from")
write("# jip_nvse (lutana.h:339): currCell = g_thePlayer->parentCell")
write("# If parentCell pointer itself is stale...")
write("# What is the offset of parentCell in TESObjectREFR/PlayerCharacter?")
write("######################################################################")

write("")
write("# From xNVSE GameObjects.h:")
write("# TESObjectREFR+0x060 = parentCell (TESObjectCELL*)")
write("# PlayerCharacter inherits from Actor which inherits from TESObjectREFR")
write("")
write("# g_thePlayer is at 0x011DEA3C+offset or a separate global.")
write("# The player's parentCell should always be valid during gameplay.")
write("# But during cell transition, parentCell is updated to the new cell.")
write("# lastCell = the PREVIOUS parentCell. If that cell was freed...")


write("")
write("######################################################################")
write("# PART 6: Is the TESObjectCELL actually freed through our slab?")
write("# Search for calls to GameHeap::Free (0x00AA4060) from cell-related")
write("# code. If cells are freed through the game heap, they go through")
write("# our slab. If they are reference-counted, they are freed when")
write("# refcount hits 0 -> PDD -> our free.")
write("######################################################################")

decompile_at(0x00451530, "Cell_ShouldLoadCheck")
decompile_at(0x00452580, "Cell_LoadQueue_AddCell")


write("")
write("######################################################################")
write("# PART 7: PDD Form queue - does it process TESObjectCELL?")
write("# DAT_011de828 = Form queue. Does cell unload add cells to it?")
write("# If so, PDD frees the cell form -> slab recycles -> crash")
write("######################################################################")

decompile_at(0x00868D10, "PDD_FormQueue_Drain")
find_and_print_calls_from(0x00868D10, "PDD_FormQueue_Drain")


outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/populateargs_stale_form.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
