# @category Analysis
# @description Trace writers and users of ExtraOwnership.owner and ownership-related BaseExtraList helpers

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
ref_mgr = currentProgram.getReferenceManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def write(msg):
	output.append(msg)
	print(msg)

def func_for(addr_int):
	addr = toAddr(addr_int)
	func = fm.getFunctionAt(addr)
	if func is None:
		func = fm.getFunctionContaining(addr)
	return func

def name_for_func(func):
	if func is None:
		return "???"
	return "%s @ 0x%08x" % (func.getName(), func.getEntryPoint().getOffset())

def decompile_at(addr_int, label, max_len=18000):
	addr = toAddr(addr_int)
	func = func_for(addr_int)
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
		if len(code) > max_len:
			write("  [decompile truncated at %d chars]" % max_len)
	else:
		write("  [decompilation failed]")

def find_refs_to(addr_int, label, limit=140):
	write("")
	write("-" * 70)
	write("References TO 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		write("  %s @ 0x%08x (in %s)" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), name_for_func(from_func)))
		count += 1
		if count >= limit:
			write("  ... (truncated at %d)" % limit)
			break
	write("  Total printed: %d" % count)

def find_and_print_calls_from(addr_int, label, limit=220):
	func = func_for(addr_int)
	write("")
	write("-" * 70)
	write("Calls FROM %s (0x%08x)" % (label, addr_int))
	write("-" * 70)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				tgt_func = func_for(tgt)
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, name_for_func(tgt_func)))
				count += 1
				if count >= limit:
					write("  ... (truncated at %d)" % limit)
					write("  Total printed: %d" % count)
					return
	write("  Total printed: %d" % count)

def disasm_window(center_int, before_count, after_count, label):
	write("")
	write("-" * 70)
	write("Disassembly %s around 0x%08x" % (label, center_int))
	write("-" * 70)
	inst = listing.getInstructionAt(toAddr(center_int))
	if inst is None:
		inst = listing.getInstructionBefore(toAddr(center_int))
	count = 0
	while inst is not None and count < before_count:
		prev = inst.getPrevious()
		if prev is None:
			break
		inst = prev
		count += 1
	idx = 0
	limit = before_count + after_count + 1
	while inst is not None and idx < limit:
		off = inst.getAddress().getOffset()
		marker = ""
		if off == center_int:
			marker = " << target"
		write("  0x%08x: %-42s%s" % (off, inst.toString(), marker))
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				write("      call -> 0x%08x %s" % (tgt, name_for_func(func_for(tgt))))
		inst = inst.getNext()
		idx += 1

def decompile_callers(addr_int, label, limit=8):
	write("")
	write("=" * 70)
	write("Callers/ref functions for %s 0x%08x" % (label, addr_int))
	write("=" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	seen = {}
	count = 0
	while refs.hasNext():
		ref = refs.next()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		if from_func is not None:
			entry = from_func.getEntryPoint().getOffset()
			if entry not in seen:
				seen[entry] = True
				disasm_window(ref.getFromAddress().getOffset(), 12, 18, "ref to %s" % label)
				decompile_at(entry, "ref/caller for %s" % label, 10000)
				count += 1
				if count >= limit:
					write("  ... (caller decompile truncated at %d)" % limit)
					return
	write("  Total unique functions printed: %d" % count)

def scan_owner_offset_writes(limit=280):
	write("")
	write("=" * 70)
	write("Candidate owner-field writes: instruction text with [*+0x0C]")
	write("=" * 70)
	write("This is intentionally broad. Confirm candidates by surrounding create/vtable/type references.")
	inst_iter = listing.getInstructions(True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		text = inst.toString().lower()
		mnemonic = inst.getMnemonicString().lower()
		if ("+ 0xc" in text or "+0xc" in text or "+ 0x0c" in text or "+0x0c" in text) and mnemonic == "mov":
			func = fm.getFunctionContaining(inst.getAddress())
			write("  0x%08x: %-52s in %s" % (inst.getAddress().getOffset(), inst.toString(), name_for_func(func)))
			count += 1
			if count >= limit:
				write("  ... (truncated at %d)" % limit)
				break
	write("  Total printed: %d" % count)

def analyze_known_functions():
	targets = [
		(0x0042C5E0, "ExtraOwnership create/constructor candidate"),
		(0x0040FF60, "BaseExtraList::Add candidate"),
		(0x00410020, "BaseExtraList::Remove candidate"),
		(0x00410140, "BaseExtraList::RemoveByType candidate"),
		(0x00410220, "BaseExtraList::GetByType candidate"),
		(0x008BFBC1, "Stewie handle stealing crash patch site containing function"),
		(0x005785E0, "TESObjectREFR::IsOwnedByActor candidate"),
		(0x00567790, "TESObjectREFR ownership resolver candidate"),
		(0x004BED60, "Current crashing save handler"),
		(0x00865DF0, "Current crashing save-field helper")
	]
	idx = 0
	while idx < len(targets):
		item = targets[idx]
		decompile_at(item[0], item[1], 22000)
		disasm_window(item[0], 8, 32, item[1])
		find_and_print_calls_from(item[0], item[1], 140)
		idx += 1

def analyze_refs():
	refs = [
		(0x0042C5E0, "ExtraOwnership create/constructor candidate"),
		(0x0040FF60, "BaseExtraList::Add candidate"),
		(0x00410220, "BaseExtraList::GetByType candidate"),
		(0x008BFBC1, "Stewie handle stealing patch site"),
		(0x005785E0, "IsOwnedByActor candidate"),
		(0x00567790, "Ownership resolver candidate")
	]
	idx = 0
	while idx < len(refs):
		item = refs[idx]
		find_refs_to(item[0], item[1], 160)
		decompile_callers(item[0], item[1], 6)
		idx += 1

def main():
	write("=" * 70)
	write("EXTRAOWNERSHIP OWNER WRITE PROVENANCE AUDIT")
	write("=" * 70)
	write("Goal: identify where owner is written/read and whether 0x00000007 can come from save data, list links, or corrupted/stale extra data.")
	analyze_known_functions()
	analyze_refs()
	scan_owner_offset_writes(300)
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/extraownership_owner_write_provenance_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
