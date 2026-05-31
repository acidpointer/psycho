# @category Analysis
# @description Audit save path from Famine Box TESObjectREFR context into ExtraOwnership serialization crash

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

def find_refs_to(addr_int, label, limit=120):
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

def analyze_path_functions():
	targets = [
		(0x00562230, "TESObjectREFR save/change-data function candidate"),
		(0x004D4090, "extra-data list save dispatcher candidate"),
		(0x004BED60, "ExtraOwnership save handler candidate"),
		(0x00865DF0, "form/value save-field helper"),
		(0x0084E3A0, "form-id/type helper called with ECX=0x7"),
		(0x004BF220, "nearby extra-data save helper candidate"),
		(0x00484D60, "save/change-data helper candidate"),
		(0x004280F0, "save buffer helper candidate"),
		(0x00428110, "save buffer helper candidate"),
		(0x00426A30, "loop body save helper used by 0x004BED60"),
		(0x006815C0, "iterator/list helper used by 0x004BED60"),
		(0x00726070, "iterator/list next helper used by 0x004BED60")
	]
	idx = 0
	while idx < len(targets):
		item = targets[idx]
		decompile_at(item[0], item[1], 22000)
		find_and_print_calls_from(item[0], item[1], 180)
		idx += 1

def analyze_path_windows():
	windows = [
		(0x00562305, "runtime caller 0x00562305"),
		(0x004D4112, "runtime caller 0x004D4112"),
		(0x004BEDCC, "runtime caller 0x004BEDCC"),
		(0x00865DFB, "fault 0x00865DFB")
	]
	idx = 0
	while idx < len(windows):
		item = windows[idx]
		disasm_window(item[0], 48, 58, item[1])
		idx += 1

def analyze_refs():
	targets = [
		(0x00562230, "TESObjectREFR save/change-data function candidate"),
		(0x004D4090, "extra-data list save dispatcher candidate"),
		(0x004BED60, "ExtraOwnership save handler candidate"),
		(0x004BF220, "nearby extra-data save helper candidate"),
		(0x00484D60, "save/change-data helper candidate")
	]
	idx = 0
	while idx < len(targets):
		item = targets[idx]
		find_refs_to(item[0], item[1], 160)
		idx += 1

def main():
	write("=" * 70)
	write("FAMINE BOX OWNERSHIP SAVE PATH AUDIT")
	write("=" * 70)
	write("Crash context to explain:")
	write("  Ref on stack: TESObjectREFR Famine Box, FormID 7F000AEB, plugin Famine.esp, cell Famine Cell not loaded")
	write("  Save file on stack: autosave.fos.tmp")
	write("  Crash path: 0x00562305 -> 0x004D4112 -> core hook -> 0x004BEDCC -> 0x00865DFB")
	write("")
	write("Goal: prove what save/change-data path serializes this unloaded ref and what extra-list contract it expects.")
	analyze_path_functions()
	analyze_path_windows()
	analyze_refs()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/famine_box_ownership_path_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
