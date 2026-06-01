# @category Analysis
# @description Audit ExtraLinkedRef target getter/setter and crash-path NULL/invalid-pointer contract

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

def find_refs_to(addr_int, label, limit=180):
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
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, name_for_func(func_for(tgt))))
				count += 1
				if count >= limit:
					write("  ... (truncated at %d)" % limit)
					write("  Total printed: %d" % count)
					return
	write("  Total printed: %d" % count)

def disasm_window(center_int, before_count, after_count, label):
	write("")
	write("-" * 70)
	write("Disassembly: %s around 0x%08x" % (label, center_int))
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
		marker = " << target" if off == center_int else ""
		write("  0x%08x: %-58s%s" % (off, inst.toString(), marker))
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				write("      call -> 0x%08x %s" % (tgt, name_for_func(func_for(tgt))))
		inst = inst.getNext()
		idx += 1

def add_seen(seen, func):
	if func is None:
		return
	key = func.getEntryPoint().getOffset()
	if key not in seen:
		seen[key] = func

def refs_with_context(addr_int, label, limit=120, decompile_limit=40):
	write("")
	write("=" * 70)
	write("Reference context for 0x%08x (%s)" % (addr_int, label))
	write("=" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	seen = {}
	while refs.hasNext():
		ref = refs.next()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		add_seen(seen, from_func)
		write("  %s @ 0x%08x (in %s)" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), name_for_func(from_func)))
		disasm_window(ref.getFromAddress().getOffset(), 14, 28, "reference to %s" % label)
		count += 1
		if count >= limit:
			write("  ... (reference context truncated at %d)" % limit)
			break
	write("  Reference contexts printed: %d" % count)
	decompile_seen(seen, label, decompile_limit)

def decompile_seen(seen, label, limit):
	write("")
	write("-" * 70)
	write("Decompiled reference owners for %s" % label)
	write("-" * 70)
	keys = sorted(seen.keys())
	count = 0
	for key in keys:
		decompile_at(key, "owner of %s: %s" % (label, name_for_func(seen[key])), 14000)
		count += 1
		if count >= limit:
			write("  [owner decompile truncated at %d]" % limit)
			break
	write("  Owner functions decompiled: %d" % count)

def audit_core_contracts():
	write("")
	write("=" * 70)
	write("Core ExtraLinkedRef and activation contracts")
	write("=" * 70)
	targets = [
		(0x0041e410, "ExtraLinkedRef target getter candidate"),
		(0x0041e440, "ExtraLinkedRef target setter/remover candidate"),
		(0x00569b80, "TESObjectREFR linked-ref getter used by crash path"),
		(0x00568680, "linked-ref base-form type gate used by crash path"),
		(0x00568260, "post type-gate helper used by crash path"),
		(0x005012c0, "activation helper that checks linked ref before message"),
		(0x00501310, "activation parent helper"),
		(0x00573170, "TESObjectREFR Activate path"),
		(0x007af430, "TESObjectREFR base-form resolver"),
		(0x00401170, "TESForm::GetTypeID"),
	]
	for item in targets:
		decompile_at(item[0], item[1], 22000)
		disasm_window(item[0], 20, 80, item[1])
		find_and_print_calls_from(item[0], item[1], 180)

def audit_provenance_refs():
	refs_with_context(0x0041e410, "ExtraLinkedRef target getter candidate", 120, 50)
	refs_with_context(0x0041e440, "ExtraLinkedRef target setter/remover candidate", 120, 50)
	refs_with_context(0x00569b80, "TESObjectREFR linked-ref getter", 120, 50)
	refs_with_context(0x00568680, "linked-ref base-form type gate", 120, 50)
	refs_with_context(0x00568260, "post linked-ref type-gate helper", 120, 50)

def main():
	write("ExtraLinkedRef target provenance audit")
	write("")
	write("Current crash chain from previous outputs:")
	write("  0x00501310 -> 0x005012C0 -> 0x00569B80 -> 0x00568680 -> 0x007AF430 -> 0x00401170")
	write("  0x007AF430 is TESObjectREFR base-form resolver: returns [ref + 0x20].")
	write("  Crash ECX=0xFFFFFDA5 means the linked target ref had an invalid non-NULL base-form pointer.")
	write("")
	write("Questions this output must answer before patching:")
	write("  1. Does 0x00569B80 simply return ExtraLinkedRef +0x0C, or does it do fallback resolution?")
	write("  2. Is NULL from the linked-ref getter accepted by all relevant callers?")
	write("  3. Is setter/remover 0x0041E440 the right boundary to scrub bad targets, or is consumer gate 0x00568680 safer?")
	audit_core_contracts()
	audit_provenance_refs()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/extralinkedref_target_provenance_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
