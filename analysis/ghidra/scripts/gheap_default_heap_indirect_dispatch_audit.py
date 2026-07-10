# @category Analysis
# @description Find indirect Default heap allocation/free dispatches that can bypass GameHeap hooks

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

GAME_HEAP_SINGLETON = 0x011F6238
DEFAULT_SLOT_OFFSET = "0x110"

def write(msg):
	output.append(msg)
	print(msg)

def func_at_or_containing(addr_int):
	addr = toAddr(addr_int)
	func = fm.getFunctionAt(addr)
	if func is None:
		func = fm.getFunctionContaining(addr)
	return func

def func_name(func):
	if func is None:
		return "???"
	return "%s @ 0x%08x" % (func.getName(), func.getEntryPoint().getOffset())

def decompile_at(addr_int, label, max_len=22000):
	func = func_at_or_containing(addr_int)
	write("")
	write("=" * 70)
	write("%s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	if func is None:
		write("  [function not found]")
		return
	write("  Function: %s @ 0x%08x, Size: %d bytes" % (func.getName(), func.getEntryPoint().getOffset(), func.getBody().getNumAddresses()))
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		write(code[:max_len])
		if len(code) > max_len:
			write("  [decompile truncated at %d chars]" % max_len)
	else:
		write("  [decompilation failed]")

def find_refs_to(addr_int, label, limit=200):
	write("")
	write("-" * 70)
	write("References TO 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		write("  %s @ 0x%08x (in %s)" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), func_name(from_func)))
		count += 1
		if count >= limit:
			write("  ... (truncated at %d)" % limit)
			break
	write("  Total printed: %d" % count)

def find_and_print_calls_from(addr_int, label, limit=240):
	func = func_at_or_containing(addr_int)
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
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, func_name(func_at_or_containing(tgt))))
				count += 1
				if count >= limit:
					write("  ... (truncated at %d)" % limit)
					write("  Total printed: %d" % count)
					return
	write("  Total printed: %d" % count)

def singleton_referencing_functions():
	refs = ref_mgr.getReferencesTo(toAddr(GAME_HEAP_SINGLETON))
	seen = {}
	functions = []
	while refs.hasNext():
		ref = refs.next()
		func = fm.getFunctionContaining(ref.getFromAddress())
		if func is None:
			continue
		entry = func.getEntryPoint().getOffset()
		if seen.has_key(entry):
			continue
		seen[entry] = True
		functions.append(func)
	return functions

def is_indirect_call(text):
	upper = text.upper()
	return upper.find("CALL") >= 0 and upper.find("[") >= 0

def audit_default_slot_dispatch_candidates():
	write("")
	write("=" * 70)
	write("GameHeap Default-slot (+0x110) indirect dispatch candidates")
	write("=" * 70)
	write("This is a coarse co-occurrence scan, not a dataflow proof.")
	write("Use gheap_default_heap_dispatch_provenance_audit.py for the follow-up trace.")
	write("Only functions that statically reference the GameHeap singleton are scanned.")
	write("A candidate must contain both a +0x110 access and an indirect CALL.")
	functions = singleton_referencing_functions()
	write("  Singleton-referencing functions: %d" % len(functions))
	candidates = []
	idx = 0
	while idx < len(functions):
		func = functions[idx]
		inst_iter = listing.getInstructions(func.getBody(), True)
		has_default_slot = False
		indirect_calls = []
		while inst_iter.hasNext():
			inst = inst_iter.next()
			text = inst.toString()
			if text.find(DEFAULT_SLOT_OFFSET) >= 0:
				has_default_slot = True
			if is_indirect_call(text):
				indirect_calls.append("0x%08x: %s" % (inst.getAddress().getOffset(), text))
		if has_default_slot and len(indirect_calls) > 0:
			candidates.append((func, indirect_calls))
		idx += 1
	write("  Candidates: %d" % len(candidates))
	idx = 0
	while idx < len(candidates):
		item = candidates[idx]
		func = item[0]
		calls = item[1]
		write("")
		write("Candidate %s" % func_name(func))
		call_idx = 0
		while call_idx < len(calls):
			write("  %s" % calls[call_idx])
			call_idx += 1
		decompile_at(func.getEntryPoint().getOffset(), "Default-slot dispatch candidate", 16000)
		idx += 1

def main():
	write("AUDIT: gheap Default heap indirect dispatch bypasses")
	write("=" * 70)
	write("Goal: determine whether GameHeap singleton users load the Default heap")
	write("slot at +0x110 and issue an indirect virtual call that bypasses")
	write("the hooked GameHeap::Allocate/Free entrypoints.")
	find_refs_to(GAME_HEAP_SINGLETON, "GameHeap singleton")
	decompile_at(0x00866E00, "SBM Default/File heap construction")
	find_and_print_calls_from(0x00866E00, "SBM Default/File heap construction")
	decompile_at(0x00AA3E40, "GameHeap Allocate virtual dispatch")
	decompile_at(0x00AA4060, "GameHeap Free dispatch")
	audit_default_slot_dispatch_candidates()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/memory/gheap_default_heap_indirect_dispatch_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
