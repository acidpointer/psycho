# @category Analysis
# @description Audit Default heap reachability after gheap hooks are installed

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

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

def find_refs_to(addr_int, label, limit=160):
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

def decompile_ref_callers(addr_int, label, limit=40):
	write("")
	write("-" * 70)
	write("Caller decompilations for %s" % label)
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	seen = {}
	count = 0
	while refs.hasNext():
		ref = refs.next()
		func = fm.getFunctionContaining(ref.getFromAddress())
		if func is None:
			continue
		entry = func.getEntryPoint().getOffset()
		if seen.has_key(entry):
			continue
		seen[entry] = True
		decompile_at(entry, "caller of %s" % label, 12000)
		count += 1
		if count >= limit:
			write("  ... (truncated at %d callers)" % limit)
			return

def audit_target(addr_int, label):
	decompile_at(addr_int, label)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)
	decompile_ref_callers(addr_int, label)

def main():
	write("AUDIT: gheap heap-domain and Default-tail reachability")
	write("=" * 70)
	write("Questions:")
	write("  1. Which static call paths reach the original GameHeap and Default heap allocators?")
	write("  2. Which wrappers or vtable entries bypass GameHeap::Allocate after hooks install?")
	write("  3. Which constructor/global references can retain a Default heap allocation domain?")
	write("")
	write("# GameHeap public allocation/free domain")
	audit_target(0x00AA3E40, "GameHeap Allocate")
	audit_target(0x00AA4060, "GameHeap Free")
	write("")
	write("# Default/File large heap virtual methods")
	audit_target(0x00AA7B20, "large_heap allocate vtable entry")
	audit_target(0x00AA7B40, "large_heap free vtable entry")
	audit_target(0x00AA8F50, "large_heap allocation implementation")
	audit_target(0x00AA98F0, "large_heap free implementation")
	write("")
	write("# Vtable and known GameHeap global references")
	find_refs_to(0x010A28FC, "large_heap vtable")
	decompile_ref_callers(0x010A28FC, "large_heap vtable")
	find_refs_to(0x011F6238, "GameHeap singleton")
	decompile_ref_callers(0x011F6238, "GameHeap singleton")

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/memory/gheap_heap_domain_and_tail_reachability_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
