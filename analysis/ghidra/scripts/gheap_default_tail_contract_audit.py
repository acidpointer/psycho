# @category Analysis
# @description Audit vanilla Default heap tail-adoption safety contract for gheap

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
				tgt_func = func_at_or_containing(tgt)
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, func_name(tgt_func)))
				count += 1
				if count >= limit:
					write("  ... (truncated at %d)" % limit)
					write("  Total printed: %d" % count)
					return
	write("  Total printed: %d" % count)

def disasm_function(addr_int, label, max_inst=280):
	func = func_at_or_containing(addr_int)
	write("")
	write("-" * 70)
	write("Disassembly: %s @ 0x%08x" % (label, addr_int))
	write("-" * 70)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
		count += 1
		if count >= max_inst:
			write("  ... (truncated at %d instructions)" % max_inst)
			break
	write("  Instructions printed: %d" % count)

def print_field_accesses(addr_int, label, max_inst=500):
	func = func_at_or_containing(addr_int)
	write("")
	write("-" * 70)
	write("Field-sensitive instructions in %s (0x%08x)" % (label, addr_int))
	write("-" * 70)
	if func is None:
		write("  [function not found]")
		return
	needles = ["0x14", "0x18", "0x1c", "0x24", "0x28", "0x2c", "0x30", "0x34", "0x38", "0x3c", "0x40", "0x44", "0x2048", "0x204c", "0x2050", "0x2054", "0x2058", "0x205c"]
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	printed = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		text = inst.toString()
		if contains_any(text, needles):
			write("  0x%08x: %s" % (inst.getAddress().getOffset(), text))
			printed += 1
		count += 1
		if count >= max_inst:
			write("  ... scan truncated at %d instructions" % max_inst)
			break
	write("  Field-sensitive instructions printed: %d" % printed)

def contains_any(text, needles):
	idx = 0
	while idx < len(needles):
		if text.find(needles[idx]) >= 0:
			return True
		idx += 1
	return False

def audit_function(addr_int, label, max_len=22000):
	decompile_at(addr_int, label, max_len)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)
	print_field_accesses(addr_int, label)
	disasm_function(addr_int, label, 260)

def audit_field_refs_in_function_set():
	write("")
	write("=" * 70)
	write("Focused field access summary")
	write("=" * 70)
	print_field_accesses(0x00AA8F50, "large_heap_alloc_impl_00aa8f50")
	print_field_accesses(0x00AA98F0, "large_heap_free_impl_00aa98f0")
	print_field_accesses(0x00AA9BD0, "free_block_insert_or_coalesce_00aa9bd0")
	print_field_accesses(0x00AA9970, "coalesce_adjacent_free_blocks_00aa9970")
	print_field_accesses(0x00AA9D30, "free_list_insert_00aa9d30")
	print_field_accesses(0x00AA9E50, "free_list_remove_00aa9e50")
	print_field_accesses(0x00AA8EA0, "release_storage_00aa8ea0")

def main():
	write("AUDIT: gheap Default heap tail-adoption safety contract")
	write("=" * 70)
	write("")
	write("Context:")
	write("  gheap adopts the unused tail of the vanilla Default heap after")
	write("  skipping the first 16MB. Runtime logs show adoption later disables")
	write("  only because live/free counters changed in the front zone:")
	write("    live 1546KB->1543KB, free 0->2")
	write("  while bump/high-water and first/last physical blocks stayed below")
	write("  the adopted tail. This script checks which fields are real tail-use")
	write("  evidence and which are normal front-zone allocator counters.")
	write("")
	write("Known large-heap fields from earlier audits:")
	write("  +0x14 reserve capacity")
	write("  +0x18 initial commit size")
	write("  +0x1c committed limit")
	write("  +0x24 bump/end offset")
	write("  +0x28 high-water offset")
	write("  +0x2c current live bytes")
	write("  +0x30 reservation base")
	write("  +0x34 physical block count")
	write("  +0x38 first physical block")
	write("  +0x3c last physical block")
	write("  +0x40 free block count")
	write("  +0x44..+0x2043 free-list buckets")
	write("  +0x2048/+0x204c large free-list sentinel/head")
	write("")
	write("Questions to answer from output:")
	write("  1. Does a changed +0x2c/+0x34/+0x40 imply tail use?")
	write("  2. Are +0x24/+0x28 monotonic upper bounds for all created blocks?")
	write("  3. Is +0x3c enough to prove every physical block remains below tail?")
	write("  4. Can gheap keep adopting tail while front-zone live/free counters move?")
	write("")
	audit_field_refs_in_function_set()
	write("")
	write("# Construction/reservation paths")
	audit_function(0x00AA8CA0, "large_heap_base_ctor_fields_00aa8ca0")
	audit_function(0x00AA8DD0, "large_heap_post_setup_reserve_00aa8dd0")
	audit_function(0x00AA79A0, "reserve_and_initial_commit_00aa79a0")
	audit_function(0x00AA7A50, "commit_more_00aa7a50")
	audit_function(0x00AA7AB0, "decommit_tail_00aa7ab0")
	write("")
	write("# Allocation/free paths")
	audit_function(0x00AA7B20, "large_heap_alloc_vtable_entry_00aa7b20")
	audit_function(0x00AA8F50, "large_heap_alloc_impl_00aa8f50")
	audit_function(0x00AA7B40, "large_heap_free_vtable_entry_00aa7b40")
	audit_function(0x00AA98F0, "large_heap_free_impl_00aa98f0")
	audit_function(0x00AA9CA0, "mark_allocated_block_00aa9ca0")
	audit_function(0x00AA9BD0, "free_block_insert_or_coalesce_00aa9bd0")
	audit_function(0x00AA9A70, "trim_trailing_free_blocks_00aa9a70")
	audit_function(0x00AA9970, "coalesce_adjacent_free_blocks_00aa9970")
	audit_function(0x00AA9D30, "free_list_insert_00aa9d30")
	audit_function(0x00AA9E50, "free_list_remove_00aa9e50")
	audit_function(0x00AAA660, "validate_or_remove_free_block_00aaa660")
	write("")
	write("# Lookup/release paths")
	audit_function(0x00AA7C60, "large_heap_msize_or_find_00aa7c60")
	audit_function(0x00AA7CA0, "large_heap_contains_or_validate_00aa7ca0")
	audit_function(0x00AA8EA0, "large_heap_release_storage_00aa8ea0")

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/memory/gheap_default_tail_contract_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
