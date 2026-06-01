# @category Analysis
# @description Audit safe patch surfaces for 0x00D0D7D8 Havok remove-agent crash

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
ref_mgr = currentProgram.getReferenceManager()
memory = currentProgram.getMemory()
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

def decompile_at(addr_int, label, max_len=26000):
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
			write("  [decompile truncated at %d chars, total %d]" % (max_len, len(code)))
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

def find_and_print_calls_from(addr_int, label, limit=240):
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

def byte_at(addr_int):
	b = memory.getByte(toAddr(addr_int))
	if b < 0:
		b += 256
	return b

def print_bytes(start_int, length, label):
	write("")
	write("-" * 70)
	write("Bytes: %s @ 0x%08x len=0x%x" % (label, start_int, length))
	write("-" * 70)
	pos = 0
	while pos < length:
		line_addr = start_int + pos
		parts = []
		i = 0
		while i < 16 and pos + i < length:
			try:
				parts.append("%02x" % byte_at(line_addr + i))
			except:
				parts.append("??")
			i += 1
		write("  0x%08x: %s" % (line_addr, " ".join(parts)))
		pos += 16

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

def calls_target(inst, target_int):
	refs = inst.getReferencesFrom()
	for ref in refs:
		if ref.getReferenceType().isCall() and ref.getToAddress().getOffset() == target_int:
			return True
	return False

def print_pair_regions_for_function(addr_int, label):
	func = func_for(addr_int)
	write("")
	write("=" * 70)
	write("Enter/leave pair regions: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	if func is None:
		write("  [function not found]")
		return
	insts = []
	inst_iter = listing.getInstructions(func.getBody(), True)
	while inst_iter.hasNext():
		insts.append(inst_iter.next())
	enter_indexes = []
	leave_indexes = []
	i = 0
	while i < len(insts):
		if calls_target(insts[i], 0x00c911d0):
			enter_indexes.append(i)
		if calls_target(insts[i], 0x00c91210):
			leave_indexes.append(i)
		i += 1
	write("  C911D0 calls: %d, C91210 calls: %d" % (len(enter_indexes), len(leave_indexes)))
	for idx in enter_indexes:
		print_local_context(insts, idx, "C911D0 enter")
	for idx in leave_indexes:
		print_local_context(insts, idx, "C91210 leave")
	print_between_pairs(insts)

def print_local_context(insts, idx, label):
	start = idx - 10
	if start < 0:
		start = 0
	end = idx + 14
	if end > len(insts):
		end = len(insts)
	write("")
	write("  Local context for %s at 0x%08x" % (label, insts[idx].getAddress().getOffset()))
	i = start
	while i < end:
		inst = insts[i]
		marker = " << %s" % label if i == idx else ""
		write("    0x%08x: %-58s%s" % (inst.getAddress().getOffset(), inst.toString(), marker))
		i += 1

def print_between_pairs(insts):
	pairs = []
	i = 0
	while i < len(insts):
		if calls_target(insts[i], 0x00c911d0):
			j = i + 1
			while j < len(insts):
				if calls_target(insts[j], 0x00c91210):
					pairs.append((i, j))
					break
				j += 1
		i += 1
	for pair in pairs:
		start = pair[0]
		end = pair[1]
		write("")
		write("  Region C911D0 -> C91210: 0x%08x..0x%08x" % (insts[start].getAddress().getOffset(), insts[end].getAddress().getOffset()))
		i = start
		printed = 0
		while i <= end:
			inst = insts[i]
			text = inst.toString()
			interesting = calls_target(inst, 0x00c911d0) or calls_target(inst, 0x00c91210) or calls_target(inst, 0x00cf7080) or "+ 0xcc" in text.lower() or "0xcc]" in text.lower()
			if interesting:
				write("    0x%08x: %s" % (inst.getAddress().getOffset(), text))
				printed += 1
			i += 1
		write("    Interesting instructions printed: %d" % printed)

def audit_function_family():
	print_pair_regions_for_function(0x00d0d3f0, "crash worker FUN_00D0D3F0")
	print_pair_regions_for_function(0x00d931a0, "sibling worker FUN_00D931A0")
	print_pair_regions_for_function(0x00d93380, "sibling worker FUN_00D93380")
	print_pair_regions_for_function(0x00d93ba0, "sibling worker FUN_00D93BA0")

def audit_patch_bytes():
	print_bytes(0x00d0d73e, 0xb0, "crash worker unsafe region bytes")
	disasm_window(0x00d0d744, 8, 12, "initial island read before C911D0")
	disasm_window(0x00d0d7d1, 18, 18, "StAddAgt call before crash reread")
	disasm_window(0x00d0d7d8, 12, 18, "crash reread before C91210")
	disasm_window(0x00d93f4a, 12, 16, "sibling initial island read")
	disasm_window(0x00d93fea, 12, 16, "sibling leave island reread")

def audit_contract_helpers():
	decompile_at(0x00c911d0, "C911D0 enter critical section", 8000)
	decompile_at(0x00c91210, "C91210 leave critical section", 8000)
	decompile_at(0x00cf7080, "CF7080 StAddAgt side-effect boundary", 22000)
	find_refs_to(0x00c911d0, "C911D0", 120)
	find_refs_to(0x00c91210, "C91210", 120)
	find_refs_to(0x00cf7080, "CF7080", 120)
	find_and_print_calls_from(0x00d0d3f0, "crash worker", 260)

def main():
	write("HAVOK REMOVE-AGENT SAFE PATCH SURFACE AUDIT")
	write("")
	write("Patch quality bar:")
	write("  Do not skip C91210 if C911D0 already ran; that risks leaving a critical section held.")
	write("  Do not blindly skip CF7080; that changes narrowphase semantics.")
	write("  Prove whether the island pointer can be captured before CF7080 and reused for C91210.")
	write("  Also check sibling functions, because a one-site patch may only move the crash.")
	audit_patch_bytes()
	audit_contract_helpers()
	audit_function_family()
	write("")
	write("Questions this output must answer before code changes:")
	write("  1. Is the C911D0 argument exactly the island pointer we must pass to C91210?")
	write("  2. Is the crash reread only needed to recompute the same island pointer?")
	write("  3. Do all C911D0/C91210 users follow the same saveable pattern?")
	write("  4. Is there enough local stack/register space for a tiny patch without changing frame layout?")

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/havok_remove_agent_safe_patch_surface_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
