# @category Analysis
# @description Audit stress-test navmesh/tasklet crash at 0x0069083A

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
		faddr = from_func.getEntryPoint().getOffset() if from_func else 0
		fname = from_func.getName() if from_func else "???"
		write("  %s @ 0x%08x (in %s @ 0x%08x)" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname, faddr))
		count += 1
		if count >= limit:
			write("  ... (truncated at %d)" % limit)
			break
	write("  Total printed: %d" % count)

def find_refs_into_function(addr_int, label, limit=220):
	func = func_for(addr_int)
	write("")
	write("-" * 70)
	write("References INTO function containing 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	if func is None:
		write("  [function not found]")
		return
	body = func.getBody()
	addr_iter = body.getAddresses(True)
	count = 0
	while addr_iter.hasNext():
		addr = addr_iter.next()
		refs = ref_mgr.getReferencesTo(addr)
		while refs.hasNext():
			ref = refs.next()
			from_func = fm.getFunctionContaining(ref.getFromAddress())
			if from_func is not None and from_func.getEntryPoint() == func.getEntryPoint():
				continue
			write("  target=0x%08x %s from 0x%08x in %s" % (addr.getOffset(), ref.getReferenceType(), ref.getFromAddress().getOffset(), name_for_func(from_func)))
			count += 1
			if count >= limit:
				write("  ... (truncated at %d)" % limit)
				write("  Total printed: %d" % count)
				return
	write("  Total printed: %d" % count)

def find_and_print_calls_from(addr_int, label, limit=260):
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
				tgt_func = fm.getFunctionAt(toAddr(tgt))
				if tgt_func is None:
					tgt_func = fm.getFunctionContaining(toAddr(tgt))
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, name_for_func(tgt_func)))
				count += 1
				if count >= limit:
					write("  ... (truncated at %d)" % limit)
					write("  Total printed: %d" % count)
					return
	write("  Total printed: %d" % count)

def read_u8(addr_int):
	v = memory.getByte(toAddr(addr_int))
	if v < 0:
		v += 256
	return v

def read_u32(addr_int):
	v = memory.getInt(toAddr(addr_int))
	if v < 0:
		v += 0x100000000
	return v

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
				parts.append("%02x" % read_u8(line_addr + i))
			except:
				parts.append("??")
			i += 1
		write("  0x%08x: %s" % (line_addr, " ".join(parts)))
		pos += 16

def print_words(start_int, count, label):
	write("")
	write("-" * 70)
	write("U32 words: %s @ 0x%08x" % (label, start_int))
	write("-" * 70)
	i = 0
	while i < count:
		addr_int = start_int + i * 4
		try:
			write("  +0x%02x 0x%08x: 0x%08x" % (i * 4, addr_int, read_u32(addr_int)))
		except:
			write("  +0x%02x 0x%08x: <unreadable>" % (i * 4, addr_int))
		i += 1

def print_instruction(addr_int, label):
	inst = listing.getInstructionAt(toAddr(addr_int))
	write("")
	write("-" * 70)
	write("Instruction: %s @ 0x%08x" % (label, addr_int))
	write("-" * 70)
	if inst is None:
		write("  [instruction not found]")
		return
	write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
	write("  Mnemonic: %s" % inst.getMnemonicString())
	write("  Flow: %s" % inst.getFlowType())
	write("  Length: %d" % inst.getLength())
	refs = inst.getReferencesFrom()
	for ref in refs:
		write("  RefFrom: %s -> 0x%08x" % (ref.getReferenceType(), ref.getToAddress().getOffset()))

def highlight_for(off, highlights):
	for item in highlights:
		if off == item:
			return "=> "
	return "   "

def disasm_window(start_int, length, label, highlights, max_inst=380):
	end_int = start_int + length
	write("")
	write("-" * 70)
	write("Disassembly: %s 0x%08x..0x%08x" % (label, start_int, end_int))
	write("-" * 70)
	inst = listing.getInstructionAt(toAddr(start_int))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(start_int))
	count = 0
	while inst is not None and inst.getAddress().getOffset() < end_int:
		off = inst.getAddress().getOffset()
		write("%s0x%08x: %s" % (highlight_for(off, highlights), off, inst.toString()))
		inst = inst.getNext()
		count += 1
		if count >= max_inst:
			write("  ... (truncated at %d instructions)" % max_inst)
			break
	write("  Instructions printed: %d" % count)

def disasm_function(addr_int, label, highlights, max_inst=420):
	func = func_for(addr_int)
	write("")
	write("-" * 70)
	write("Function disassembly: %s @ 0x%08x" % (label, addr_int))
	write("-" * 70)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		off = inst.getAddress().getOffset()
		write("%s0x%08x: %s" % (highlight_for(off, highlights), off, inst.toString()))
		count += 1
		if count >= max_inst:
			write("  ... (truncated at %d instructions)" % max_inst)
			break
	write("  Instructions printed: %d" % count)

def scan_function_for_text(addr_int, label, needles, limit=220):
	func = func_for(addr_int)
	write("")
	write("-" * 70)
	write("Instruction text scan: %s" % label)
	write("-" * 70)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		text = inst.toString().lower()
		matched = False
		for needle in needles:
			if needle.lower() in text:
				matched = True
		if matched:
			write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
			count += 1
			if count >= limit:
				write("  ... (truncated at %d)" % limit)
				break
	write("  Total matches: %d" % count)

def scan_range_for_text(start_int, end_int, label, needles, limit=260):
	write("")
	write("-" * 70)
	write("Instruction text scan: %s 0x%08x..0x%08x" % (label, start_int, end_int))
	write("-" * 70)
	inst = listing.getInstructionAt(toAddr(start_int))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(start_int))
	count = 0
	while inst is not None and inst.getAddress().getOffset() < end_int:
		text = inst.toString().lower()
		matched = False
		for needle in needles:
			if needle.lower() in text:
				matched = True
		if matched:
			from_func = fm.getFunctionContaining(inst.getAddress())
			write("  0x%08x: %-44s in %s" % (inst.getAddress().getOffset(), inst.toString(), name_for_func(from_func)))
			count += 1
			if count >= limit:
				write("  ... (truncated at %d)" % limit)
				break
		inst = inst.getNext()
	write("  Total matches: %d" % count)

def audit_function(addr_int, label, max_len=18000):
	decompile_at(addr_int, label, max_len)
	find_refs_into_function(addr_int, label)
	find_and_print_calls_from(addr_int, label)

def print_function_table(items):
	write("")
	write("-" * 70)
	write("Crash calltrace function table")
	write("-" * 70)
	for item in items:
		addr_int = item[0]
		label = item[1]
		func = func_for(addr_int)
		if func is None:
			write("  0x%08x %-42s [function not found]" % (addr_int, label))
			continue
		write("  0x%08x %-42s -> %s size=%d" % (addr_int, label, name_for_func(func), func.getBody().getNumAddresses()))

def audit_calltrace(items):
	for item in items:
		audit_function(item[0], item[1], item[2])
		disasm_function(item[0], item[1], item[3], item[4])
		scan_function_for_text(item[0], item[1], ["+ 0x20", "+0x20", "+ 0x1c", "+0x1c", "0x20", "0x1c", "call", "cmp", "test"], 180)

def main():
	highlights = [0x0069083A, 0x0069081B, 0x006B8CD4, 0x006C9600, 0x006C8FB4, 0x006C8EE0, 0x006D0B54, 0x006D0970, 0x006EA0B6, 0x00B0258A, 0x00B02403]
	calltrace = [
		(0x0069083A, "crash EIP: tasklet navmesh/pathing deref", 26000, highlights, 520),
		(0x0069081B, "caller/near-crash return in same path", 20000, highlights, 300),
		(0x006B8CD4, "navmesh/pathing caller", 22000, highlights, 320),
		(0x006C9600, "navmesh/pathing caller", 22000, highlights, 320),
		(0x006C8FB4, "navmesh/pathing caller", 22000, highlights, 320),
		(0x006C8EE0, "navmesh/pathing caller", 22000, highlights, 320),
		(0x006D0B54, "navmesh/pathing caller", 22000, highlights, 320),
		(0x006D0970, "navmesh/pathing caller", 22000, highlights, 320),
		(0x006EA0B6, "pathfinding outer caller", 26000, highlights, 380),
		(0x00B0258A, "BSWin32TaskletManager worker dispatch", 22000, highlights, 360),
		(0x00B02403, "BSWin32TaskletManager thread loop", 22000, highlights, 360)
	]
	write("=" * 70)
	write("CRASH 0x0069083A NAVMESH/TASKLET AUDIT")
	write("=" * 70)
	write("")
	write("Runtime facts from latest logs:")
	write("  Thread: [FNV] BSWin32TaskletManager - Tasklet 1.")
	write("  Exception: read AV at 0x00000020, EIP=0x0069083A.")
	write("  Registers: EAX=0x00000004 ECX=0x00000004 EDX=0x0D8FDCDC ESI=0 EDI=0 EBX=0x011F8270.")
	write("  CrashLogger resolves EDX as NavMeshInfoSearch and EBX as BSWin32TaskletManager.")
	write("  Stack contains BSScrapArray<NavMeshInfo const *,1024> and BSScrapArray<TESObjectREFR *,1024>.")
	write("  psycho crash_diag says fault/pool/block/mimalloc ownership are all false.")
	write("  Before crash, gheap pool was exhausted and VAS largest hole was around 15-17MB.")
	write("")
	write("# SECTION 1: exact crash instruction and bytes")
	print_instruction(0x0069083A, "faulting instruction")
	print_bytes(0x00690810, 0x70, "crash bytes around 0x0069083A")
	disasm_window(0x006907C0, 0x140, "faulting function window", highlights, 420)
	write("")
	write("# SECTION 2: function and calltrace overview")
	print_function_table(calltrace)
	audit_calltrace(calltrace)
	write("")
	write("# SECTION 3: focused near-crash scans")
	scan_range_for_text(0x0068F000, 0x00691C00, "near 0x0069083A null/small-pointer deref patterns", ["+ 0x20", "+0x20", "+ 0x1c", "+0x1c", "[ecx", "[eax", "[esi", "[edi", "test", "cmp", "jz", "jnz", "call"])
	disasm_window(0x006B8B80, 0x220, "0x006B8CD4 caller window", highlights, 420)
	disasm_window(0x006C8E00, 0x980, "0x006C8EE0..0x006C9600 caller region", highlights, 700)
	disasm_window(0x006D0800, 0x420, "0x006D0970..0x006D0B54 caller region", highlights, 520)
	disasm_window(0x006E9F00, 0x260, "0x006EA0B6 pathfinding outer region", highlights, 420)
	disasm_window(0x00B02380, 0x280, "BSWin32TaskletManager thread dispatch region", highlights, 420)
	write("")
	write("# SECTION 4: RTTI/vtable refs visible in CrashLogger stack")
	print_words(0x0106C22C, 16, "NavMeshInfoSearch RTTI/vtable area from CrashLogger")
	print_words(0x0106C968, 16, "BSScrapArray<NavMeshInfo const *,1024> RTTI area from CrashLogger")
	print_words(0x0106C97C, 16, "BSScrapArray<TESObjectREFR *,1024> RTTI area from CrashLogger")
	find_refs_to(0x0106C22C, "NavMeshInfoSearch class/vtable from CrashLogger")
	find_refs_to(0x0106C968, "BSScrapArray<NavMeshInfo const *,1024> RTTI")
	find_refs_to(0x0106C97C, "BSScrapArray<TESObjectREFR *,1024> RTTI")
	write("")
	write("# SECTION 5: direct refs to exact addresses")
	find_refs_to(0x0069083A, "faulting instruction address")
	find_refs_to(0x0069081B, "near-crash return address")
	find_refs_to(0x006B8CD4, "calltrace node")
	find_refs_to(0x006EA0B6, "pathfinding outer calltrace node")
	write("")
	write("=" * 70)
	write("END CRASH 0x0069083A NAVMESH/TASKLET AUDIT")
	write("=" * 70)

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/crash_0069083a_navmesh_tasklet_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
