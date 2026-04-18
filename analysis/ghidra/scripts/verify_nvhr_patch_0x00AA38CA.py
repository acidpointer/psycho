# @category Analysis
# @description Verify what the 30-byte NOP patch at 0x00AA38CA..0x00AA38E8 removes, as done by NVHR (Heap-Replacer/main/heap_replacer.h).
#
# NVHR applies: patch_nops((void *)0x00AA38CA, 0x00AA38E8 - 0x00AA38CA);
# We don't apply this, and our tester's crash reproduces. Goal: understand
# exactly what 30 bytes NVHR removes before we copy the patch blindly.
#
# Questions this answers:
#  Q1. What function is 0x00AA38CA inside? What does the function do?
#  Q2. What instructions are in the 30-byte [0x00AA38CA, 0x00AA38E8) range?
#       Control-flow? CALL? LOOP? Conditional branch?
#  Q3. Why would NVHR disable these specific 30 bytes? What vanilla
#       SBM machinery depends on them that we've already disabled via
#       the neighboring `patch_ret` calls (0x00AA58D0, 0x00AA5C80,
#       0x00AA6840, 0x00AA6F90, 0x00AA7030, 0x00AA7290, 0x00AA7300)?
#  Q4. Are they reachable from any path that's still live after our
#       current patches? If yes, leaving them running could corrupt
#       SBM state that interacts with our pool/block allocators.

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def write(msg):
	output.append(msg)
	print(msg)

def decompile_at(addr_int, label, max_len=12000):
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
		write("  NOTE: Requested 0x%08x is inside %s (entry at 0x%08x, +0x%x)" % (addr_int, func.getName(), faddr, addr_int - faddr))
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		write(code[:max_len])
	else:
		write("  [decompilation failed]")

def disasm_range(start, end, label):
	write("")
	write("-" * 70)
	write("Disassembly: %s [0x%08x .. 0x%08x) -- %d bytes" % (label, start, end, end - start))
	write("-" * 70)
	listing = currentProgram.getListing()
	inst_iter = listing.getInstructions(toAddr(start), True)
	while inst_iter.hasNext():
		inst = inst_iter.next()
		ia = inst.getAddress().getOffset()
		if ia < start:
			continue
		if ia >= end:
			break
		# Flag call/jump targets so we can follow them.
		targets = []
		for ref in inst.getReferencesFrom():
			rt = ref.getReferenceType()
			if rt.isCall() or rt.isConditional() or rt.isJump():
				tgt = ref.getToAddress().getOffset()
				tgt_func = fm.getFunctionAt(toAddr(tgt))
				name = tgt_func.getName() if tgt_func else "???"
				targets.append("%s -> 0x%08x %s" % (rt, tgt, name))
		suffix = (" ; " + " ; ".join(targets)) if targets else ""
		write("  0x%08x: %s%s" % (ia, inst.toString(), suffix))

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
	write("--- Calls FROM %s (entry 0x%08x) ---" % (label, func.getEntryPoint().getOffset()))
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				tgt_func = fm.getFunctionAt(toAddr(tgt))
				name = tgt_func.getName() if tgt_func else "???"
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, name))
				count += 1
	write("  Total: %d calls" % count)

def callers_of_containing(addr_int, label):
	write("")
	write("-" * 70)
	write("Callers of the function containing %s" % label)
	write("-" * 70)
	func = fm.getFunctionContaining(toAddr(addr_int))
	if func is None:
		write("  [no containing function]")
		return
	entry = func.getEntryPoint().getOffset()
	write("  Function entry: %s @ 0x%08x" % (func.getName(), entry))
	refs = ref_mgr.getReferencesTo(toAddr(entry))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		if not ref.getReferenceType().isCall():
			continue
		src = ref.getFromAddress().getOffset()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		fname = from_func.getName() if from_func else "???"
		fentry = from_func.getEntryPoint().getOffset() if from_func else 0
		write("  0x%08x in %s (entry 0x%08x)" % (src, fname, fentry))
		count += 1
		if count > 40:
			write("  ... (truncated)")
			break
	write("  Total callers: %d" % count)

# --- Main body ---

write("######################################################################")
write("# Verify NVHR patch: patch_nops(0x00AA38CA, 30 bytes)")
write("######################################################################")
write("")
write("Goal: see exactly what 30 bytes of instructions NVHR removes at")
write("0x00AA38CA..0x00AA38E8, what function contains them, what CALL or")
write("jump targets appear in that window, and whether the surrounding")
write("function is reachable from our current hook set.")

# The 30-byte window itself -- instructions only, no guessing.
disasm_range(0x00AA38CA, 0x00AA38E8, "NVHR NOP window")

# The full containing function -- context for WHY the 30 bytes exist.
decompile_at(0x00AA38CA, "Containing function", max_len=14000)

# What does the containing function call? Several of those calls may
# be the exact SBM functions we've already patch_ret'd.
find_and_print_calls_from(0x00AA38CA, "containing function")

# Who calls this containing function? Lets us trace whether it's
# still reachable after our patches (e.g. from AA3E40 game_heap_allocate
# entry, AA4060 game_heap_free entry, etc.).
callers_of_containing(0x00AA38CA, "0x00AA38CA (NOP window)")

# Wider context: show 48 bytes before and after the NOP window to see
# what precedes and follows it. Sometimes NVHR NOPs a specific branch
# target inside a larger conditional; the surrounding code tells us
# which branch survives.
disasm_range(0x00AA389A, 0x00AA3908, "Context +/- 48 bytes")

# --- Output ---

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/verify_nvhr_patch_0x00AA38CA.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
