# @category Analysis
# @description OOM memset(NULL) crash research. Decompile the game calloc
# wrapper tail at 0x00aa22a2, NiDDSReader load path, and the inline memset
# around the faulting EIP 0x00ed2c9e. No loops beyond simple helpers.

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
	write(
		"  Function: %s @ 0x%08x, Size: %d bytes"
		% (func.getName(), faddr, func.getBody().getNumAddresses())
	)
	if faddr != addr_int:
		write(
			"  NOTE: Requested 0x%08x is inside %s (entry at 0x%08x)"
			% (addr_int, func.getName(), faddr)
		)
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		write(code[:max_len])
	else:
		write("  [decompilation failed]")


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
		write(
			"  %s @ 0x%08x (in %s)"
			% (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname)
		)
		count += 1
		if count > 120:
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
				write(
					"  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, name)
				)
				count += 1
	write("  Total: %d calls" % count)


def disasm_range(start_int, count=30):
	listing = currentProgram.getListing()
	inst = listing.getInstructionAfter(toAddr(start_int - 1))
	for i in range(count):
		if inst is None:
			break
		write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
		inst = inst.getNext()


# ======================================================================
# MAIN ANALYSIS
# ======================================================================

write("OOM-INDUCED MEMSET(NULL) CRASH ANALYSIS")
write("Fault: EIP=0x00ED2C9E  ECX=0x2AAAB  EAX=ESI=EDI=0")
write("Caller: 0x00AA22A2 (game calloc-style wrapper tail)")
write("Trigger: NiDDSReader 21 MB DDS load returned NULL from gheap")
write("=" * 70)

# ----------------------------------------------------------------------
# SECTION 1: Function containing 0x00AA22A2 and its disasm tail
# ----------------------------------------------------------------------

write("")
write("#" * 70)
write("# SECTION 1: Caller function around 0x00AA22A2")
write("#" * 70)

decompile_at(0x00AA22A2, "caller_function_around_0x00aa22a2")

write("")
write("Disasm 0x00aa2200..0x00aa22b0 (50 instructions):")
disasm_range(0x00AA2200, 50)

# ----------------------------------------------------------------------
# SECTION 2: Known callees of 0x00AA22A2's allocator/memset calls
# ----------------------------------------------------------------------

write("")
write("#" * 70)
write("# SECTION 2: Allocator wrappers and inline memset")
write("#" * 70)

decompile_at(0x00AA4030, "alloc_thin_wrapper_FUN_00aa4030")
find_refs_to(0x00AA4030, "alloc_thin_wrapper_callers")

decompile_at(0x00AA3E40, "gheap_retry_loop_FUN_00aa3e40")

decompile_at(0x00AA4290, "crt_malloc_wrapper_FUN_00aa4290")

decompile_at(0x00EC61C0, "inline_memset_FUN_00ec61c0")
find_refs_to(0x00EC61C0, "inline_memset_callers")

write("")
write("Disasm 0x00ed2c80..0x00ed2d00 (30 instructions around faulting EIP):")
disasm_range(0x00ED2C80, 30)

# ----------------------------------------------------------------------
# SECTION 3: NiDDSReader load path
# ----------------------------------------------------------------------

write("")
write("#" * 70)
write("# SECTION 3: NiDDSReader vtable[2] load path")
write("#" * 70)

decompile_at(0x00A8D0D0, "NiDDSReader_vtable2_Read", 16000)
find_and_print_calls_from(0x00A8D0D0, "NiDDSReader_vtable2_Read")

decompile_at(0x00A8C6E0, "NiDDSReader_branch_A")
decompile_at(0x00A8CC40, "NiDDSReader_branch_B")
decompile_at(0x00A8C7A0, "NiDDSReader_branch_C")
decompile_at(0x00A7C190, "NiPixelData_ctor_candidate")
decompile_at(0x00AA13E0, "small_alloc_wrapper_0x74")

# ----------------------------------------------------------------------
# OUTPUT
# ----------------------------------------------------------------------

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/oom_memset_crash_analysis.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("")
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
