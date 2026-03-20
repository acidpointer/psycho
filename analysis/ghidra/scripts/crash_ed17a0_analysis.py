# @category Analysis
# @description Analyze BSTaskManagerThread crash at 0x00ED17A0 during LOD texture loading

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def write(msg):
	output.append(msg)
	print(msg)

def decompile_at(addr_int, label, max_len=8000):
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
	entry = func.getEntryPoint().getOffset()
	sz = func.getBody().getNumAddresses()
	write("  Function: %s, Size: %d bytes" % (func.getName(), sz))
	write("  Entry: 0x%08x" % entry)
	sig = func.getSignature()
	if sig is not None:
		write("  Signature: %s" % sig.getPrototypeString())
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		write(code[:max_len])
	else:
		write("  [decompilation failed]")

def find_calls_from(addr_int, label):
	addr = toAddr(addr_int)
	func = fm.getFunctionAt(addr)
	if func is None:
		func = fm.getFunctionContaining(addr)
	write("")
	write("--- Calls FROM %s (0x%08x) ---" % (label, addr_int))
	if func is None:
		write("  [function not found]")
		return
	listing = currentProgram.getListing()
	body = func.getBody()
	addr_iter = body.getAddresses(True)
	count = 0
	while addr_iter.hasNext():
		a = addr_iter.next()
		inst = listing.getInstructionAt(a)
		if inst is None:
			continue
		if not inst.getFlowType().isCall():
			continue
		refs_from = inst.getReferencesFrom()
		for r in refs_from:
			target = r.getToAddress().getOffset()
			target_func = fm.getFunctionAt(toAddr(target))
			target_name = target_func.getName() if target_func else "unknown_0x%08x" % target
			write("  CALL 0x%08x -> %s" % (target, target_name))
			count += 1
	write("  Total unique calls: %d" % count)

def find_xrefs_to(addr_int, label, limit=30):
	addr = toAddr(addr_int)
	refs = getReferencesTo(addr)
	write("")
	write("--- XRefs to %s (0x%08x) ---" % (label, addr_int))
	count = 0
	for ref in refs:
		from_addr = ref.getFromAddress()
		func = fm.getFunctionContaining(from_addr)
		fname = func.getName() if func else "???"
		write("  %s @ 0x%s (in %s)" % (ref.getReferenceType(), from_addr, fname))
		count += 1
		if count >= limit:
			write("  ... (truncated at %d)" % limit)
			break
	write("  Total: %d refs" % count)

def find_functions_in_range(start_int, end_int, label):
	write("")
	write("=" * 70)
	write("Functions in range 0x%08x - 0x%08x (%s)" % (start_int, end_int, label))
	write("=" * 70)
	addr = toAddr(start_int)
	end = toAddr(end_int)
	count = 0
	while addr.getOffset() < end.getOffset():
		func = fm.getFunctionAt(addr)
		if func is not None:
			entry = func.getEntryPoint().getOffset()
			sz = func.getBody().getNumAddresses()
			sig = func.getSignature()
			sig_str = sig.getPrototypeString() if sig else "?"
			write("  0x%08x (%d bytes): %s -- %s" % (entry, sz, func.getName(), sig_str))
			nxt = func.getBody().getMaxAddress()
			if nxt is not None:
				addr = nxt.add(1)
				count += 1
				continue
		addr = addr.add(1)
	write("  Total: %d functions" % count)

def disasm_around(addr_int, before=10, after=10):
	listing = currentProgram.getListing()
	write("")
	write("--- Disassembly around 0x%08x ---" % addr_int)
	start = toAddr(addr_int - before)
	inst = listing.getInstructionAfter(start)
	count = 0
	while inst is not None and count < (before + after):
		off = inst.getAddress().getOffset()
		marker = " <<< CRASH" if off == addr_int else ""
		write("  0x%08x: %s%s" % (off, inst.toString(), marker))
		inst = inst.getNext()
		count += 1


write("=" * 70)
write("CRASH ANALYSIS: BSTaskManagerThread LOD Texture Loading")
write("Exception: EXCEPTION_ACCESS_VIOLATION (C0000005)")
write("eip=0x00ED17A0, eax=0x00000000 (NULL dereference)")
write("Calltrace: 0x00ED17A0 -> 0x00ED1846 -> 0x00AA17F1")
write("Stack: NiSourceTexture(RefCount:0), BSFile(wastelandnv.buildings.dds)")
write("=" * 70)

# SECTION 1: Crash addresses
write("")
write("#" * 70)
write("# SECTION 1: Crash callstack addresses")
write("#" * 70)

decompile_at(0x00ED17A0, "CRASH_POINT_eip")
disasm_around(0x00ED17A0, 20, 20)
find_calls_from(0x00ED17A0, "CRASH_POINT")

decompile_at(0x00ED1846, "CALLER_1")
disasm_around(0x00ED1846, 20, 10)

decompile_at(0x00AA17F1, "CALLER_2")
disasm_around(0x00AA17F1, 20, 10)

# SECTION 2: Function enumeration near crash addresses
write("")
write("#" * 70)
write("# SECTION 2: Functions near crash addresses")
write("#" * 70)

find_functions_in_range(0x00ED1600, 0x00ED1A00, "CRT area near crash")
find_functions_in_range(0x00AA1600, 0x00AA1A00, "near 0x00AA17F1")

# SECTION 3: lpCriticalSection_011f4380 users
write("")
write("#" * 70)
write("# SECTION 3: Who uses lpCriticalSection_011f4380?")
write("#" * 70)

find_xrefs_to(0x011F4380, "lpCriticalSection_011f4380")

# SECTION 4: BSTaskManagerThread task processing
write("")
write("#" * 70)
write("# SECTION 4: BSTaskManagerThread task processing path")
write("#" * 70)

decompile_at(0x00C42DA0, "BSTaskManagerThread_Create")
decompile_at(0x00C410B0, "BSTaskManagerThread_Loop")
decompile_at(0x00C42380, "IO_ProcessTask_Variant1")
decompile_at(0x00C42560, "IO_ProcessTask_Variant2")

# SECTION 5: NiSourceTexture related functions
write("")
write("#" * 70)
write("# SECTION 5: NiSourceTexture / texture loading on IO thread")
write("#" * 70)

decompile_at(0x00A6DF48, "NiSourceTexture_area")
find_xrefs_to(0x0109B9EC, "NiSourceTexture_RTTI", 20)

# SECTION 6: AsyncQueueFlush internals (confirm TryEnterCriticalSection issue)
write("")
write("#" * 70)
write("# SECTION 6: AsyncQueueFlush internals (0x00c459d0)")
write("#" * 70)

decompile_at(0x00C459D0, "AsyncQueueFlush")
decompile_at(0x00C46080, "AsyncFlush_Inner1")
decompile_at(0x00C45A80, "AsyncFlush_Inner2")
decompile_at(0x0040FBF0, "BlockingLockAcquire")
decompile_at(0x0078D200, "TryLockAcquire")

# SECTION 7: IOManager queue count / pending state
write("")
write("#" * 70)
write("# SECTION 7: IO queue pending count mechanism")
write("#" * 70)

decompile_at(0x0044DDC0, "GetQueueCount")
decompile_at(0x00449150, "IOTask_Enqueue")
decompile_at(0x0044DD60, "IOTask_DecRef")

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/crash_00ED17A0_analysis.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
