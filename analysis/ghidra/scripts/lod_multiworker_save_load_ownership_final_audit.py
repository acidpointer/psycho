# @category Analysis
# @description Close the LOD producer-to-holder ownership race exposed by priority boost and two IO workers

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []
decompiled = {}

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
	faddr = func.getEntryPoint().getOffset()
	write("  Function: %s @ 0x%08x, Size: %d bytes" % (func.getName(), faddr, func.getBody().getNumAddresses()))
	if faddr != addr_int:
		write("  NOTE: Requested 0x%08x is inside %s (entry at 0x%08x)" % (addr_int, func.getName(), faddr))
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
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, name))
				count += 1
	write("  Total: %d calls" % count)

def decompile_once(addr_int, label, max_len=16000):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	if func is None:
		decompile_at(addr_int, label, max_len)
		return
	entry = func.getEntryPoint().getOffset()
	if entry in decompiled:
		write("  [already decompiled 0x%08x as %s]" % (entry, decompiled[entry]))
		return
	decompiled[entry] = label
	decompile_at(addr_int, label, max_len)

def audit_function(addr_int, label, max_len=16000):
	decompile_once(addr_int, label, max_len)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)

def print_instruction_window(addr_int, label, before=20, after=48):
	write("")
	write("=" * 70)
	write("Instruction window %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	inst = listing.getInstructionContaining(toAddr(addr_int))
	if inst is None:
		write("  [instruction not found]")
		return
	start = inst
	count = 0
	while start.getPrevious() is not None and count < before:
		start = start.getPrevious()
		count += 1
	cur = start
	count = 0
	while cur is not None and count < before + after + 1:
		marker = "  "
		if cur.getAddress() == inst.getAddress():
			marker = ">>"
		write("%s 0x%08x  %s" % (marker, cur.getAddress().getOffset(), cur))
		cur = cur.getNext()
		count += 1

def print_reference_windows(addr_int, label, limit=40, before=18, after=44):
	write("")
	write("=" * 70)
	write("Code-reference windows to %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext() and count < limit:
		ref = refs.next()
		if not ref.getReferenceType().isCall():
			continue
		from_addr = ref.getFromAddress()
		inst = listing.getInstructionContaining(from_addr)
		if inst is not None:
			owner = fm.getFunctionContaining(from_addr)
			owner_name = owner.getName() if owner else "???"
			write("")
			write("-" * 70)
			write("Reference 0x%08x in %s" % (from_addr.getOffset(), owner_name))
			start = inst
			back_count = 0
			while start.getPrevious() is not None and back_count < before:
				start = start.getPrevious()
				back_count += 1
			cur = start
			window_count = 0
			while cur is not None and window_count < before + after + 1:
				marker = "  "
				if cur.getAddress() == inst.getAddress():
					marker = ">>"
				write("%s 0x%08x  %s" % (marker, cur.getAddress().getOffset(), cur))
				cur = cur.getNext()
				window_count += 1
			count += 1
	if refs.hasNext():
		write("  [truncated after %d code references]" % limit)

def audit_addresses(items):
	for item in items:
		audit_function(item[0], item[1], item[2])

write("LOD MULTI-WORKER SAVE-LOAD OWNERSHIP FINAL AUDIT")
write("Program: %s" % currentProgram.getName())
write("Image base: %s" % currentProgram.getImageBase())
write("")
write("Observed crash chain:")
write("  0x006fdc12 -> 0x006fdd26 -> 0x006fa34e -> 0x006f752d -> 0x0040b467")
write("  Terrain producer returned a pointer that failed at InterlockedIncrement(task + 8).")
write("")
write("Contract questions:")
write("  1. What owns a new IOTask before the request holder takes its reference?")
write("  2. Which call publishes the task to workers, and which path drops that queue reference?")
write("  3. Can priority promotion or a second worker complete and destroy the task before holder assignment?")
write("  4. Where can a producer reservation be acquired and transferred without leaks or delayed completion?")

core_lifetime = [
	(0x0040B460, "InterlockedIncrement wrapper at crash EIP", 8000),
	(0x0092C870, "IOTask AddRef on field +8", 8000),
	(0x0044DD60, "IOTask Release on field +8", 10000),
	(0x00C3C590, "BSTask base constructor and initial reference state", 16000),
	(0x00C3CE60, "IOTask base constructor", 12000),
	(0x00C3CEE0, "IOTask path initialization", 12000),
	(0x00C3CF40, "IOTask file or queue attachment", 16000),
	(0x00C3CF60, "IOTask file request publication", 20000),
	(0x00C3D090, "IOTask request descriptor builder", 16000),
	(0x00AFD270, "File request descriptor transform", 16000),
	(0x00AF6540, "File request creation or lookup", 20000)
]

queue_lifetime = [
	(0x00C3DE80, "IOManager task submission", 20000),
	(0x00C3D440, "IOTask queue key builder", 12000),
	(0x00C3CAE0, "IOTask dependency priority propagation", 20000),
	(0x00C3DF40, "IOManager queued task priority update", 20000),
	(0x00C3DBF0, "IOManager processing and queue-reference release", 24000),
	(0x00C3E420, "IOManager queued task acquisition", 18000),
	(0x00C3CB70, "IOTask completion or dependency release path", 24000),
	(0x00C3D4F0, "IOTask manager release path", 18000),
	(0x00C3D5E0, "IOTask destruction or cancellation path", 18000)
]

lod_terrain = [
	(0x006FB980, "BGSTerrainChunkLoadTask producer", 24000),
	(0x006FA210, "Terrain request caller and holder publication", 28000),
	(0x006F74F0, "Intrusive task holder assignment", 12000),
	(0x006FBAE0, "BGSTerrainChunkLoadTask scalar destructor", 12000),
	(0x006FDC12, "Save-load crash outer caller at 0x006fdc12", 28000),
	(0x006FDD26, "Save-load crash direct terrain-request caller at 0x006fdd26", 28000)
]

lod_other = [
	(0x006F6D10, "BGSDistantObjectBlockLoadTask producer", 26000),
	(0x006F9360, "BGSDistantTreeBlockLoadTask producer", 22000),
	(0x006F5160, "Object LOD request caller A", 26000),
	(0x006F6270, "Object LOD request caller B", 24000),
	(0x006F6370, "Object LOD request caller C", 24000),
	(0x006F6540, "Object LOD request caller D", 24000),
	(0x006F7540, "Tree LOD request caller", 24000)
]

write("")
write("# CORE IOTASK REFERENCE CONTRACT")
audit_addresses(core_lifetime)
write("")
write("# QUEUE PUBLICATION AND RELEASE CONTRACT")
audit_addresses(queue_lifetime)
write("")
write("# CRASHING TERRAIN PRODUCER-TO-HOLDER WINDOW")
audit_addresses(lod_terrain)
write("")
write("# OBJECT AND TREE PRODUCER CONSISTENCY")
audit_addresses(lod_other)

write("")
write("# EXACT INTERVENTION WINDOWS")
print_instruction_window(0x006FA324, "terrain producer call through holder AddRef", 20, 48)
print_instruction_window(0x006FBAB2, "terrain producer file publication before return", 24, 40)
print_instruction_window(0x006F7528, "holder first AddRef crash caller", 20, 24)
print_instruction_window(0x00C3CF40, "file attachment or publication entry", 12, 48)
print_instruction_window(0x00C3DE80, "IOManager submission entry", 14, 56)
print_instruction_window(0x00C3CAE0, "priority propagation entry", 14, 56)
print_reference_windows(0x00C3CF40, "IOTask file or queue attachment", 40, 18, 40)
print_reference_windows(0x00C3DE80, "IOManager task submission", 40, 18, 44)
print_reference_windows(0x006F74F0, "intrusive task holder assignment", 40, 18, 34)

write("")
write("END LOD MULTI-WORKER SAVE-LOAD OWNERSHIP FINAL AUDIT")

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/lod_multiworker_save_load_ownership_final_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
