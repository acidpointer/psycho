# @category Analysis
# @description Prove the BSTreeManager LockFreeMap TLS slot budget and every save-load participant behind crash 0x006EC846

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
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
	decompile_at(entry, label, max_len)

def audit_function(addr_int, label, max_len=16000):
	decompile_once(addr_int, label, max_len)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)

def decompile_callers(addr_int, label, limit=80):
	write("")
	write("=" * 70)
	write("Decompiled callers of %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	seen = set()
	count = 0
	while refs.hasNext() and count < limit:
		ref = refs.next()
		if ref.getReferenceType().isCall():
			func = fm.getFunctionContaining(ref.getFromAddress())
			if func is not None:
				entry = func.getEntryPoint().getOffset()
				if entry not in seen:
					seen.add(entry)
					decompile_once(entry, "%s caller" % label, 18000)
					find_and_print_calls_from(entry, "%s caller" % label)
					count += 1
	write("  Total unique callers: %d" % count)

def decompile_direct_callees(addr_int, label, limit=80):
	write("")
	write("=" * 70)
	write("Direct callees of %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	if func is None:
		write("  [function not found]")
		return
	seen = set()
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext() and count < limit:
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				target = ref.getToAddress().getOffset()
				if target not in seen and fm.getFunctionAt(toAddr(target)) is not None:
					seen.add(target)
					decompile_once(target, "%s direct callee" % label, 14000)
					count += 1
	write("  Total unique callees: %d" % count)

def print_function_instructions(addr_int, label, limit=500):
	write("")
	write("=" * 70)
	write("Full instructions for %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext() and count < limit:
		inst = inst_iter.next()
		write("  0x%08x  %s" % (inst.getAddress().getOffset(), inst))
		count += 1
	if inst_iter.hasNext():
		write("  [truncated after %d instructions]" % limit)
	write("  Total printed: %d" % count)

def print_reference_windows(addr_int, label, limit=80, before=18, after=45):
	write("")
	write("=" * 70)
	write("Code-reference windows to %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext() and count < limit:
		ref = refs.next()
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
	write("  Total code references: %d" % count)

def read_u32(addr_int):
	try:
		return memory.getInt(toAddr(addr_int)) & 0xffffffff
	except:
		return None

def print_data_ref_neighborhoods(addr_int, label, before_slots=18, after_slots=18):
	write("")
	write("=" * 70)
	write("Data-reference neighborhoods to %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		from_addr = ref.getFromAddress()
		if listing.getInstructionContaining(from_addr) is None:
			write("")
			write("-" * 70)
			write("Data reference at 0x%08x" % from_addr.getOffset())
			index = -before_slots
			while index <= after_slots:
				slot_addr = from_addr.getOffset() + index * 4
				value = read_u32(slot_addr)
				marker = "  "
				if index == 0:
					marker = ">>"
				if value is None:
					write("%s 0x%08x: [unreadable]" % (marker, slot_addr))
				else:
					func = fm.getFunctionAt(toAddr(value))
					name = func.getName() if func else "???"
					write("%s 0x%08x: 0x%08x %s" % (marker, slot_addr, value, name))
				index += 1
			count += 1
	write("  Total data references: %d" % count)

write("LOD BSTREE TLS SLOT EXHAUSTION ROOT-CAUSE AUDIT")
write("Program: %s" % currentProgram.getName())
write("Image base: %s" % currentProgram.getImageBase())
write("")
write("Crash: 0x006EC846 because 0x00449F80 returned a null per-thread map object")
write("Goal: prove the exact BSTreeManager capacity, constructor family, and all thread participants")

write("")
write("# BSTREE MANAGER CONSTRUCTION AND MAP ARGUMENTS")
audit_function(0x00664440, "BSTreeManager object constructor", 24000)
print_function_instructions(0x00664440, "BSTreeManager object constructor", 500)
decompile_direct_callees(0x00664440, "BSTreeManager object constructor", 80)
audit_function(0x00664870, "BSTreeManager singleton creation", 18000)
audit_function(0x00664940, "BSTreeManager singleton destruction", 12000)

write("")
write("# LOCKFREEMAP CONSTRUCTOR FAMILIES AND CAPACITY STORAGE")
audit_function(0x0044C040, "LockFreeMap constructor family A", 20000)
audit_function(0x0044C270, "LockFreeMap constructor family B", 20000)
audit_function(0x00449FA0, "LockFreeMap family B public constructor", 12000)
decompile_callers(0x0044C040, "LockFreeMap constructor family A", 40)
decompile_callers(0x0044C270, "LockFreeMap constructor family B", 40)
decompile_callers(0x00449FA0, "LockFreeMap family B public constructor", 40)
print_reference_windows(0x0044C040, "LockFreeMap constructor family A", 40, 20, 55)
print_reference_windows(0x0044C270, "LockFreeMap constructor family B", 40, 20, 55)
print_reference_windows(0x00449FA0, "LockFreeMap family B public constructor", 40, 20, 55)

write("")
write("# TLS SLOT ALLOCATION FAILURE CONTRACT")
audit_function(0x00449F80, "LockFreeMap current-thread object getter", 12000)
audit_function(0x0044D5B0, "LockFreeMap TlsGetValue wrapper", 10000)
audit_function(0x0044D5C0, "LockFreeMap TLS lookup and lazy allocation", 14000)
audit_function(0x0044E3A0, "LockFreeMap TLS slot allocator and capacity gate", 18000)
audit_function(0x0044E340, "LockFreeMap TlsSetValue wrapper", 10000)
print_function_instructions(0x0044E3A0, "LockFreeMap TLS slot allocator and capacity gate", 180)
print_reference_windows(0x00449F80, "LockFreeMap current-thread object getter", 80, 16, 32)

write("")
write("# CRASHING BSTREE MAP VTABLE AND OPERATIONS")
audit_function(0x00449530, "Crashing BSTree map find wrapper", 14000)
audit_function(0x004498B0, "Second wrapper with the same null consumer", 14000)
audit_function(0x006EC830, "Null-consuming BSTree map operation", 12000)
audit_function(0x006EC7E0, "Adjacent BSTree map operation", 14000)
audit_function(0x006EC9B0, "BSTree map result publication", 14000)
print_data_ref_neighborhoods(0x00449530, "Crashing BSTree map find wrapper", 22, 22)
print_data_ref_neighborhoods(0x00449FA0, "BSTree map constructor wrapper", 22, 22)

write("")
write("# ALL BSTREE LOAD CALLERS AND SAVE-LOAD PARTICIPANTS")
audit_function(0x00664F50, "BSTreeManager find or load", 24000)
decompile_callers(0x00664F50, "BSTreeManager find or load", 80)
audit_function(0x0043DA00, "Queued tree worker execute path", 18000)
audit_function(0x0050F810, "QueuedReference main completion tree path", 18000)
audit_function(0x00C3DBF0, "Main-thread completed-task drain", 22000)
audit_function(0x00C3DFA0, "Blocking ModelLoader save-load drain", 22000)
audit_function(0x00C3EE70, "IO worker thread object constructor", 18000)
audit_function(0x00C3E4F0, "BSTaskManager worker and TLS-capacity constructor", 22000)
audit_function(0x00C3DA50, "IOManager constructor", 18000)
print_reference_windows(0x00664F50, "BSTreeManager find or load", 80, 18, 48)

write("")
write("# SINGLETON AND THREAD-ROLE CROSS-CHECKS")
find_refs_to(0x011D5C48, "BSTreeManager singleton")
find_refs_to(0x01202D98, "IOManager singleton")
find_refs_to(0x00C3EE70, "IO worker thread object constructor")

write("")
write("END OF AUDIT")

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/lod_bstree_tls_slot_exhaustion_root_cause_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
