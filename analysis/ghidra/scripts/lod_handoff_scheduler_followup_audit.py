# @category Analysis
# @description Close the remaining FNV LOD scheduler, ready-counter, attach-task, retirement, and undefined virtual-slot contract gaps

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

def read_u32(addr_int):
	try:
		return memory.getInt(toAddr(addr_int)) & 0xffffffff
	except:
		return None

def decompile_once(addr_int, label, max_len):
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

def collect_callers(addr_int):
	callers = {}
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	while refs.hasNext():
		ref = refs.next()
		if ref.getReferenceType().isCall():
			func = fm.getFunctionContaining(ref.getFromAddress())
			if func is not None:
				callers[func.getEntryPoint().getOffset()] = True
	return sorted(callers.keys())

def decompile_callers(addr_int, label, limit, max_len):
	callers = collect_callers(addr_int)
	idx = 0
	while idx < len(callers) and idx < limit:
		entry = callers[idx]
		decompile_once(entry, "%s caller %d" % (label, idx + 1), max_len)
		find_and_print_calls_from(entry, "%s caller %d" % (label, idx + 1))
		idx += 1
	write("  Caller functions considered: %d of %d" % (idx, len(callers)))

def audit_known_function(addr_int, label, max_len, caller_limit):
	decompile_once(addr_int, label, max_len)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)
	decompile_callers(addr_int, label, caller_limit, max_len)

def print_instruction_window(addr_int, label, max_instructions):
	write("")
	write("-" * 70)
	write("INSTRUCTION WINDOW: %s @ 0x%08x" % (label, addr_int))
	write("-" * 70)
	inst = listing.getInstructionAt(toAddr(addr_int))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(addr_int - 1))
	count = 0
	while inst is not None and count < max_instructions:
		write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
		refs = inst.getReferencesFrom()
		for ref in refs:
			write("    %s -> 0x%08x" % (ref.getReferenceType(), ref.getToAddress().getOffset()))
		inst = inst.getNext()
		count += 1
	write("  Instructions printed: %d" % count)

def print_vtable(vtable, label, max_slots):
	methods = []
	write("")
	write("-" * 70)
	write("%s vtable @ 0x%08x" % (label, vtable))
	write("-" * 70)
	idx = 0
	while idx < max_slots:
		target = read_u32(vtable + idx * 4)
		if target is None:
			write("  [%02d] unreadable" % idx)
			break
		func = fm.getFunctionAt(toAddr(target))
		if func is None:
			func = fm.getFunctionContaining(toAddr(target))
		name = func.getName() if func is not None else "???"
		write("  [%02d] +0x%02x -> 0x%08x %s" % (idx, idx * 4, target, name))
		if 0x00400000 <= target < 0x01000000:
			methods.append((idx, target))
		elif idx >= 5:
			break
		idx += 1
	return methods

def audit_vtable(vtable, label, max_slots, max_len):
	write("")
	write("#" * 70)
	write("VTABLE CONTRACT: %s" % label)
	write("#" * 70)
	methods = print_vtable(vtable, label, max_slots)
	idx = 0
	while idx < len(methods):
		item = methods[idx]
		slot = item[0]
		target = item[1]
		func = fm.getFunctionAt(toAddr(target))
		if func is None:
			func = fm.getFunctionContaining(toAddr(target))
		if func is None:
			print_instruction_window(target, "%s undefined slot %d" % (label, slot), 80)
		else:
			decompile_once(target, "%s slot %d" % (label, slot), max_len)
			find_and_print_calls_from(target, "%s slot %d" % (label, slot))
		idx += 1

def audit_undefined_vtable_targets(vtable, label, max_slots):
	write("")
	write("#" * 70)
	write("UNDEFINED VIRTUAL TARGETS: %s" % label)
	write("#" * 70)
	methods = print_vtable(vtable, label, max_slots)
	seen = {}
	idx = 0
	while idx < len(methods):
		item = methods[idx]
		slot = item[0]
		target = item[1]
		func = fm.getFunctionAt(toAddr(target))
		if func is None:
			func = fm.getFunctionContaining(toAddr(target))
		if func is None and target not in seen:
			seen[target] = True
			print_instruction_window(target, "%s undefined slot %d" % (label, slot), 80)
		idx += 1

write("FNV LOD HANDOFF AND SCHEDULER FOLLOW-UP AUDIT")
write("")
write("This follow-up closes gaps left by the two broad LOD audits:")
write("1. Exact IOManager and IOTask virtual-slot ownership from submission through worker execution and completion.")
write("2. Exact AttachDistant3DTask submission, cancellation, and main-thread real-3D publication path.")
write("3. Exact TESObjectCELL +0xA8 total and +0xAA ready counter lifecycle, retirement guard, and retirement action.")
write("4. Raw bodies for undefined NiLOD and BSFade virtual targets that can affect selection, traversal, or visibility.")

audit_known_function(0x00C3C620, "IOTask base destruction and final ownership release", 50000, 8)
audit_known_function(0x00C3C700, "IOTask primary dependency ownership insertion", 50000, 8)
audit_known_function(0x00C3C7E0, "IOTask dependency set deduplication and insertion", 50000, 8)
audit_known_function(0x00C3C930, "IOTask dependency-ready scheduling transition", 70000, 12)
audit_known_function(0x00C3D4F0, "IOTask dependency array ownership helper", 50000, 8)
audit_known_function(0x00C3DBF0, "main-thread completed IOTask callback loop", 70000, 8)
audit_known_function(0x00C3E420, "completed IOTask queue pop", 50000, 8)
audit_known_function(0x00C3E490, "IOManager worker queue pop wrapper", 50000, 8)
audit_known_function(0x00C3EA60, "IOManager lock-free queue transition and ownership release", 70000, 8)
audit_known_function(0x00C3F090, "IOManager completion-node recycle", 50000, 8)
audit_vtable(0x010C1524, "IOTask base", 20, 70000)
audit_vtable(0x010C1604, "IOManager", 28, 70000)

audit_known_function(0x00440310, "real-reference distant-3D attach producer", 70000, 12)
audit_known_function(0x004404C0, "AttachDistant3DTask constructor", 50000, 8)
audit_known_function(0x00440540, "AttachDistant3DTask base constructor", 50000, 8)
audit_known_function(0x00440710, "AttachDistant3DTask queue submission", 70000, 12)
audit_known_function(0x0043FC40, "AttachDistant3DTask real-3D publication callback", 70000, 12)
audit_known_function(0x00440660, "AttachDistant3DTask priority or cancellation transition", 50000, 8)
audit_known_function(0x00451EF0, "real TESObjectREFR 3D creation, attach, and ready publication", 100000, 12)
audit_vtable(0x01016BEC, "AttachDistant3DTask", 12, 70000)

audit_known_function(0x00452390, "TESObjectCELL +0xAA ready counter increment", 40000, 12)
audit_known_function(0x005495A0, "TESObjectCELL VWD total-versus-ready gate", 40000, 12)
audit_known_function(0x00557D10, "cell distant-retirement eligibility guard", 70000, 12)
audit_known_function(0x00557AA0, "cell distant representation retirement action", 90000, 12)
audit_known_function(0x0054CA90, "TESObjectCELL reference removal and +0xA8 decrement", 90000, 8)
audit_known_function(0x0055E1D0, "TESObjectCELL alternate +0xA8 decrement", 50000, 8)
audit_known_function(0x0054CD20, "TESObjectCELL teardown counter reset", 70000, 8)
audit_known_function(0x005508B0, "TESObjectCELL reload counter reset", 90000, 8)
print_instruction_window(0x004520AC, "ready increment call-site register ownership", 24)
print_instruction_window(0x00549520, "cell gate and retirement call sequence", 28)
print_instruction_window(0x005519A0, "per-frame cell gate and retirement call sequence", 28)

audit_undefined_vtable_targets(0x01082CCC, "BSFadeNodeCuller", 24)
audit_undefined_vtable_targets(0x010A001C, "NiSwitchNode", 48)
audit_undefined_vtable_targets(0x010A051C, "NiScreenLODData", 24)
audit_undefined_vtable_targets(0x010A2254, "NiLODData", 24)
audit_undefined_vtable_targets(0x010A073C, "NiRangeLODData", 24)
audit_undefined_vtable_targets(0x010A0B64, "NiLODNode", 48)
audit_undefined_vtable_targets(0x010A8F90, "BSFadeNode", 48)

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/lod_handoff_scheduler_followup_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
