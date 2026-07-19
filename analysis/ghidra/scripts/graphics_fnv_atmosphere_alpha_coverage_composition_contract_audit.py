# @category Analysis
# @description Prove the FNV alpha-tested foliage, MSAA resolve, and atmosphere composition stage contract

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
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
	inst_iter = listing.getInstructions(body, True)
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
	except Exception as error:
		write("  Failed reading 0x%08x: %s" % (addr_int, error))
		return None

def disassemble_window(center_int, before_count, after_count, label):
	center = toAddr(center_int)
	inst = listing.getInstructionContaining(center)
	write("")
	write("-" * 70)
	write("Disassembly %s around 0x%08x" % (label, center_int))
	write("-" * 70)
	if inst is None:
		write("  [instruction not found]")
		return
	start = inst
	count = 0
	while count < before_count:
		previous = start.getPrevious()
		if previous is None:
			break
		start = previous
		count += 1
	current = start
	remaining = before_count + after_count + 1
	while current is not None and remaining > 0:
		marker = " <<" if current.getAddress().getOffset() == inst.getAddress().getOffset() else ""
		write("  0x%08x: %-58s%s" % (current.getAddress().getOffset(), current.toString(), marker))
		current = current.getNext()
		remaining -= 1

def decompile_direct_callees(addr_int, label, max_functions=32, max_len=12000):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	write("")
	write("=" * 70)
	write("DIRECT CALLEE DECOMPILATIONS: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	if func is None:
		write("  [function not found]")
		return
	targets = []
	seen = set()
	inst_iter = listing.getInstructions(func.getBody(), True)
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if not ref.getReferenceType().isCall():
				continue
			target = ref.getToAddress().getOffset()
			if target in seen:
				continue
			seen.add(target)
			targets.append(target)
	targets.sort()
	count = 0
	for target in targets:
		if count >= max_functions:
			write("  Callee list truncated after %d functions" % count)
			break
		decompile_at(target, "direct callee %d" % (count + 1), max_len)
		count += 1
	write("  Decompiled: %d of %d direct callees" % (count, len(targets)))

def print_vtable_entries(base_int, entry_count, label):
	write("")
	write("=" * 70)
	write("VTABLE: %s @ 0x%08x" % (label, base_int))
	write("=" * 70)
	index = 0
	while index < entry_count:
		target = read_u32(base_int + index * 4)
		if target is None:
			write("  [%02d] [unreadable]" % index)
		else:
			func = fm.getFunctionAt(toAddr(target))
			name = func.getName() if func else "???"
			write("  [%02d] +0x%03x: 0x%08x -> %s" % (index, index * 4, target, name))
		index += 1

def decompile_vtable_entries(base_int, first_index, last_index, label, max_len=10000):
	write("")
	write("=" * 70)
	write("VTABLE METHODS: %s" % label)
	write("=" * 70)
	index = first_index
	seen = set()
	while index <= last_index:
		target = read_u32(base_int + index * 4)
		if target is not None and target not in seen:
			seen.add(target)
			decompile_at(target, "%s vtable[%d]" % (label, index), max_len)
		index += 1

def audit_function(addr_int, label, max_len=18000, callees=False):
	decompile_at(addr_int, label, max_len)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)
	if callees:
		decompile_direct_callees(addr_int, label, 24, 10000)

write("FNV ATMOSPHERE ALPHA-COVERAGE COMPOSITION CONTRACT AUDIT")
write("")
write("Observed failure to explain:")
write("Strong OMV atmosphere can leave alpha-tested foliage or grass black instead of integrating it into fog.")
write("")
write("Questions:")
write("1. Which accumulator groups own TallGrass, SpeedTree leaf, and other alpha-tested/A2C geometry?")
write("2. Are those groups complete when RenderWorldSceneGraph returns to OMV?")
write("3. Does native image-space effect 0x22 resolve MSAA before or after those alpha groups?")
write("4. Which exact color surface preserves alpha-to-coverage results, and when is it safe to sample and compose?")
write("5. Which D3D alpha-test, multisample, sample-mask, and adaptive-tessellation states do foliage shaders set and restore?")
write("6. Is there a resolved world-color boundary before first-person rendering, or must atmosphere preserve per-sample coverage on the MSAA target?")

audit_function(0x00873200, "RenderWorldSceneGraph entry and OMV return boundary", 30000, True)
audit_function(0x00875110, "RenderFirstPerson boundary", 22000, True)
audit_function(0x00B65AE0, "standard accumulator pre/post-depth owner", 26000, True)
audit_function(0x00B65C60, "FinishAccumulating post-depth group owner", 30000, True)
audit_function(0x00B639E0, "RenderGeometryGroup", 24000, True)
audit_function(0x00B650C0, "alpha blend group renderer", 24000, True)
audit_function(0x00B63120, "geometry group range classifier", 18000, True)

disassemble_window(0x00B65CD1, 45, 95, "effect 0x22 and following alpha groups")
disassemble_window(0x00870E18, 35, 55, "main world render invocation")
disassemble_window(0x008710E4, 45, 60, "main image-space invocation")

audit_function(0x00B55AC0, "ProcessImageSpaceShaders front end", 26000, True)
audit_function(0x00B97550, "ImageSpace RenderEffect", 26000, True)
audit_function(0x00B8C830, "image-space effect dispatch", 26000, True)
audit_function(0x00B97900, "native image-space ping-pong owner", 30000, True)
audit_function(0x00875FD0, "main image-space owner", 30000, True)
audit_function(0x00870BD0, "main render caller C", 30000, True)

print_vtable_entries(0x010B8980, 28, "TallGrassShader")
find_refs_to(0x010B8980, "TallGrassShader vtable")
decompile_vtable_entries(0x010B8980, 0, 27, "TallGrassShader", 12000)

print_vtable_entries(0x010B9190, 28, "SpeedTreeLeafShader")
find_refs_to(0x010B9190, "SpeedTreeLeafShader vtable")
decompile_vtable_entries(0x010B9190, 0, 27, "SpeedTreeLeafShader", 12000)

print_vtable_entries(0x010BC070, 28, "SpeedTreeBranchShader")
find_refs_to(0x010BC070, "SpeedTreeBranchShader vtable")
decompile_vtable_entries(0x010BC070, 0, 27, "SpeedTreeBranchShader", 12000)

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_atmosphere_alpha_coverage_composition_contract_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("")
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
