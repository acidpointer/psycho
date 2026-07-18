# @category Analysis
# @description Prove whether OMV TAA world-camera frustum jitter contaminates FNV culling or LOD before projection upload

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

def print_calls_in_range(func_addr, first_addr, last_addr, label):
	func = fm.getFunctionAt(toAddr(func_addr))
	if func is None:
		func = fm.getFunctionContaining(toAddr(func_addr))
	write("")
	write("-" * 70)
	write("Calls in %s from 0x%08x through 0x%08x" % (label, first_addr, last_addr))
	write("-" * 70)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		inst_addr = inst.getAddress().getOffset()
		if inst_addr < first_addr or inst_addr > last_addr:
			continue
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				target = ref.getToAddress()
				target_func = fm.getFunctionAt(target)
				name = target_func.getName() if target_func else "???"
				write("  0x%08x -> 0x%08x %s" % (inst_addr, target.getOffset(), name))
				count += 1
	write("  Total: %d calls" % count)

def print_offset_operands(addr_int, label, offsets):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	write("")
	write("-" * 70)
	write("Camera/frustum offset operands in %s" % label)
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
		for offset in offsets:
			if offset in text:
				matched = True
				break
		if matched:
			write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
			count += 1
	write("  Total: %d matched instructions" % count)

def collect_data_targets(addr_int):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	targets = []
	seen = set()
	if func is None:
		return targets
	inst_iter = listing.getInstructions(func.getBody(), True)
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if not ref.getReferenceType().isData():
				continue
			target = ref.getToAddress()
			if not target.isMemoryAddress():
				continue
			offset = target.getOffset()
			if offset in seen:
				continue
			seen.add(offset)
			targets.append(offset)
	targets.sort()
	return targets

def print_data_targets_and_consumers(addr_int, label, max_refs_per_target=120):
	targets = collect_data_targets(addr_int)
	write("")
	write("=" * 70)
	write("DATA TARGETS AND CONSUMERS: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	if len(targets) == 0:
		write("  No direct data targets found")
		return
	for target in targets:
		write("")
		write("Data target 0x%08x" % target)
		refs = ref_mgr.getReferencesTo(toAddr(target))
		count = 0
		while refs.hasNext():
			ref = refs.next()
			from_func = fm.getFunctionContaining(ref.getFromAddress())
			fname = from_func.getName() if from_func else "???"
			write("  %s @ 0x%08x (in %s)" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname))
			count += 1
			if count >= max_refs_per_target:
				write("  ... (truncated)")
				break
		write("  Listed: %d refs" % count)

def decompile_data_consumers(addr_int, label, max_functions=36, max_len=7000):
	targets = collect_data_targets(addr_int)
	functions = []
	seen = set()
	for target in targets:
		refs = ref_mgr.getReferencesTo(toAddr(target))
		while refs.hasNext():
			ref = refs.next()
			func = fm.getFunctionContaining(ref.getFromAddress())
			if func is None:
				continue
			entry = func.getEntryPoint().getOffset()
			if entry == addr_int or entry in seen:
				continue
			seen.add(entry)
			functions.append(entry)
	functions.sort()
	write("")
	write("=" * 70)
	write("DECOMPILED DATA CONSUMERS: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	count = 0
	for entry in functions:
		if count >= max_functions:
			write("  Consumer list truncated after %d functions" % count)
			break
		decompile_at(entry, "data consumer %d" % (count + 1), max_len)
		count += 1
	write("  Decompiled: %d of %d discovered consumer functions" % (count, len(functions)))

def decompile_direct_callees(addr_int, label, max_functions=24, max_len=7000):
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

write("FNV TAA FRUSTUM / LOD / CULLING CONTRACT AUDIT")
write("")
write("Runtime fact motivating this audit:")
write("OMV currently mutates the real World NiCamera +0xDC..+0xE8 at RenderWorldSceneGraph entry.")
write("The engine publishes/consumes that frustum at 0x0087338F, before the proven camera upload at 0x00874180.")
write("")
write("Questions:")
write("1. What exact state does FUN_00A694A0 derive or publish from NiCamera +0xDC?")
write("2. Is that state consumed by visibility, culling, LOD, occlusion, or draw-list selection before 0x00874180?")
write("3. Does raw +0xDC..+0xE8 mutation bypass any required camera setter or derived-state update?")
write("4. Does NiRenderer::SetCameraData copy projection state synchronously, allowing a projection-only jitter boundary?")
write("5. What is the narrowest proven point that can receive jitter without changing scene selection?")

disassemble_window(0x0087338F, 70, 90, "early world-frustum publication")
disassemble_window(0x00874180, 90, 70, "world camera upload and first following draw setup")
print_calls_in_range(0x00873200, 0x00873200, 0x008733A0, "RenderWorld entry through early frustum publication")
print_calls_in_range(0x00873200, 0x00873390, 0x00874180, "RenderWorld between frustum publication and camera upload")

decompile_at(0x0045BBE0, "NiCamera frustum getter", 5000)
decompile_at(0x00A694A0, "early frustum-derived-state publisher", 16000)
find_refs_to(0x00A694A0, "early frustum-derived-state publisher")
find_and_print_calls_from(0x00A694A0, "early frustum-derived-state publisher")
print_offset_operands(0x00A694A0, "early frustum-derived-state publisher", ["0xdc", "0xe0", "0xe4", "0xe8", "0xec", "0xf0", "0xf4", "0xf8", "0xfc", "0x100", "0x104", "0x108", "0x10c"])
print_data_targets_and_consumers(0x00A694A0, "early frustum-derived-state publisher")
decompile_direct_callees(0x00A694A0, "early frustum-derived-state publisher")
decompile_data_consumers(0x00A694A0, "early frustum-derived-state publisher")

decompile_at(0x00A6FAF0, "NiCamera frustum setter", 12000)
find_refs_to(0x00A6FAF0, "NiCamera frustum setter")
find_and_print_calls_from(0x00A6FAF0, "NiCamera frustum setter")
print_offset_operands(0x00A6FAF0, "NiCamera frustum setter", ["0xdc", "0xe0", "0xe4", "0xe8", "0xec", "0xf0", "0xf4", "0xf8", "0xfc"])

decompile_at(0x00B6BA20, "world rendered-texture camera setup", 12000)
find_refs_to(0x00B6BA20, "world rendered-texture camera setup")
find_and_print_calls_from(0x00B6BA20, "world rendered-texture camera setup")
decompile_at(0x004E9BB0, "NiRenderer::SetCameraData", 16000)
find_refs_to(0x004E9BB0, "NiRenderer::SetCameraData")
find_and_print_calls_from(0x004E9BB0, "NiRenderer::SetCameraData")
decompile_direct_callees(0x004E9BB0, "NiRenderer::SetCameraData", 16, 10000)
decompile_at(0x004E9C90, "camera-to-renderer projection packet builder", 20000)
find_refs_to(0x004E9C90, "camera-to-renderer projection packet builder")
find_and_print_calls_from(0x004E9C90, "camera-to-renderer projection packet builder")
print_offset_operands(0x004E9C90, "camera-to-renderer projection packet builder", ["0xdc", "0xe0", "0xe4", "0xe8", "0xec", "0xf0", "0xf4", "0xf8", "0xfc", "0x100", "0x104", "0x108", "0x10c"])
print_data_targets_and_consumers(0x004E9C90, "camera-to-renderer projection packet builder", 80)
decompile_direct_callees(0x004E9C90, "camera-to-renderer projection packet builder", 20, 10000)

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_taa_frustum_lod_culling_contract_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("")
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
