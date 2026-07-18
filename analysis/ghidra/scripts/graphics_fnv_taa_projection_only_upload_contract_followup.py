# @category Analysis
# @description Resolve the NiDX9Renderer SetCameraData vtable target and prove a projection-only TAA jitter boundary

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

NIDX9_RENDERER_VTABLE = 0x010EE4BC
SET_CAMERA_DATA_SLOT = 0x18C

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
	except Exception as error:
		write("  Failed reading 0x%08x: %s" % (addr_int, error))
		return None

def print_vtable_window(base_int, first_offset, last_offset, label):
	write("")
	write("=" * 70)
	write("%s @ 0x%08x" % (label, base_int))
	write("=" * 70)
	offset = first_offset
	while offset <= last_offset:
		target = read_u32(base_int + offset)
		if target is None:
			write("  +0x%03x: [unreadable]" % offset)
		else:
			func = fm.getFunctionAt(toAddr(target))
			name = func.getName() if func else "???"
			marker = " << SET CAMERA DATA" if offset == SET_CAMERA_DATA_SLOT else ""
			write("  [%03d] +0x%03x: 0x%08x -> %s%s" % (offset / 4, offset, target, name, marker))
		offset += 4

def disassemble_function(addr_int, label, max_instructions=700):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	write("")
	write("=" * 70)
	write("FULL DISASSEMBLY: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext() and count < max_instructions:
		inst = inst_iter.next()
		extra = ""
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				target = ref.getToAddress().getOffset()
				target_func = fm.getFunctionAt(toAddr(target))
				name = target_func.getName() if target_func else "???"
				extra = " ; CALL 0x%08x %s" % (target, name)
		write("  0x%08x: %-64s%s" % (inst.getAddress().getOffset(), inst.toString(), extra))
		count += 1
	if inst_iter.hasNext():
		write("  ... disassembly truncated after %d instructions" % count)
	write("  Total printed: %d instructions" % count)

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

def print_memory_operands(addr_int, label):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	write("")
	write("=" * 70)
	write("MEMORY OPERANDS: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		text = inst.toString()
		if "[" not in text or "]" not in text:
			continue
		write("  0x%08x: %s" % (inst.getAddress().getOffset(), text))
		count += 1
	write("  Total: %d memory-operand instructions" % count)

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

def audit_set_camera_slot():
	target = read_u32(NIDX9_RENDERER_VTABLE + SET_CAMERA_DATA_SLOT)
	write("")
	write("=" * 70)
	write("RESOLVED SET CAMERA DATA SLOT")
	write("=" * 70)
	if target is None:
		write("  Slot could not be read")
		return
	write("  NiDX9Renderer vtable: 0x%08x" % NIDX9_RENDERER_VTABLE)
	write("  Slot: +0x%03x (index %d)" % (SET_CAMERA_DATA_SLOT, SET_CAMERA_DATA_SLOT / 4))
	write("  Target: 0x%08x" % target)
	decompile_at(target, "NiDX9Renderer SetCameraData implementation", 30000)
	find_refs_to(target, "NiDX9Renderer SetCameraData implementation")
	find_and_print_calls_from(target, "NiDX9Renderer SetCameraData implementation")
	disassemble_function(target, "NiDX9Renderer SetCameraData implementation")
	print_memory_operands(target, "NiDX9Renderer SetCameraData implementation")
	decompile_direct_callees(target, "NiDX9Renderer SetCameraData implementation")

write("FNV TAA PROJECTION-ONLY UPLOAD CONTRACT FOLLOWUP")
write("")
write("Proven input from the prior audit:")
write("Entry-wide NiCamera frustum jitter is copied into the culling process and used to build six world-space clip planes.")
write("")
write("Questions:")
write("1. What exact NiDX9Renderer function occupies vtable slot +0x18C?")
write("2. Does it synchronously copy/derive projection state, or retain camera/frustum pointers after return?")
write("3. Which renderer and D3D state fields receive the projection derived from the frustum?")
write("4. Can OMV jitter only during the direct 0x00B6BA35 SetCameraData call and restore immediately afterward?")
write("5. Does that boundary leave culling, LOD, first-person, UI, and later camera users unjittered?")

print_vtable_window(NIDX9_RENDERER_VTABLE, 0x170, 0x1A8, "NiDX9Renderer vtable window")
find_refs_to(NIDX9_RENDERER_VTABLE, "NiDX9Renderer vtable")
decompile_at(0x00E75A70, "NiDX9Renderer constructor/destructor vtable writer A", 14000)
decompile_at(0x00E754A0, "NiDX9Renderer constructor/destructor vtable writer B", 14000)

decompile_at(0x004E9BB0, "NiRenderer::SetCameraData front end", 18000)
decompile_at(0x004E9C90, "NiRenderer SetCameraData virtual dispatch", 14000)
disassemble_window(0x004E9BFE, 30, 25, "SetCameraData argument construction and virtual dispatch")
disassemble_window(0x00B6BA35, 18, 30, "unique world SetCameraData direct call")
find_refs_to(0x00B6BA20, "unique world rendered-texture camera setup")
audit_set_camera_slot()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_taa_projection_only_upload_contract_followup.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("")
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
