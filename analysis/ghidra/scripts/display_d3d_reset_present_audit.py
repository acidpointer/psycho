# @category Analysis
# @description Audit D3D9 TestCooperativeLevel, Reset, Present, and related render loop callsites for alt-tab recovery

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
sym_tab = currentProgram.getSymbolTable()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x004DC020: "renderer/device accessor used before TestCooperativeLevel",
	0x004DC1E0: "HWND/render window accessor",
	0x004DC1F0: "render width accessor",
	0x004DC200: "render height accessor",
	0x004DC6E0: "render size update helper",
	0x0086BA10: "device-lost helper A",
	0x0086BA90: "device-lost helper B",
	0x0086E650: "active render/update helper",
	0x00E72E60: "NiDX9Renderer device initialization",
	0x00E6C240: "D3D post-create/backbuffer validation",
	0x00A62030: "texture/cache pre-reset helper",
	0x00A62090: "texture/cache reset helper",
	0x011C73B4: "NiDX9Renderer singleton pointer",
}

TARGETS = [
	0x004DC020,
	0x004DC1E0,
	0x004DC1F0,
	0x004DC200,
	0x004DC6E0,
	0x0086BA10,
	0x0086BA90,
	0x0086E650,
	0x00E72E60,
	0x00E6C240,
	0x00A62030,
	0x00A62090,
]

VTABLE_OFFSETS = [
	(0x0C, "IDirect3DDevice9::TestCooperativeLevel"),
	(0x10, "IDirect3DDevice9::GetAvailableTextureMem"),
	(0x14, "IDirect3DDevice9::EvictManagedResources"),
	(0x40, "IDirect3DDevice9::Reset"),
	(0x44, "IDirect3DDevice9::Present"),
	(0x48, "IDirect3DDevice9::GetBackBuffer"),
	(0x5C, "IDirect3DDevice9::CreateTexture"),
	(0x60, "IDirect3DDevice9::CreateVolumeTexture"),
	(0x64, "IDirect3DDevice9::CreateCubeTexture"),
	(0x68, "IDirect3DDevice9::CreateVertexBuffer"),
	(0x6C, "IDirect3DDevice9::CreateIndexBuffer"),
]

def write(msg):
	output.append(msg)
	print(msg)

def label_for(addr_int):
	label = KNOWN.get(addr_int)
	if label is not None:
		return label
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is not None:
		return func.getName()
	func = fm.getFunctionContaining(toAddr(addr_int))
	if func is not None:
		return "%s+0x%x" % (func.getName(), addr_int - func.getEntryPoint().getOffset())
	sym = sym_tab.getPrimarySymbol(toAddr(addr_int))
	if sym is not None:
		return sym.getName()
	return "unknown"

def decompile_at(addr_int, label, max_len=18000):
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
		if count > 160:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)

def find_and_print_calls_from(addr_int, label):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	write("")
	write("--- Calls FROM %s (0x%08x) ---" % (label, addr_int))
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
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, label_for(tgt)))
				count += 1
	write("  Total: %d calls" % count)

def disasm_window(center_int, before_count, after_count, label):
	write("")
	write("-" * 70)
	write("Disassembly %s around 0x%08x" % (label, center_int))
	write("-" * 70)
	inst = listing.getInstructionAt(toAddr(center_int))
	if inst is None:
		inst = listing.getInstructionBefore(toAddr(center_int))
	count = 0
	while inst is not None and count < before_count:
		prev = inst.getPrevious()
		if prev is None:
			break
		inst = prev
		count += 1
	idx = 0
	limit = before_count + after_count + 1
	while inst is not None and idx < limit:
		addr_int = inst.getAddress().getOffset()
		marker = " << TARGET" if addr_int == center_int else ""
		write("  0x%08x: %-52s%s" % (addr_int, inst.toString(), marker))
		inst = inst.getNext()
		idx += 1

def inst_has_vtable_offset(text, offset):
	hex_plain = "0x%x" % offset
	hex_pad = "0x%02x" % offset
	dec_text = "%d" % offset
	lower = text.lower()
	if ("+ " + hex_plain) in lower or ("+ " + hex_pad) in lower:
		return True
	if ("+ " + dec_text) in lower:
		return True
	if (" + " + hex_plain) in lower or (" + " + hex_pad) in lower:
		return True
	return False

def scan_function_for_device_vtable(addr_int, label):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	write("")
	write("-" * 70)
	write("D3D device vtable-call candidates in %s (0x%08x)" % (label, addr_int))
	write("-" * 70)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		text = inst.toString()
		matched = []
		for item in VTABLE_OFFSETS:
			if inst_has_vtable_offset(text, item[0]):
				matched.append(item[1])
		if len(matched) != 0:
			write("  0x%08x: %-52s ; %s" % (inst.getAddress().getOffset(), text, ", ".join(matched)))
			count += 1
			if count > 220:
				write("  ... (truncated)")
				break
	write("  Total candidates: %d" % count)

def find_callers_and_scan(target_addr, label):
	write("")
	write("-" * 70)
	write("Callers of %s (0x%08x), scanned for D3D device vtable calls" % (label, target_addr))
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(target_addr))
	seen = {}
	count = 0
	while refs.hasNext():
		ref = refs.next()
		if not ref.getReferenceType().isCall():
			continue
		func = fm.getFunctionContaining(ref.getFromAddress())
		if func is None:
			continue
		entry = func.getEntryPoint().getOffset()
		if seen.get(entry) is not None:
			continue
		seen[entry] = True
		write("  caller %s @ 0x%08x via 0x%08x" % (func.getName(), entry, ref.getFromAddress().getOffset()))
		scan_function_for_device_vtable(entry, func.getName())
		count += 1
		if count > 80:
			write("  ... callers truncated")
			break
	write("  Total caller funcs scanned: %d" % count)

def print_targets():
	for addr_int in TARGETS:
		label = label_for(addr_int)
		decompile_at(addr_int, label)
		find_and_print_calls_from(addr_int, label)
		find_refs_to(addr_int, label)
		scan_function_for_device_vtable(addr_int, label)

def print_known_windows():
	windows = [
		(0x0086B535, "main loop TestCooperativeLevel call"),
		(0x0086BA10, "device-lost helper A entry"),
		(0x0086BA90, "device-lost helper B entry"),
		(0x0086E650, "active render/update helper entry")
	]
	for item in windows:
		disasm_window(item[0], 40, 70, item[1])

def main():
	write("DISPLAY D3D RESET/PRESENT AUDIT")
	write("Goal: find the real lost-device/reset/present path before changing alt-tab behavior.")
	print_targets()
	find_callers_and_scan(0x004DC020, "renderer/device accessor")
	find_callers_and_scan(0x004DC6E0, "render size update helper")
	print_known_windows()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/display_d3d_reset_present_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
