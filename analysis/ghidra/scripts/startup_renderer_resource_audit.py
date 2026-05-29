# @category Analysis
# @description Audit renderer resource creation, shader/texture paths, and NVR/Stewie compatibility surfaces

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
sym_tab = currentProgram.getSymbolTable()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x0086D500: "NVR: InitializeRenderer",
	0x00442650: "NVR: NewQueuedModelLoader",
	0x00447080: "ModelLoader LoadFile candidate",
	0x00BE0FE0: "NVR: CreateVertexShader",
	0x00BE1750: "NVR: CreatePixelShader",
	0x00B4F710: "NVR: SetShaderPackage",
	0x00BE1F90: "NVR: SetShaders",
	0x00E910A0: "NVR: SetSamplerState",
	0x008706B0: "NVR: Render",
	0x00B55AC0: "NVR: ProcessImageSpaceShaders",
	0x00873200: "NVR: RenderWorldSceneGraph",
	0x00875110: "NVR: RenderFirstPerson",
	0x004E1BC0: "NVR: RenderReflections",
	0x008761E0: "NVR: RenderPipboy",
	0x00871290: "NVR: RenderShadowMaps",
	0x00A61A60: "Texture cache find",
	0x00A5FCA0: "NiSourceTexture destructor",
	0x00E68A80: "Stewie target comment: NiDX9SourceTextureData::E68A80",
	0x00E68BA9: "Stewie texture zeroing callsite",
	0x00E8C051: "Stewie VB lock zeroing callsite",
	0x00E731FF: "NVR jumper: CreateDevice hook",
	0x00E73204: "NVR jumper: CreateDevice return",
	0x007144D3: "NVR jumper: RenderInterface hook",
	0x007134D0: "NVR jumper: RenderInterface method",
	0x00BCAAD7: "NVR jumper: SetTileShaderConstants hook",
	0x008751C0: "NVR patch: skip first-person depth clear byte",
	0x0086A170: "NVR patch: alt-tab pause bypass",
	0x00BE1690: "NVR patch: vertex shader object size",
	0x00BE1DFB: "NVR patch: pixel shader object size",
	0x00E7624D: "NVR patch: renderer object size",
	0x004E4C3B: "NVR patch: reflection water fix 1",
	0x004E4DA4: "NVR patch: reflection water fix 2",
	0x00875B86: "NVR patch: world fov restore call 1",
	0x00875B9D: "NVR patch: world fov restore call 2",
	0x00C03F49: "NVR patch: image space effect fix",
	0x010EE4BC: "NiDX9Renderer vtable",
	0x010ED37C: "NiDX9SourceTextureData vtable",
	0x01016788: "QueuedTexture vtable",
	0x011F91BC: "shader package max global",
	0x011F91C0: "shader package global",
	0x011F91E0: "current geometry global",
	0x0126F74C: "current NiD3DPass global",
	0x0126F92C: "sampler type map global"
}

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
	return "unknown"

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
		if count > 80:
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
		write("  0x%08x: %-44s%s" % (addr_int, inst.toString(), marker))
		inst = inst.getNext()
		idx += 1

def scan_callers_to(addr_int, label, max_callers):
	write("")
	write("=" * 70)
	write("CALLER SCAN: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		if not ref.getReferenceType().isCall():
			continue
		from_addr = ref.getFromAddress()
		from_func = fm.getFunctionContaining(from_addr)
		fname = from_func.getName() if from_func else "???"
		write("")
		write("Caller %d: 0x%08x in %s" % (count + 1, from_addr.getOffset(), fname))
		disasm_window(from_addr.getOffset(), 8, 18, "caller of %s" % label)
		count += 1
		if count >= max_callers:
			write("  ... caller scan truncated")
			break
	write("Total callers printed: %d" % count)

def read_vtable(addr_int, label, count):
	write("")
	write("-" * 70)
	write("VTable/dispatch table %s @ 0x%08x" % (label, addr_int))
	write("-" * 70)
	for idx in range(count):
		slot_addr = addr_int + idx * 4
		try:
			target = getInt(toAddr(slot_addr)) & 0xffffffff
		except:
			write("  [%02d] +0x%02x: <read failed>" % (idx, idx * 4))
			continue
		write("  [%02d] +0x%02x: 0x%08x -> %s" % (idx, idx * 4, target, label_for(target)))

def print_import_refs(name, limit):
	write("")
	write("-" * 70)
	write("Import/symbol refs: %s" % name)
	write("-" * 70)
	symbols = sym_tab.getSymbols(name)
	total = 0
	while symbols.hasNext():
		sym = symbols.next()
		write("  Symbol %s @ %s" % (sym.getName(), sym.getAddress()))
		refs = ref_mgr.getReferencesTo(sym.getAddress())
		count = 0
		while refs.hasNext():
			ref = refs.next()
			from_func = fm.getFunctionContaining(ref.getFromAddress())
			fname = from_func.getName() if from_func else "???"
			write("    %s @ 0x%08x in %s" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname))
			count += 1
			total += 1
			if count >= limit:
				write("    ... refs for this symbol truncated")
				break
	write("  Total printed refs: %d" % total)

def analyze_high_value_functions():
	targets = [
		(0x0086D500, "InitializeRenderer"),
		(0x00442650, "NewQueuedModelLoader"),
		(0x00447080, "ModelLoader LoadFile candidate"),
		(0x00BE0FE0, "CreateVertexShader"),
		(0x00BE1750, "CreatePixelShader"),
		(0x00B4F710, "SetShaderPackage"),
		(0x00BE1F90, "SetShaders"),
		(0x00E910A0, "SetSamplerState"),
		(0x008706B0, "Render"),
		(0x00B55AC0, "ProcessImageSpaceShaders"),
		(0x00873200, "RenderWorldSceneGraph"),
		(0x00875110, "RenderFirstPerson"),
		(0x004E1BC0, "RenderReflections"),
		(0x008761E0, "RenderPipboy"),
		(0x00871290, "RenderShadowMaps"),
		(0x00A61A60, "Texture cache find"),
		(0x00A5FCA0, "NiSourceTexture destructor"),
		(0x00E68A80, "NiDX9SourceTextureData::E68A80 / Stewie target"),
		(0x00E68BA9, "Stewie texture zeroing callsite containing function"),
		(0x00E8C051, "Stewie VB lock zeroing callsite containing function"),
		(0x00E731FF, "CreateDevice hook site containing function")
	]
	for item in targets:
		decompile_at(item[0], item[1], 10000)
		find_and_print_calls_from(item[0], item[1])

def analyze_callers():
	targets = [
		(0x0086D500, "InitializeRenderer"),
		(0x00442650, "NewQueuedModelLoader"),
		(0x00447080, "ModelLoader LoadFile candidate"),
		(0x00BE0FE0, "CreateVertexShader"),
		(0x00BE1750, "CreatePixelShader"),
		(0x00B4F710, "SetShaderPackage"),
		(0x00BE1F90, "SetShaders"),
		(0x00E910A0, "SetSamplerState"),
		(0x00A61A60, "Texture cache find"),
		(0x00A5FCA0, "NiSourceTexture destructor")
	]
	for item in targets:
		scan_callers_to(item[0], item[1], 30)

def analyze_imports():
	names = [
		"Direct3DCreate9",
		"Direct3DCreate9Ex",
		"D3DXCreateTextureFromFileA",
		"D3DXCreateTextureFromFileInMemory",
		"D3DXCreateTextureFromFileInMemoryEx",
		"D3DXCreateVolumeTextureFromFileA",
		"D3DXCreateVolumeTextureFromFileInMemory",
		"D3DXCreateCubeTextureFromFileA",
		"D3DXCreateCubeTextureFromFileInMemory",
		"D3DXCreateBuffer",
		"D3DXCreateEffectFromFileA",
		"D3DXCreateEffectCompilerFromFileA"
	]
	for name in names:
		print_import_refs(name, 40)

def analyze_patch_windows():
	windows = [
		(0x00E731FF, "NVR CreateDevice hook site"),
		(0x00E73204, "NVR CreateDevice return"),
		(0x007144D3, "NVR RenderInterface hook site"),
		(0x007134D0, "NVR RenderInterface method"),
		(0x00BCAAD7, "NVR SetTileShaderConstants hook site"),
		(0x008751C0, "NVR first-person depth clear patch byte"),
		(0x0086A170, "NVR alt-tab pause patch"),
		(0x00BE1690, "NVR vertex shader object size patch"),
		(0x00BE1DFB, "NVR pixel shader object size patch"),
		(0x00E7624D, "NVR renderer object size patch"),
		(0x004E4C3B, "NVR reflection water fix 1"),
		(0x004E4DA4, "NVR reflection water fix 2"),
		(0x00875B86, "NVR world fov restore call 1"),
		(0x00875B9D, "NVR world fov restore call 2"),
		(0x00C03F49, "NVR image space effect fix"),
		(0x00E68BA9, "Stewie texture zeroing callsite"),
		(0x00E8C051, "Stewie VB lock zeroing callsite")
	]
	for item in windows:
		disasm_window(item[0], 10, 18, item[1])

def analyze_refs():
	targets = [
		(0x010EE4BC, "NiDX9Renderer vtable"),
		(0x010ED37C, "NiDX9SourceTextureData vtable"),
		(0x01016788, "QueuedTexture vtable"),
		(0x011F91BC, "shader package max global"),
		(0x011F91C0, "shader package global"),
		(0x011F91E0, "current geometry global"),
		(0x0126F74C, "current NiD3DPass global"),
		(0x0126F92C, "sampler type map global")
	]
	for item in targets:
		find_refs_to(item[0], item[1])

def analyze_vtables():
	read_vtable(0x010EE4BC, "NiDX9Renderer", 64)
	read_vtable(0x010ED37C, "NiDX9SourceTextureData", 40)
	read_vtable(0x01016788, "QueuedTexture", 24)

def main():
	write("=" * 70)
	write("STARTUP RENDERER RESOURCE AUDIT")
	write("=" * 70)
	write("Goal:")
	write("  Identify concrete GPU/resource creation paths that can explain the")
	write("  startup renderer bucket, and list hook/patch surfaces used by NVR and Stewie.")
	write("")
	write("Source hints:")
	write("  NVR attaches InitializeRenderer, shader creation, SetShaderPackage,")
	write("  Render, image-space, scene-graph, first-person, and sampler-state hooks.")
	write("  Stewie skips texture/VB zeroing at 0x00E68BA9 and 0x00E8C051.")
	analyze_patch_windows()
	analyze_high_value_functions()
	analyze_callers()
	analyze_imports()
	analyze_vtables()
	analyze_refs()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/startup_renderer_resource_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
