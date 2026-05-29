# @category Analysis
# @description Audit the startup renderer timing bucket and direct callees

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x0086A850: "WinMain / startup driver",
	0x0086B01A: "startup marker: Initializing Renderer",
	0x0086B1E1: "startup marker: Initializing Actor Locations",
	0x0086B210: "startup marker: Loading initial area",
	0x0086B230: "startup marker: Placing player",
	0x0086B2D1: "startup marker: Begin Idle loop",
	0x0086D500: "NVR: InitializeRenderer",
	0x0086C160: "NVR: NewMain",
	0x0044FB20: "NVR: NewTES",
	0x00938180: "NVR: NewPlayerCharacter",
	0x00878610: "NVR: NewSceneGraph",
	0x0045D270: "NVR: NewMainDataHandler",
	0x0070A130: "NVR: NewMenuInterfaceManager",
	0x00442650: "NVR: NewQueuedModelLoader",
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
	0x0043C4B0: "frequent startup texture/cache helper",
	0x004A0370: "renderer bucket direct callee",
	0x004A03C0: "renderer bucket direct callee",
	0x0086BBD0: "renderer bucket direct callee",
	0x0086BAE0: "renderer bucket direct callee",
	0x0086BF70: "renderer bucket direct callee",
	0x0086D590: "renderer bucket direct callee after InitializeRenderer",
	0x00702250: "renderer/menu or loading-state callee",
	0x006519F0: "renderer bucket direct callee",
	0x00871C90: "renderer bucket direct callee",
	0x006A2920: "renderer bucket direct callee",
	0x0086C010: "renderer bucket direct callee",
	0x00866FF0: "renderer bucket direct callee",
	0x00403DF0: "renderer bucket direct callee",
	0x00EC16D0: "runtime library/helper call",
	0x00404F70: "thread/context helper",
	0x0045C670: "repeated renderer bucket helper",
	0x0086CF20: "renderer bucket direct callee",
	0x006629F0: "repeated renderer bucket helper",
	0x0086BE90: "renderer bucket direct callee",
	0x0086BE80: "renderer bucket direct callee",
	0x0043D4D0: "renderer bucket direct callee",
	0x00713D80: "renderer bucket direct callee",
	0x008C7290: "renderer bucket direct callee",
	0x006D0870: "renderer bucket direct callee",
	0x0047D0B0: "renderer bucket direct callee",
	0x006EB8C0: "renderer bucket direct callee",
	0x00408D60: "renderer bucket direct callee",
	0x006C0720: "renderer bucket direct callee",
	0x006C07D0: "renderer bucket direct callee",
	0x004E0540: "renderer bucket direct callee",
	0x004DEB30: "renderer bucket direct callee",
	0x00416870: "renderer bucket direct callee",
	0x00460140: "renderer bucket direct callee",
	0x006815C0: "renderer bucket direct callee",
	0x00458200: "renderer bucket direct callee",
	0x0095EE80: "renderer bucket direct callee",
	0x008A8150: "renderer bucket direct callee",
	0x010EE4BC: "NiDX9Renderer vtable",
	0x010ED37C: "NiDX9SourceTextureData vtable",
	0x01016788: "QueuedTexture vtable",
	0x011F91BC: "shader package max global",
	0x011F91C0: "shader package global",
	0x011F91E0: "current geometry global",
	0x0126F74C: "current NiD3DPass global",
	0x0126F92C: "sampler type map global",
	0x011AF70C: "ModelLoader loading-complete flag",
	0x01202D98: "IOManager singleton",
	0x011FDB08: "renderer/global candidate",
	0x011FDE5C: "renderer/global candidate",
	0x011F9548: "renderer/global candidate"
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

def disasm_range(start_int, end_int, label, limit):
	write("")
	write("=" * 70)
	write("DISASSEMBLY RANGE: %s 0x%08x-0x%08x" % (label, start_int, end_int))
	write("=" * 70)
	inst = listing.getInstructionAt(toAddr(start_int))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(start_int))
	count = 0
	while inst is not None and inst.getAddress().getOffset() <= end_int and count < limit:
		addr_int = inst.getAddress().getOffset()
		extra = ""
		known = KNOWN.get(addr_int)
		if known is not None:
			extra = " ; %s" % known
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				extra = "%s ; CALL 0x%08x %s" % (extra, tgt, label_for(tgt))
		write("  0x%08x: %-44s%s" % (addr_int, inst.toString(), extra))
		inst = inst.getNext()
		count += 1
	if count >= limit:
		write("  ... range truncated at %d instructions" % limit)

def collect_direct_calls_in_range(start_int, end_int):
	calls = []
	inst = listing.getInstructionAt(toAddr(start_int))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(start_int))
	while inst is not None and inst.getAddress().getOffset() <= end_int:
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				calls.append((inst.getAddress().getOffset(), tgt))
		inst = inst.getNext()
	return calls

def print_calls_in_range(start_int, end_int, label):
	write("")
	write("=" * 70)
	write("DIRECT CALLS IN RANGE: %s 0x%08x-0x%08x" % (label, start_int, end_int))
	write("=" * 70)
	calls = collect_direct_calls_in_range(start_int, end_int)
	count = 0
	for item in calls:
		write("  0x%08x -> 0x%08x %s" % (item[0], item[1], label_for(item[1])))
		count += 1
	write("  Total: %d direct calls" % count)

def decompile_unique_targets_in_range(start_int, end_int, max_len):
	write("")
	write("=" * 70)
	write("UNIQUE DIRECT CALL TARGETS IN RENDERER BUCKET")
	write("=" * 70)
	calls = collect_direct_calls_in_range(start_int, end_int)
	targets = []
	for item in calls:
		target = item[1]
		if target not in targets:
			targets.append(target)
	for target in targets:
		decompile_at(target, "Renderer bucket callee: %s" % label_for(target), max_len)
		find_and_print_calls_from(target, label_for(target))

def analyze_refs():
	targets = [
		(0x0086D500, "InitializeRenderer"),
		(0x00442650, "NewQueuedModelLoader"),
		(0x00878610, "NewSceneGraph"),
		(0x00BE0FE0, "CreateVertexShader"),
		(0x00BE1750, "CreatePixelShader"),
		(0x00B4F710, "SetShaderPackage"),
		(0x00A61A60, "Texture cache find"),
		(0x00A5FCA0, "NiSourceTexture destructor"),
		(0x010EE4BC, "NiDX9Renderer vtable"),
		(0x010ED37C, "NiDX9SourceTextureData vtable"),
		(0x01016788, "QueuedTexture vtable"),
		(0x011F91BC, "shader package max global"),
		(0x011F91C0, "shader package global"),
		(0x011F91E0, "current geometry global"),
		(0x0126F74C, "current NiD3DPass global"),
		(0x0126F92C, "sampler type map global"),
		(0x011AF70C, "ModelLoader loading-complete flag"),
		(0x01202D98, "IOManager singleton"),
		(0x011FDB08, "renderer/global candidate"),
		(0x011FDE5C, "renderer/global candidate"),
		(0x011F9548, "renderer/global candidate")
	]
	for item in targets:
		find_refs_to(item[0], item[1])

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

def analyze_vtables():
	read_vtable(0x010EE4BC, "NiDX9Renderer", 48)
	read_vtable(0x010ED37C, "NiDX9SourceTextureData", 32)
	read_vtable(0x01016788, "QueuedTexture", 24)

def analyze_markers():
	disasm_window(0x0086B01A, 12, 28, "renderer marker start")
	disasm_window(0x0086B1E1, 18, 18, "renderer marker end / actor locations marker")
	disasm_window(0x0086B210, 10, 10, "loading initial area marker")
	disasm_window(0x0086B2D1, 18, 18, "begin idle loop marker")

def main():
	write("=" * 70)
	write("STARTUP RENDERER BUCKET AUDIT")
	write("=" * 70)
	write("Runtime log showed the first large startup bucket between:")
	write("  Initializing Renderer -> Initializing Actor Locations")
	write("Static range audited here:")
	write("  work range 0x0086B028-0x0086B1E0 inside startup driver 0x0086A850")
	write("")
	write("NVR source anchors used:")
	write("  InitializeRenderer=0x0086D500, NewQueuedModelLoader=0x00442650,")
	write("  shader creation hooks=0x00BE0FE0/0x00BE1750, SetShaderPackage=0x00B4F710.")
	analyze_markers()
	decompile_at(0x0086A850, "WinMain / startup driver", 18000)
	disasm_range(0x0086B028, 0x0086B1E0, "renderer startup bucket", 260)
	print_calls_in_range(0x0086B028, 0x0086B1E0, "renderer startup bucket")
	decompile_unique_targets_in_range(0x0086B028, 0x0086B1E0, 6000)
	analyze_vtables()
	analyze_refs()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/startup_renderer_bucket_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
