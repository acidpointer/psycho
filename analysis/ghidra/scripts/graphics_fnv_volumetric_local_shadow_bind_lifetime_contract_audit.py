# @category Analysis
# @description Close FNV per-light shadow texture binding, projection pairing, encoding, and lifetime ownership

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

FUNCTIONS = [
	(0x00871A30, "RenderShadowMaps candidate reference array getter"),
	(0x00472380, "RenderShadowMaps candidate reference count getter"),
	(0x00B70390, "PPLighting general light-list sorter"),
	(0x00B70590, "first active general light iterator"),
	(0x00B70600, "first active non-shadow light iterator"),
	(0x00B70680, "next active general light iterator"),
	(0x00B70700, "next active non-shadow light iterator"),
	(0x00B70820, "native selected-light value staging"),
	(0x00B67BE0, "PPLighting list population owner A"),
	(0x00BB4740, "PPLighting list population owner B"),
	(0x00C058F0, "PPLighting list population owner C"),
	(0x00B6D3F0, "rendered-texture type 0x2B pool acquisition"),
	(0x00B5AEE0, "per-light +0x10C rendered-texture assignment"),
	(0x00B6D4C0, "rendered-texture pool return"),
	(0x00B9DDA0, "ShadowSceneLight native light-object setter"),
	(0x00B9DBE0, "ShadowSceneLight contribution score"),
	(0x00B9DFC0, "selected light shadow-camera and projection producer"),
	(0x00B9F780, "per-light shadow render and filter consumer"),
	(0x00BF0720, "PPLighting SimpleShadow package construction"),
	(0x00BA53C0, "SimpleShadow package block acquisition helper"),
	(0x00B7DAB0, "PPLighting draw setup and shader dispatch"),
	(0x00B7B930, "ShadowProj per-draw matrix writer"),
	(0x00B7E430, "ShadowProj shader-interface registration"),
	(0x00B7C120, "PPLighting current rendered-texture binding path"),
	(0x00E7EA00, "renderer resource resolver and texture apply path"),
	(0x00E7DC90, "post-texture sampler-state apply helper"),
	(0x00E88A20, "NiDX9RenderState SetTexture"),
	(0x00E910A0, "NiDX9RenderState sampler-state setter"),
]

REFERENCE_TARGETS = [
	(0x011F9174, "current selected per-light shadow object"),
	(0x011FD968, "ShadowProj per-draw matrix backing"),
	(0x011FE8BC, "SimpleShadow package object A"),
	(0x011FE8C0, "SimpleShadow package object B"),
	(0x011FE8C4, "SimpleShadow package object C"),
	(0x011FDFC0, "SimpleShadow vertex group C index 89"),
	(0x011FDFC4, "SimpleShadow vertex group C index 90"),
	(0x011FDFC8, "SimpleShadow vertex group C index 91"),
	(0x011FDD68, "SimpleShadow pixel group B index 152"),
	(0x011FDD6C, "SimpleShadow pixel group B index 153"),
	(0x011FDD70, "SimpleShadow pixel group B index 154"),
	(0x011FDD74, "SimpleShadow pixel group B index 155"),
	(0x011FDD78, "SimpleShadow pixel group B index 156"),
	(0x011FDD7C, "SimpleShadow pixel group B index 157"),
	(0x00E88A20, "NiDX9RenderState SetTexture implementation"),
	(0x00E910A0, "NiDX9RenderState sampler-state implementation"),
]

SHADER_STRINGS = [
	(0x010AE968, "lighting\\2x\\v\\SimpleShadow.v.hlsl"),
	(0x010AEE30, "lighting\\2x\\p\\SimpleShadow.p.hlsl"),
	(0x010AEBA0, "PROJ_SHADOW compile define"),
	(0x010AE95C, "SHADOWMAP descriptor entry point"),
	(0x010AEE24, "DEPTHBIAS descriptor token"),
	(0x010AEE54, "SAMPLE descriptor token"),
	(0x010AEE14, "PASSES descriptor token"),
	(0x010AEFE0, "SHADOWMODE descriptor token"),
]

CALL_CONTEXT_TARGETS = [
	(0x00871A30, "RenderShadowMaps candidate reference array getter"),
	(0x00472380, "RenderShadowMaps candidate reference count getter"),
	(0x00B70390, "PPLighting general light-list sorter"),
	(0x00B70590, "first active general light iterator"),
	(0x00B70600, "first active non-shadow light iterator"),
	(0x00B70680, "next active general light iterator"),
	(0x00B70700, "next active non-shadow light iterator"),
	(0x00B70820, "native selected-light value staging"),
	(0x00B5AEE0, "per-light +0x10C rendered-texture assignment"),
	(0x00B9DFC0, "selected light shadow-camera and projection producer"),
	(0x00B9F780, "per-light shadow render and filter consumer"),
	(0x00B7B930, "ShadowProj per-draw matrix writer"),
	(0x00E7EA00, "renderer resource resolver and texture apply path"),
	(0x00E7DC90, "post-texture sampler-state apply helper"),
]

PAIRING_SCAN_RANGES = [
	(0x00B58000, 0x00B5FFFF, "shadow scene manager resource ownership"),
	(0x00B67000, 0x00B68FFF, "PPLighting general light-list population A"),
	(0x00B70000, 0x00B7FFFF, "PPLighting texture, constant, and package dispatch"),
	(0x00B9CF00, 0x00BA0FFF, "per-light shadow camera, render, and filter"),
	(0x00BB4700, 0x00BB60FF, "PPLighting general light-list population B"),
	(0x00C05800, 0x00C06FFF, "PPLighting general light-list population C"),
	(0x00E7D000, 0x00E92000, "NiDX9 renderer texture and sampler application"),
]

PAIRING_MARKERS = [
	" + 0x60]",
	" + 0x64]",
	" + 0x10c]",
	" + 0x20c]",
	" + 0x128]",
	" + 0x140]",
	" + 0x44]",
	" + 0xcc]",
	" + 0xdc]",
	"0x011f9174",
	"0x011fd968",
	"0x011fe8bc",
	"0x011fe8c0",
	"0x011fe8c4",
]

INDIRECT_CALL_RANGES = [
	(0x00B70000, 0x00B7FFFF, "PPLighting indirect render-state calls"),
	(0x00E7D000, 0x00E92000, "NiDX9 indirect texture and sampler calls"),
]

INDIRECT_SLOT_MARKERS = [
	" + 0xcc]",
	" + 0xdc]",
	" + 0x104]",
	" + 0x10c]",
]

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

def checkpoint_output(path):
	fout = open(path, "w")
	fout.write("\n".join(output))
	fout.close()

def read_ascii(addr_int, max_length):
	chars = []
	idx = 0
	while idx < max_length:
		try:
			value = memory.getByte(toAddr(addr_int + idx)) & 0xff
		except:
			return None
		if value == 0:
			break
		if value < 0x20 or value > 0x7e:
			return None
		chars.append(chr(value))
		idx += 1
	if len(chars) == 0:
		return None
	return "".join(chars)

def print_shader_strings(items):
	write("")
	write("=" * 70)
	write("SIMPLESHADOW DESCRIPTOR IDENTITIES")
	write("=" * 70)
	idx = 0
	while idx < len(items):
		item = items[idx]
		value = read_ascii(item[0], 160)
		write("  0x%08x %-40s %r" % (item[0], item[1], value))
		idx += 1

def disasm_window(addr_int, before_count, after_count, label):
	write("")
	write("=" * 70)
	write("DISASM: %s around 0x%08x" % (label, addr_int))
	write("=" * 70)
	inst = listing.getInstructionContaining(toAddr(addr_int))
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
		marker = "=>" if current.getAddress() == inst.getAddress() else "  "
		write("%s 0x%08x: %s" % (marker, current.getAddress().getOffset(), current.toString()))
		refs = current.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall() or ref.getReferenceType().isData() or ref.getReferenceType().isJump():
				write("      ref %-18s -> 0x%08x" % (ref.getReferenceType(), ref.getToAddress().getOffset()))
		current = current.getNext()
		remaining -= 1

def audit_functions(items):
	idx = 0
	while idx < len(items):
		item = items[idx]
		decompile_at(item[0], item[1], 20000)
		find_refs_to(item[0], item[1])
		find_and_print_calls_from(item[0], item[1])
		idx += 1

def audit_references(items):
	idx = 0
	while idx < len(items):
		item = items[idx]
		find_refs_to(item[0], item[1])
		idx += 1

def print_call_contexts(items):
	idx = 0
	while idx < len(items):
		item = items[idx]
		refs = ref_mgr.getReferencesTo(toAddr(item[0]))
		count = 0
		while refs.hasNext():
			ref = refs.next()
			if ref.getReferenceType().isCall():
				disasm_window(ref.getFromAddress().getOffset(), 14, 24, item[1])
				count += 1
				if count >= 24:
					write("  Callsite windows truncated after %d" % count)
					break
		if count == 0:
			write("  [no direct call references to %s]" % item[1])
		idx += 1

def scan_pairing_markers():
	write("")
	write("=" * 70)
	write("TEXTURE, PROJECTION, AND PACKAGE PAIRING SCAN")
	write("=" * 70)
	range_idx = 0
	while range_idx < len(PAIRING_SCAN_RANGES):
		item = PAIRING_SCAN_RANGES[range_idx]
		write("")
		write("Range 0x%08x-0x%08x (%s)" % (item[0], item[1], item[2]))
		inst = listing.getInstructionAt(toAddr(item[0]))
		if inst is None:
			inst = listing.getInstructionAfter(toAddr(item[0]))
		matches = 0
		while inst is not None and inst.getAddress().getOffset() <= item[1]:
			text = inst.toString().lower()
			marker_idx = 0
			matched = False
			while marker_idx < len(PAIRING_MARKERS):
				if PAIRING_MARKERS[marker_idx] in text:
					matched = True
					break
				marker_idx += 1
			if matched:
				func = fm.getFunctionContaining(inst.getAddress())
				name = func.getName() if func else "???"
				write("  0x%08x in %-24s %s" % (inst.getAddress().getOffset(), name, inst.toString()))
				matches += 1
				if matches >= 400:
					write("  ... (range truncated after %d matches)" % matches)
					break
			inst = inst.getNext()
		write("  Total shown: %d" % matches)
		range_idx += 1

def scan_indirect_render_calls():
	write("")
	write("=" * 70)
	write("INDIRECT TEXTURE OR SAMPLER VTABLE CALL SCAN")
	write("=" * 70)
	range_idx = 0
	while range_idx < len(INDIRECT_CALL_RANGES):
		item = INDIRECT_CALL_RANGES[range_idx]
		write("")
		write("Range 0x%08x-0x%08x (%s)" % (item[0], item[1], item[2]))
		inst = listing.getInstructionAt(toAddr(item[0]))
		if inst is None:
			inst = listing.getInstructionAfter(toAddr(item[0]))
		matches = 0
		while inst is not None and inst.getAddress().getOffset() <= item[1]:
			text = inst.toString().lower()
			if inst.getMnemonicString().upper() == "CALL":
				marker_idx = 0
				matched = False
				while marker_idx < len(INDIRECT_SLOT_MARKERS):
					if INDIRECT_SLOT_MARKERS[marker_idx] in text:
						matched = True
						break
					marker_idx += 1
				if matched:
					func = fm.getFunctionContaining(inst.getAddress())
					name = func.getName() if func else "???"
					write("  0x%08x in %-24s %s" % (inst.getAddress().getOffset(), name, inst.toString()))
					matches += 1
			inst = inst.getNext()
		write("  Total matches: %d" % matches)
		range_idx += 1

def print_contract_questions():
	write("FNV VOLUMETRIC LOCAL-SHADOW BIND AND LIFETIME CONTRACT AUDIT")
	write("")
	write("Proven starting point:")
	write("1. A selected 0x250-byte local-shadow object retains a type-0x2B rendered texture at +0x10C.")
	write("2. Type 0x2B is normally R32F but changes to A8R8G8B8 in the ATI compatibility path.")
	write("3. SimpleShadow packages and a separate draw-scoped ShadowProj matrix are registered by PPLighting.")
	write("4. Earlier audits did not prove that the selected object's +0x10C texture reaches that package.")
	write("5. The first value-copy audit proved that RenderShadowMaps sees a capped shadow-selected subset, not all active lights.")
	write("")
	write("Closure questions:")
	write("1. Which object owns the PPLighting +0x60 list, and when is its shadow plus non-shadow membership stable?")
	write("2. Does that list include player, muzzle, projectile, scripted, point, and spot lights once per world frame?")
	write("3. Can its ShadowSceneLight values be copied once without retaining its +0xF8 native light pointer?")
	write("4. Which live draw path dispatches SimpleShadow vertex 89-91 and pixel 152-157?")
	write("5. How does the same selected light's +0x10C texture reach a texture stage, and which stage is it?")
	write("6. What sampler, comparison, bias, channel, and ATI encoding rules decode that texture?")
	write("7. Which projection matrix is paired with that exact texture, and where is the pairing established?")
	write("8. Can a hook retain both resources with explicit references until OMV finishes its atmosphere draw?")
	write("9. At what render phase are production complete, filtering complete, and pool invalidation impossible?")
	write("10. Does NVR replace any list, producer, package, format, or lifetime owner in this chain?")
	write("")
	write("Required result:")
	write("Either a complete copied texture-plus-matrix ABI with explicit lifetime rules, or proof that OMV must own local shadow resources.")

print_contract_questions()
print_shader_strings(SHADER_STRINGS)
audit_functions(FUNCTIONS)
print_call_contexts(CALL_CONTEXT_TARGETS)
audit_references(REFERENCE_TARGETS)
scan_pairing_markers()
scan_indirect_render_calls()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_volumetric_local_shadow_bind_lifetime_contract_audit.txt"
checkpoint_output(outpath)
write("")
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
