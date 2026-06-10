# @category Analysis
# @description Audit FNV native render-state fog color contract for PBR environment constants

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x00E881A0: "NiDX9RenderState constructor",
	0x010EF60C: "NiDX9RenderState vtable",
	0x011F4998: "Default/current fog color R candidate",
	0x011F499C: "Default/current fog color G candidate",
	0x011F49A0: "Default/current fog color B candidate",
}

VTABLE_BASE = 0x010EF60C

VTABLE_SLOTS = [
	(0x05, "SetFog"),
	(0x16, "InitializeRenderStates"),
	(0x17, "BackUpAllStates"),
	(0x18, "RestoreRenderState"),
	(0x19, "RestoreAllRenderStates"),
	(0x1A, "SetRenderState"),
	(0x1B, "GetRenderState"),
	(0x30, "SetTextureStageState"),
	(0x31, "GetTextureStageState"),
	(0x33, "SetSamplerState"),
	(0x34, "GetSamplerState"),
	(0x35, "RestoreSamplerState"),
	(0x37, "SetTexture"),
	(0x38, "GetTexture"),
]

REF_TARGETS = [
	0x010EF60C,
	0x011F4998,
	0x011F499C,
	0x011F49A0,
]

D3D_RENDER_STATE_METHODS = [
	(0xE4, "IDirect3DDevice9::SetRenderState"),
	(0xE8, "IDirect3DDevice9::GetRenderState"),
	(0xEC, "IDirect3DDevice9::CreateStateBlock"),
	(0xF0, "IDirect3DDevice9::BeginStateBlock"),
	(0xF4, "IDirect3DDevice9::EndStateBlock"),
]

FOG_RENDER_STATES = [
	(0x1C, "D3DRS_FOGENABLE"),
	(0x22, "D3DRS_FOGCOLOR"),
	(0x23, "D3DRS_FOGTABLEMODE"),
	(0x24, "D3DRS_FOGSTART"),
	(0x25, "D3DRS_FOGEND"),
	(0x26, "D3DRS_FOGDENSITY"),
	(0x30, "D3DRS_RANGEFOGENABLE"),
]

MATCH_PATTERNS = [
	"010ef60c",
	"011f4998",
	"011f499c",
	"011f49a0",
	"+ 0x8c",
	"+ 0x90",
	"+ 0x94",
	"+ 0x98",
	"+ 0x120",
	"+ 0x10f8",
	"+ 0xe4",
	"+ 0xe8",
	"+ 0xec",
	"+ 0xf0",
	"+ 0xf4",
	"0x1c",
	"0x22",
	"0x23",
	"0x24",
	"0x25",
	"0x26",
	"0x30",
	"fog",
	"render",
	"state",
]

def write(msg):
	output.append(msg)
	print(msg)

def read_u32(addr_int):
	try:
		return getInt(toAddr(addr_int)) & 0xffffffff
	except:
		return None

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

def decompile_text(addr_int):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	if func is None:
		return None
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		return result.getDecompiledFunction().getC()
	return None

def decompile_at(addr_int, label, max_len=24000):
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
	code = decompile_text(addr_int)
	if code is None:
		write("  [decompilation failed]")
		return
	write(code[:max_len])

def find_refs_to(addr_int, label):
	write("")
	write("-" * 70)
	write("References TO 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		from_addr = ref.getFromAddress()
		from_func = fm.getFunctionContaining(from_addr)
		fname = from_func.getName() if from_func else "???"
		inst = listing.getInstructionContaining(from_addr)
		inst_text = inst.toString() if inst is not None else ""
		write("  %s @ 0x%08x (in %s) %s" % (ref.getReferenceType(), from_addr.getOffset(), fname, inst_text))
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

def line_matches(line):
	lower = line.lower()
	idx = 0
	while idx < len(MATCH_PATTERNS):
		if lower.find(MATCH_PATTERNS[idx]) >= 0:
			return True
		idx += 1
	return False

def print_matching_decompile_lines(addr_int, label):
	write("")
	write("=" * 70)
	write("RENDER-STATE FOG MATCHES: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	code = decompile_text(addr_int)
	if code is None:
		write("  [decompilation failed]")
		return
	lines = code.split("\n")
	idx = 0
	count = 0
	while idx < len(lines):
		line = lines[idx]
		if line_matches(line):
			write("  L%04d: %s" % (idx + 1, line))
			count += 1
		idx += 1
	write("  Total matched lines: %d" % count)

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
		extra = ""
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				extra = "%s ; CALL 0x%08x %s" % (extra, tgt, label_for(tgt))
		write("  0x%08x: %-52s%s%s" % (addr_int, inst.toString(), marker, extra))
		inst = inst.getNext()
		idx += 1

def text_has_vtable_offset(text, offset):
	token = "+ 0x%x]" % offset
	if text.find(token) >= 0:
		return True
	token = "+0x%x]" % offset
	if text.find(token) >= 0:
		return True
	token = "+ 0x%X]" % offset
	if text.find(token) >= 0:
		return True
	token = "+0x%X]" % offset
	if text.find(token) >= 0:
		return True
	return False

def collect_ref_function(addr_int, functions):
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	while refs.hasNext():
		ref = refs.next()
		func = fm.getFunctionContaining(ref.getFromAddress())
		if func is not None:
			functions[func.getEntryPoint().getOffset()] = True

def print_vtable_slots(functions):
	write("")
	write("=" * 70)
	write("NiDX9RenderState vtable slots")
	write("=" * 70)
	idx = 0
	while idx < len(VTABLE_SLOTS):
		slot = VTABLE_SLOTS[idx][0]
		name = VTABLE_SLOTS[idx][1]
		slot_addr = VTABLE_BASE + slot * 4
		ptr = read_u32(slot_addr)
		if ptr is None:
			write("  slot 0x%02x %-28s @ 0x%08x -> [read failed]" % (slot, name, slot_addr))
		else:
			write("  slot 0x%02x %-28s @ 0x%08x -> 0x%08x %s" % (slot, name, slot_addr, ptr, label_for(ptr)))
			if ptr != 0:
				functions[ptr] = True
		idx += 1

def audit_slot_functions(functions):
	keys = functions.keys()
	keys.sort()
	idx = 0
	while idx < len(keys):
		addr = keys[idx]
		decompile_at(addr, label_for(addr))
		print_matching_decompile_lines(addr, label_for(addr))
		find_and_print_calls_from(addr, label_for(addr))
		disasm_window(addr, 8, 34, label_for(addr))
		idx += 1

def audit_refs(functions):
	idx = 0
	while idx < len(REF_TARGETS):
		addr_int = REF_TARGETS[idx]
		find_refs_to(addr_int, label_for(addr_int))
		collect_ref_function(addr_int, functions)
		idx += 1

def scan_device_renderstate_slot_loads(functions):
	write("")
	write("=" * 70)
	write("Potential D3D render-state vtable slot loads")
	write("=" * 70)
	hits = {}
	idx = 0
	while idx < len(D3D_RENDER_STATE_METHODS):
		hits[D3D_RENDER_STATE_METHODS[idx][0]] = 0
		idx += 1
	inst_iter = listing.getInstructions(True)
	while inst_iter.hasNext():
		inst = inst_iter.next()
		text = inst.toString()
		idx = 0
		while idx < len(D3D_RENDER_STATE_METHODS):
			offset = D3D_RENDER_STATE_METHODS[idx][0]
			name = D3D_RENDER_STATE_METHODS[idx][1]
			if hits[offset] < 100 and text_has_vtable_offset(text, offset):
				from_func = fm.getFunctionContaining(inst.getAddress())
				fname = from_func.getName() if from_func else "???"
				write("  %s slot load @ 0x%08x (in %s): %s" % (name, inst.getAddress().getOffset(), fname, text))
				hits[offset] = hits[offset] + 1
				if from_func is not None:
					functions[from_func.getEntryPoint().getOffset()] = True
			idx += 1
	write("")
	idx = 0
	while idx < len(D3D_RENDER_STATE_METHODS):
		offset = D3D_RENDER_STATE_METHODS[idx][0]
		name = D3D_RENDER_STATE_METHODS[idx][1]
		write("  Total shown for %s: %d" % (name, hits[offset]))
		idx += 1

def print_fog_state_constants():
	write("")
	write("=" * 70)
	write("D3D fog render states to check inside SetRenderState paths")
	write("=" * 70)
	idx = 0
	while idx < len(FOG_RENDER_STATES):
		state = FOG_RENDER_STATES[idx][0]
		name = FOG_RENDER_STATES[idx][1]
		cache_offset = 0x120 + state * 8
		write("  0x%02x %-24s render-state cache slot candidate +0x%03x" % (state, name, cache_offset))
		idx += 1
	write("")
	write("  If SetRenderState only writes +0x120 cache and D3D, Psycho can still read D3DRS_FOGCOLOR through the cache/state-block path.")
	write("  If +0x8C/+0x90/+0x94 are updated from D3DRS_FOGCOLOR, those floats are the cleaner normalized fog-color source.")

def print_header():
	write("FNV NATIVE RENDER-STATE FOG COLOR CONTRACT AUDIT")
	write("")
	write("Questions:")
	write("1. Which vtable entry is NiDX9RenderState::SetRenderState, and how does it update the render-state cache?")
	write("2. Does D3DRS_FOGCOLOR update NiDX9RenderState +0x8C/+0x90/+0x94, or only the packed D3D render-state cache?")
	write("3. Is final renderer fog color a safer source than raw TESWeather color fields for Psycho material lighting?")
	write("")
	write("Compatibility target:")
	write("Prefer a final renderer-owned fog color if this audit proves it. Fall back to unavailable constants rather than walking raw weather fields when the render-state contract is unproven.")

def main():
	functions = {}
	print_header()
	print_fog_state_constants()
	audit_refs(functions)
	print_vtable_slots(functions)
	decompile_at(0x00E881A0, "NiDX9RenderState constructor")
	print_matching_decompile_lines(0x00E881A0, "NiDX9RenderState constructor")
	scan_device_renderstate_slot_loads(functions)
	audit_slot_functions(functions)
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_native_render_state_fog_color_contract_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("")
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
