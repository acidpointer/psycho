# @category Analysis
# @description Audit FNV native texture/sampler binding contracts for material PBR work

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x00E881A0: "NiDX9RenderState constructor",
	0x00E890C0: "NiDX9RenderState texture stage state cache writer candidate",
	0x00E910A0: "NiDX9RenderState::SetSamplerState",
	0x00E91120: "NiDX9RenderState sampler restore/apply candidate",
	0x011C73B4: "NiDX9Renderer::singleton",
	0x0126F74C: "Current NiD3DPass global",
	0x0126F92C: "NiDX9RenderState sampler TypeMap candidate",
	0x0126F958: "NiDX9RenderState texture stage TypeMap candidate",
}

FUNCTION_TARGETS = [
	0x00E881A0,
	0x00E890C0,
	0x00E910A0,
	0x00E91120,
]

REF_TARGETS = [
	0x011C73B4,
	0x0126F74C,
	0x0126F92C,
	0x0126F958,
]

MATCH_PATTERNS = [
	"011c73b4",
	"0126f74c",
	"0126f92c",
	"0126f958",
	"+ 0x100",
	"+ 0x104",
	"+ 0x108",
	"+ 0x10c",
	"+ 0x110",
	"+ 0x114",
	"settexture",
	"sampler",
	"texture",
	"stage",
	"type",
]

DEVICE_METHODS = [
	(0x100, "IDirect3DDevice9::GetTexture"),
	(0x104, "IDirect3DDevice9::SetTexture"),
	(0x108, "IDirect3DDevice9::GetTextureStageState"),
	(0x10C, "IDirect3DDevice9::SetTextureStageState"),
	(0x110, "IDirect3DDevice9::GetSamplerState"),
	(0x114, "IDirect3DDevice9::SetSamplerState"),
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

def decompile_at(addr_int, label, max_len=22000):
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
		if count > 180:
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
	write("NATIVE TEXTURE BINDING MATCHES: %s @ 0x%08x" % (label, addr_int))
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

def inst_text_mentions_offset(text, offset):
	hex_lower = "0x%x" % offset
	hex_upper = "0x%X" % offset
	if text.find(hex_lower) >= 0:
		return True
	if text.find(hex_upper) >= 0:
		return True
	return False

def scan_device_method_calls():
	write("")
	write("=" * 70)
	write("Potential IDirect3DDevice9 texture/sampler vtable callsites")
	write("=" * 70)
	hits = {}
	idx = 0
	while idx < len(DEVICE_METHODS):
		hits[DEVICE_METHODS[idx][0]] = 0
		idx += 1
	inst_iter = listing.getInstructions(True)
	while inst_iter.hasNext():
		inst = inst_iter.next()
		text = inst.toString()
		if text.find("CALL") < 0:
			continue
		idx = 0
		while idx < len(DEVICE_METHODS):
			offset = DEVICE_METHODS[idx][0]
			name = DEVICE_METHODS[idx][1]
			if hits[offset] < 80 and inst_text_mentions_offset(text, offset):
				from_func = fm.getFunctionContaining(inst.getAddress())
				fname = from_func.getName() if from_func else "???"
				write("  %s @ 0x%08x (in %s): %s" % (name, inst.getAddress().getOffset(), fname, text))
				hits[offset] = hits[offset] + 1
			idx += 1
	write("")
	idx = 0
	while idx < len(DEVICE_METHODS):
		offset = DEVICE_METHODS[idx][0]
		name = DEVICE_METHODS[idx][1]
		write("  Total shown for %s: %d" % (name, hits[offset]))
		idx += 1

def audit_functions():
	idx = 0
	while idx < len(FUNCTION_TARGETS):
		addr_int = FUNCTION_TARGETS[idx]
		decompile_at(addr_int, label_for(addr_int))
		print_matching_decompile_lines(addr_int, label_for(addr_int))
		find_and_print_calls_from(addr_int, label_for(addr_int))
		idx += 1

def audit_refs():
	idx = 0
	while idx < len(REF_TARGETS):
		addr_int = REF_TARGETS[idx]
		find_refs_to(addr_int, label_for(addr_int))
		idx += 1

def print_header():
	write("FNV NATIVE TEXTURE BINDING CONTRACT AUDIT")
	write("")
	write("Questions:")
	write("1. Which engine paths own native SetTexture/SetTextureStageState/SetSamplerState calls?")
	write("2. Which sampler states are tracked by NiDX9RenderState, and which bypass its backup table?")
	write("3. Can Psycho bind extra PBR textures without dirtying persistent engine render state?")
	write("")
	write("Expected compatibility result:")
	write("Bind extra material textures only inside the native material draw hook, capture/restore D3D texture and sampler state, and prefer engine render-state wrappers where their TypeMap proves coverage.")

def main():
	print_header()
	audit_refs()
	audit_functions()
	disasm_window(0x00E910A0, 10, 28, "NiDX9RenderState::SetSamplerState")
	disasm_window(0x00E91120, 10, 28, "NiDX9RenderState sampler restore/apply candidate")
	scan_device_method_calls()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_native_texture_binding_contract_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("")
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
