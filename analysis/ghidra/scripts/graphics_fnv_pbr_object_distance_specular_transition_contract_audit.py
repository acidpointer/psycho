# @category Analysis
# @description Prove the FNV object specular LOD weight writer, shader handoff, and PPLighting draw contract

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x00B690D0: "PPLighting material serialization including specular lod",
	0x00B70820: "PPLighting per-light material and fade staging",
	0x00B71BF0: "PPLighting vertex shader table constructor",
	0x00B74210: "PPLighting pixel shader table constructor",
	0x00B78A90: "PPLighting LightData staging for current draw",
	0x00B7C850: "PPLighting alternate LightData upload path A",
	0x00B7CB00: "PPLighting alternate LightData upload path B",
	0x00B7DAB0: "PPLighting pass-entry resource and constant dispatcher",
	0x00BDB4A0: "PPLighting selector setup variant A",
	0x00BDF790: "PPLighting selector setup variant B",
	0x00BD1C50: "Current pass shader writer",
	0x00BD4BA0: "Current pass shader-interface apply",
	0x00BE1F90: "BSShader::SetShaders",
	0x011FA1F0: "Staged source LightData array",
	0x011FA1FC: "Staged source LightData[0].w",
	0x011FD9A8: "Renderer LightData array c25",
	0x011FD9B4: "Renderer LightData[0].w c25.w",
	0x011FDD88: "PPLighting vertex shader group A",
	0x011FDE04: "PPLighting vertex shader group B",
	0x011FDE5C: "PPLighting vertex shader group C object table",
	0x011FDA48: "PPLighting pixel shader group A",
	0x011FDB08: "PPLighting pixel shader group B object table",
	0x011F91E0: "Current PPLighting draw",
	0x011F91E4: "Current PPLighting pass or selector id",
	0x0126F74C: "Current NiD3DPass",
}

FUNCTION_TARGETS = [
	0x00B690D0,
	0x00B70820,
	0x00B78A90,
	0x00B7C850,
	0x00B7CB00,
	0x00B7DAB0,
	0x00BDB4A0,
	0x00BDF790,
	0x00BD1C50,
	0x00BD4BA0,
	0x00BE1F90,
]

REF_TARGETS = [
	0x00B70820,
	0x00B78A90,
	0x00B7C850,
	0x00B7CB00,
	0x011FA1F0,
	0x011FA1FC,
	0x011FD9A8,
	0x011FD9B4,
	0x011FDD88,
	0x011FDE04,
	0x011FDE5C,
	0x011FDA48,
	0x011FDB08,
	0x011F91E0,
	0x011F91E4,
	0x0126F74C,
]

DISASM_TARGETS = [
	(0x00B70D2B, 24, 72, "specular-light staged source write"),
	(0x00B78B7B, 24, 96, "LightData direct-copy branch"),
	(0x00B78D3E, 24, 64, "LightData[0].w final write"),
	(0x00B7DBAC, 30, 72, "current-draw LightData staging call"),
	(0x00B7DF8F, 30, 72, "alternate LightData upload path A call"),
	(0x00B7E0AE, 30, 72, "alternate LightData upload path B call"),
]

MATCH_PATTERNS = [
	"011fa1f0",
	"011fa1fc",
	"011fd9a8",
	"011fd9b4",
	"011fdd88",
	"011fde04",
	"011fde5c",
	"011fda48",
	"011fdb08",
	"011f91e0",
	"011f91e4",
	"0126f74c",
	"0x10c",
	"0xe0",
	"0xd4",
	"LightData",
	"specular",
	"lod",
	"shader",
	"pixel",
	"vertex",
]

STRING_TARGETS = [
	"specular lod",
	"envmap lod",
	"LightData",
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
	else:
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
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		fname = from_func.getName() if from_func else "???"
		inst = listing.getInstructionContaining(ref.getFromAddress())
		inst_text = inst.toString() if inst is not None else ""
		write("  %s @ 0x%08x (in %s) %s" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname, inst_text))
		count += 1
		if count > 120:
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

def disasm_window(addr_int, before, count, label):
	write("")
	write("-" * 70)
	write("Disassembly %s around 0x%08x" % (label, addr_int))
	write("-" * 70)
	inst = listing.getInstructionAt(toAddr(addr_int - before))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(addr_int - before))
	seen = 0
	while inst is not None and seen < count:
		off = inst.getAddress().getOffset()
		marker = " << TARGET" if off == addr_int else ""
		write("  0x%08x: %-58s%s" % (off, inst.toString(), marker))
		seen += 1
		inst = inst.getNext()

def print_matching_decompile_lines(addr_int, label):
	write("")
	write("=" * 70)
	write("MATCHED DECOMPILE LINES: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	code = decompile_text(addr_int)
	if code is None:
		write("  [decompilation failed]")
		return
	lines = code.splitlines()
	idx = 0
	count = 0
	while idx < len(lines):
		line = lines[idx]
		lower = line.lower()
		pattern_idx = 0
		matched = False
		while pattern_idx < len(MATCH_PATTERNS):
			if lower.find(MATCH_PATTERNS[pattern_idx].lower()) >= 0:
				matched = True
				break
			pattern_idx += 1
		if matched:
			write("  L%04d: %s" % (idx + 1, line))
			count += 1
		idx += 1
	write("  Total matched lines: %d" % count)

def find_string_addresses(target):
	addresses = []
	data_iter = listing.getDefinedData(True)
	while data_iter.hasNext():
		data = data_iter.next()
		value = data.getValue()
		if value is not None:
			text_value = str(value)
			if text_value.lower().find(target.lower()) >= 0:
				addresses.append(data.getAddress().getOffset())
	return addresses

def audit_string(target):
	write("")
	write("=" * 70)
	write("STRING AND REFERENCE AUDIT: %s" % target)
	write("=" * 70)
	addresses = find_string_addresses(target)
	idx = 0
	while idx < len(addresses):
		addr_int = addresses[idx]
		write("  String match @ 0x%08x" % addr_int)
		find_refs_to(addr_int, "string %s" % target)
		refs = ref_mgr.getReferencesTo(toAddr(addr_int))
		seen = {}
		while refs.hasNext():
			ref = refs.next()
			func = fm.getFunctionContaining(ref.getFromAddress())
			if func is not None:
				entry = func.getEntryPoint().getOffset()
				seen[entry] = func.getName()
		entries = seen.keys()
		entries.sort()
		entry_idx = 0
		while entry_idx < len(entries):
			entry = entries[entry_idx]
			decompile_at(entry, "%s reference in %s" % (target, seen[entry]), 18000)
			print_matching_decompile_lines(entry, seen[entry])
			entry_idx += 1
		idx += 1
	write("  Total string matches: %d" % len(addresses))

def audit_functions():
	idx = 0
	while idx < len(FUNCTION_TARGETS):
		addr_int = FUNCTION_TARGETS[idx]
		decompile_at(addr_int, label_for(addr_int))
		find_and_print_calls_from(addr_int, label_for(addr_int))
		print_matching_decompile_lines(addr_int, label_for(addr_int))
		idx += 1

def audit_refs():
	idx = 0
	while idx < len(REF_TARGETS):
		addr_int = REF_TARGETS[idx]
		find_refs_to(addr_int, label_for(addr_int))
		idx += 1

def audit_disassembly():
	idx = 0
	while idx < len(DISASM_TARGETS):
		item = DISASM_TARGETS[idx]
		disasm_window(item[0], item[1], item[2], item[3])
		idx += 1

def audit_strings():
	idx = 0
	while idx < len(STRING_TARGETS):
		audit_string(STRING_TARGETS[idx])
		idx += 1

def print_contract_questions():
	write("FNV PBR OBJECT DISTANCE SPECULAR TRANSITION CONTRACT AUDIT")
	write("")
	write("Questions to prove before changing the object PBR distance transition:")
	write("1. Which material/property value becomes LightData[0].w for combined object specular draws?")
	write("2. Is its near/far orientation and 0..1 range already computed by the engine?")
	write("3. Which functions stage and upload c25.w for low and ADTS10 object paths?")
	write("4. Which selector or pass transition swaps specular object rows for non-specular or LOD rows?")
	write("5. Do any visible PPLighting object rows bypass the current group-C/group-B replacement contract?")
	write("6. Is the safe fix entirely in the replacement shader curve, or is an engine-side pair/constant contract missing?")
	write("")
	write("Required outcome: preserve vanilla endpoints and row ownership while eliminating the compressed distance pop.")

def main():
	print_contract_questions()
	audit_strings()
	audit_refs()
	audit_disassembly()
	audit_functions()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_object_distance_specular_transition_contract_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("")
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
