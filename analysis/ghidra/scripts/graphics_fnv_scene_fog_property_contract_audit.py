# @category Analysis
# @description Audit FNV active scene fog property and camera frustum contracts for Psycho Graphics

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x00450B80: "BSShaderManager::GetShadowSceneNode candidate 00450B80",
	0x004E9BB0: "NiRenderer::SetCameraData candidate 004E9BB0",
	0x00532220: "Weather blend / fog setter candidate 00532220",
	0x00B5E870: "CameraWriter_00B5E870",
	0x00B8AF10: "Fog/weather downstream setter 00B8AF10",
	0x00B8AF60: "Fog/weather downstream setter 00B8AF60",
	0x00B8AFB0: "Fog/weather downstream setter 00B8AFB0",
	0x00B8B000: "Fog/weather downstream setter 00B8B000",
	0x00B8B0D0: "Fog/weather downstream setter 00B8B0D0",
	0x00B8B1C0: "Fog/weather downstream setter 00B8B1C0",
	0x00B8BB70: "Fog/weather downstream setter 00B8BB70",
	0x010B9E38: "BSFogProperty vtable candidate",
	0x011F917C: "BSShaderManager::pCurrentCamera",
	0x011F91C4: "BSShaderManager::ucSceneGraph",
	0x011F91C8: "BSShaderManager::ShadowSceneNode array",
}

FUNCTION_TARGETS = [
	0x00450B80,
	0x004E9BB0,
	0x00532220,
	0x00B5E870,
	0x00B8AF10,
	0x00B8AF60,
	0x00B8AFB0,
	0x00B8B000,
	0x00B8B0D0,
	0x00B8B1C0,
	0x00B8BB70,
]

REF_TARGETS = [
	0x00450B80,
	0x004E9BB0,
	0x00532220,
	0x00B8AF10,
	0x00B8AF60,
	0x00B8AFB0,
	0x00B8B000,
	0x00B8B0D0,
	0x00B8B1C0,
	0x00B8BB70,
	0x010B9E38,
	0x011F917C,
	0x011F91C4,
	0x011F91C8,
]

DISASM_WINDOWS = [
	0x00B5A232,
	0x00B5A241,
	0x00BD66C8,
	0x00BD66D5,
	0x00532220,
]

MATCH_PATTERNS = [
	"+ 0x2c",
	"+ 0x30",
	"+ 0x60",
	"+ 0x134",
	"+ 0xe8",
	"+ 0xec",
	"+ 0xf0",
	"+ 0x100",
	"+ 0x101",
	"011f917c",
	"011f91c4",
	"011f91c8",
	"10b9e38",
	"00b8af10",
	"00b8af60",
	"00b8afb0",
	"00b8b000",
	"00b8b0d0",
	"00b8b1c0",
	"00b8bb70",
	"fog",
	"weather",
]

INSTRUCTION_PATTERNS = [
	"011f91c4",
	"011f91c8",
	"10b9e38",
	"+ 0x134",
	"+0x134",
	"+ 0x2c",
	"+0x2c",
	"+ 0x30",
	"+0x30",
	"+ 0x60",
	"+0x60",
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

def decompile_at(addr_int, label, max_len=28000):
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
	write("CONTRACT MATCHES: %s @ 0x%08x" % (label, addr_int))
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
		if count > 140:
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
		extra = ""
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				extra = "%s ; CALL 0x%08x %s" % (extra, tgt, label_for(tgt))
		write("  0x%08x: %-52s%s%s" % (addr_int, inst.toString(), marker, extra))
		inst = inst.getNext()
		idx += 1

def instruction_matches(inst_text):
	lower = inst_text.lower()
	idx = 0
	while idx < len(INSTRUCTION_PATTERNS):
		if lower.find(INSTRUCTION_PATTERNS[idx]) >= 0:
			return True
		idx += 1
	return False

def scan_instruction_patterns(max_count):
	write("")
	write("=" * 70)
	write("PROGRAM INSTRUCTION SCAN FOR SCENE FOG/FRUSTUM OFFSETS")
	write("=" * 70)
	inst_iter = listing.getInstructions(True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		text = inst.toString()
		if instruction_matches(text):
			func = fm.getFunctionContaining(inst.getAddress())
			fname = func.getName() if func else "???"
			write("  0x%08x in %s: %s" % (inst.getAddress().getOffset(), fname, text))
			count += 1
			if count >= max_count:
				write("  ... instruction scan truncated")
				break
	write("  Total printed: %d" % count)

def collect_ref_functions(addr_int, functions):
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	while refs.hasNext():
		ref = refs.next()
		func = fm.getFunctionContaining(ref.getFromAddress())
		if func is not None:
			functions[func.getEntryPoint().getOffset()] = True

def audit_targets(functions):
	idx = 0
	while idx < len(FUNCTION_TARGETS):
		addr = FUNCTION_TARGETS[idx]
		decompile_at(addr, label_for(addr))
		find_and_print_calls_from(addr, label_for(addr))
		print_matching_decompile_lines(addr, label_for(addr))
		functions[addr] = True
		idx += 1

def audit_refs(functions):
	idx = 0
	while idx < len(REF_TARGETS):
		addr = REF_TARGETS[idx]
		find_refs_to(addr, label_for(addr))
		collect_ref_functions(addr, functions)
		idx += 1

def audit_windows():
	idx = 0
	while idx < len(DISASM_WINDOWS):
		addr = DISASM_WINDOWS[idx]
		disasm_window(addr, 14, 24, label_for(addr))
		func = fm.getFunctionContaining(toAddr(addr))
		if func is not None:
			faddr = func.getEntryPoint().getOffset()
			decompile_at(faddr, label_for(faddr), 22000)
			print_matching_decompile_lines(faddr, label_for(faddr))
		idx += 1

def audit_ref_functions(functions):
	write("")
	write("=" * 70)
	write("DECOMPILE FUNCTIONS THAT REFERENCE TARGETS")
	write("=" * 70)
	keys = functions.keys()
	keys.sort()
	idx = 0
	while idx < len(keys):
		addr = keys[idx]
		decompile_at(addr, label_for(addr), 18000)
		print_matching_decompile_lines(addr, label_for(addr))
		idx += 1
		if idx > 80:
			write("  ... referenced function scan truncated")
			break

def print_header():
	write("FNV GRAPHICS SCENE FOG PROPERTY CONTRACT AUDIT")
	write("")
	write("Questions:")
	write("1. Does the active scene graph index select a ShadowSceneNode from 0x011F91C8?")
	write("2. Is ShadowSceneNode + 0x134 the active BSFogProperty pointer?")
	write("3. Are BSFogProperty + 0x2C/+0x30/+0x60 live fog near/far/power?")
	write("4. Do camera + 0xEC/+0xF0 have a proven frustum near/far role?")

def main():
	functions = {}
	print_header()
	audit_targets(functions)
	audit_refs(functions)
	audit_windows()
	scan_instruction_patterns(260)
	audit_ref_functions(functions)
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_scene_fog_property_contract_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("")
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
