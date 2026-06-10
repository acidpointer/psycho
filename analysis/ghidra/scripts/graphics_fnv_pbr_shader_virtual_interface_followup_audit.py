# @category Analysis
# @description Resolve FNV PBR shader virtual interface and shader object layout gaps

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x00B55520: "Light/environment selector helper used before shader interface apply",
	0x00B55560: "Shader-interface object selector used by BD4BA0",
	0x00B7C3A0: "Vertex constant upload helper: env/fog-ish c14",
	0x00B7C750: "Vertex constant upload helper: matrices c0-c3",
	0x00B7C850: "Light/constant upload helper: light count and light data c25+",
	0x00B7DAB0: "Pass-entry shader resource dispatcher with +0x78 interface calls",
	0x00B7DED0: "Alternate pass dispatcher with pixel-only +0x78 interface call",
	0x00B7DDE0: "Alternate pass dispatcher before B7C750/B7C7B0",
	0x00BD4BA0: "Current pass shader/resource apply helper from PBR interface audit",
	0x00BE08F0: "NiD3DPixelShader object constructor/initializer",
	0x00BE0B30: "NiD3DVertexShader object constructor/initializer",
	0x00BE1F90: "BSShader::SetShaders handle binder",
	0x00E7EA00: "Pass-entry downstream virtual apply helper",
	0x00E7F7C0: "Renderer helper/global accessor used by SetShaders",
	0x00E7F990: "Pass object apply helper with shader +0x78 callbacks",
	0x00E89410: "Render-state validation/apply helper",
	0x010BBD60: "Vtable/data ref to BD1C50 current pass writer",
	0x010BC0EC: "Vtable/data ref to BD4BA0 current pass shader apply helper",
	0x011F91C4: "Light/environment selector byte used by B55520",
	0x011F91E0: "Current geometry/proxy pointer slot",
	0x011F91E4: "Current pass mode/stage selector",
	0x0126F728: "Renderer helper object global used by SetShaders",
	0x0126F74C: "Current NiD3DPass global",
}

FOCUS_FUNCTIONS = [
	0x00B55520,
	0x00B55560,
	0x00BD4BA0,
	0x00B7DAB0,
	0x00B7DED0,
	0x00B7DDE0,
	0x00E7F990,
	0x00BE08F0,
	0x00BE0B30,
	0x00BE1F90,
	0x00E7F7C0,
	0x00E7EA00,
	0x00E89410,
	0x00B7C3A0,
	0x00B7C750,
	0x00B7C850,
]

REF_TARGETS = [
	0x00B55520,
	0x00B55560,
	0x00BD4BA0,
	0x00B7DAB0,
	0x00B7DED0,
	0x00B7DDE0,
	0x00E7F990,
	0x00BE08F0,
	0x00BE0B30,
	0x00BE1F90,
	0x00E7F7C0,
	0x011F91C4,
	0x011F91E0,
	0x011F91E4,
	0x0126F728,
	0x0126F74C,
]

DISASM_WINDOWS = [
	(0x00B55520, 20, 120, "B55520 light/environment selector helper"),
	(0x00B55560, 20, 140, "B55560 shader-interface object selector"),
	(0x00BD4BA0, 20, 170, "BD4BA0 current pass shader/resource apply helper"),
	(0x00B7DAB0, 20, 220, "B7DAB0 pass-entry shader resource dispatcher"),
	(0x00B7DED0, 20, 180, "B7DED0 alternate pass dispatcher"),
	(0x00E7F990, 20, 210, "E7F990 pass object apply helper"),
	(0x00BE08F0, 20, 140, "BE08F0 pixel shader object initializer"),
	(0x00BE0B30, 20, 160, "BE0B30 vertex shader object initializer"),
	(0x00BE1F90, 16, 90, "BE1F90 SetShaders handle binder"),
]

DATA_WINDOWS = [
	(0x010BC0EC, 36, 24, "Vtable window around BD4BA0 slot"),
	(0x010BBD60, 36, 24, "Vtable window around BD1C50 slot"),
	(0x010AE1E4, 20, 20, "PPLighting setup/material vtable pair A"),
	(0x010B8444, 20, 20, "PPLighting setup/material vtable pair B"),
	(0x010B944C, 20, 20, "PPLighting setup/material vtable pair C"),
	(0x010B95A4, 20, 20, "PPLighting setup/material vtable pair D"),
	(0x010B9A24, 20, 20, "PPLighting setup/material vtable pair E"),
	(0x010BAD0C, 20, 20, "PPLighting setup/material vtable pair F"),
	(0x010BCC74, 20, 20, "PPLighting setup/material vtable pair G"),
]

CALLER_DECOMPILE_TARGETS = [
	(0x00B55560, "callers of B55560 shader-interface selector"),
	(0x00B55520, "callers of B55520 selector"),
	(0x00B7DAB0, "callers of B7DAB0 pass dispatcher"),
	(0x00BD4BA0, "callers/vtable owners of BD4BA0"),
	(0x00E7F990, "callers/vtable owners of E7F990"),
]

SCAN_PATTERNS = [
	"0126f74c",
	"0126f728",
	"011f91e0",
	"011f91e4",
	"011f91c4",
	"00b55560",
	"00b55520",
	"00b7dab0",
	"00e7f990",
	"+ 0x30",
	"+0x30",
	"+ 0x34",
	"+0x34",
	"+ 0x44",
	"+0x44",
	"+ 0x48",
	"+0x48",
	"+ 0x5c",
	"+0x5c",
	"+ 0x78",
	"+0x78",
	"+ 0x7c",
	"+0x7c",
	"+ 0x80",
	"+0x80",
	"+ 0x84",
	"+0x84",
	"+ 0x88",
	"+0x88",
	"+ 0x178",
	"+0x178",
	"SetPixelShader",
	"SetVertexShader",
	"SetPixelShaderConstant",
	"SetVertexShaderConstant",
	"constant",
	"shader",
	"pixel",
	"vertex",
	"texture",
]

def write(msg):
	output.append(msg)
	print(msg)

def read_u32(addr_int):
	try:
		value = memory.getInt(toAddr(addr_int))
		if value < 0:
			value += 0x100000000
		return value
	except:
		return None

def label_for(addr_int):
	if addr_int is None:
		return "unreadable"
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

def decompile_at(addr_int, label, max_len=26000):
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
		if count >= 120:
			write("  ... (truncated)")
			break
	write("  Total printed: %d refs" % count)

def find_and_print_calls_from(addr_int, label):
	write("")
	write("--- Calls FROM %s (0x%08x) ---" % (label, addr_int))
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	if func is None:
		write("  [function not found]")
		return
	count = 0
	inst_iter = listing.getInstructions(func.getBody(), True)
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				target = ref.getToAddress()
				taddr = target.getOffset()
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), taddr, label_for(taddr)))
				count += 1
	write("  Total: %d calls" % count)

def disasm_window(addr_int, before, count, label):
	write("")
	write("-" * 70)
	write("Disassembly %s around 0x%08x" % (label, addr_int))
	write("-" * 70)
	start = addr_int - before
	inst = listing.getInstructionAt(toAddr(start))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(start))
	seen = 0
	while inst is not None and seen < count:
		off = inst.getAddress().getOffset()
		marker = " << TARGET" if off == addr_int else ""
		write("  0x%08x: %-54s%s" % (off, inst.toString(), marker))
		seen += 1
		inst = inst.getNext()

def scan_patterns(addr_int, label, patterns):
	write("")
	write("=" * 70)
	write("MATCHED DECOMPILE LINES: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	code = decompile_text(addr_int)
	if code is None:
		write("  [decompilation failed]")
		return
	lines = code.splitlines()
	count = 0
	for line in lines:
		lower = line.lower()
		for pattern in patterns:
			if pattern.lower() in lower:
				write("  %s" % line)
				count += 1
				break
		if count >= 180:
			write("  ... (truncated)")
			break
	write("  Total matched lines: %d" % count)

def print_data_window(center_int, before_slots, after_slots, label):
	write("")
	write("-" * 70)
	write("DATA WINDOW: %s centered at 0x%08x" % (label, center_int))
	write("-" * 70)
	slot = -before_slots
	while slot <= after_slots:
		addr_int = center_int + slot * 4
		value = read_u32(addr_int)
		marker = " << CENTER" if addr_int == center_int else ""
		if value is None:
			write("  0x%08x slot %+04d: unreadable%s" % (addr_int, slot, marker))
		else:
			write("  0x%08x slot %+04d: 0x%08x  %s%s" % (addr_int, slot, value, label_for(value), marker))
		slot += 1

def decompile_function_values_from_data_windows():
	write("")
	write("=" * 70)
	write("DECOMPILE FUNCTION POINTERS FROM DATA WINDOWS")
	write("=" * 70)
	seen = {}
	total = 0
	for item in DATA_WINDOWS:
		center = item[0]
		before = item[1]
		after = item[2]
		slot = -before
		while slot <= after:
			value = read_u32(center + slot * 4)
			if value is not None and seen.get(value) is None:
				func = fm.getFunctionAt(toAddr(value))
				if func is not None:
					seen[value] = 1
					decompile_at(value, "data-window function pointer %s" % label_for(value), 12000)
					find_and_print_calls_from(value, label_for(value))
					scan_patterns(value, label_for(value), SCAN_PATTERNS)
					total += 1
					if total >= 80:
						write("  ... function pointer decompile truncated at 80")
						return
			slot += 1

def decompile_ref_callers(addr_int, label, limit):
	write("")
	write("=" * 70)
	write("DECOMPILE REF CALLERS: %s 0x%08x" % (label, addr_int))
	write("=" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	seen = {}
	count = 0
	while refs.hasNext():
		ref = refs.next()
		func = fm.getFunctionContaining(ref.getFromAddress())
		if func is not None:
			entry = func.getEntryPoint().getOffset()
			if seen.get(entry) is None:
				seen[entry] = 1
				decompile_at(entry, "ref caller %s" % label, 22000)
				find_and_print_calls_from(entry, "ref caller %s" % label)
				scan_patterns(entry, "ref caller %s" % label, SCAN_PATTERNS)
				count += 1
				if count >= limit:
					write("  ... ref caller decompile truncated")
					return

def decompile_focus_functions():
	for addr_int in FOCUS_FUNCTIONS:
		decompile_at(addr_int, label_for(addr_int))
		find_and_print_calls_from(addr_int, label_for(addr_int))
		scan_patterns(addr_int, label_for(addr_int), SCAN_PATTERNS)

def print_all_refs():
	for addr_int in REF_TARGETS:
		find_refs_to(addr_int, label_for(addr_int))

def print_all_disasm_windows():
	for item in DISASM_WINDOWS:
		disasm_window(item[0], item[1], item[2], item[3])

def print_all_data_windows():
	for item in DATA_WINDOWS:
		print_data_window(item[0], item[1], item[2], item[3])

def decompile_all_ref_callers():
	for item in CALLER_DECOMPILE_TARGETS:
		decompile_ref_callers(item[0], item[1], 18)

def main():
	write("FNV PBR SHADER VIRTUAL INTERFACE FOLLOW-UP AUDIT")
	write("")
	write("Questions:")
	write("1. What concrete object does FUN_00B55560(1) return, and who populates its +0x30/+0x34 shader interface fields?")
	write("2. Which concrete functions are called through shader interface virtual slot +0x78?")
	write("3. Do those +0x78 targets upload constants, mutate shader object fields, or bind textures?")
	write("4. Are NiD3DPixelShader/NiD3DVertexShader handle slots and getter/setter methods sufficient for safe shader substitution?")
	write("")
	write("Compatibility rule:")
	write("Do not implement visible native PBR shader replacement until this output resolves the virtual +0x78 contract and shader object ownership.")
	print_all_disasm_windows()
	print_all_refs()
	print_all_data_windows()
	decompile_focus_functions()
	decompile_all_ref_callers()
	decompile_function_values_from_data_windows()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_shader_virtual_interface_followup_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("")
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
