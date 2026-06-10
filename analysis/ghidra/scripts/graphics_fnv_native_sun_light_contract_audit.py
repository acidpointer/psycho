# @category Analysis
# @description Audit FNV native sun direction and sun color contract for PBR environment constants

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x0045BB80: "CameraVectorGetter_0045BB80",
	0x0045C670: "CurrentCameraGetter_0045C670",
	0x0045CD60: "Sky sun/current object getter",
	0x006629F0: "CameraOrSceneGetter_006629F0",
	0x00870BD0: "Main render world caller / sky sun path",
	0x00873200: "Main::RenderWorldSceneGraph",
	0x00875110: "Main::RenderFirstPerson",
	0x00877730: "Sky render/update refs candidate",
	0x00B8B1E0: "Sun/light screen vector downstream candidate",
	0x011DEA20: "Sky::singleton",
}

FUNCTION_TARGETS = [
	0x0045BB80,
	0x0045C670,
	0x0045CD60,
	0x006629F0,
	0x00870BD0,
	0x00873200,
	0x00875110,
	0x00877730,
	0x00B8B1E0,
]

REF_TARGETS = [
	0x0045CD60,
	0x00870BD0,
	0x00873200,
	0x00875110,
	0x00877730,
	0x011DEA20,
]

MATCH_PATTERNS = [
	"011dea20",
	"0045cd60",
	"00b8b1e0",
	"+ 0x1c",
	"+ 0x28",
	"+ 0x60",
	"+ 0x6c",
	"+ 0xc0",
	"+ 0xc4",
	"+ 0xc8",
	"+ 0xd4",
	"+ 0xe0",
	"+ 0xf0",
	"sun",
	"light",
	"direction",
	"ambient",
	"diff",
	"spec",
]

DISASM_WINDOWS = [
	(0x00871000, 12, 42, "Main render sky/sun singleton path"),
	(0x00877780, 10, 46, "Sky update singleton path"),
	(0x00873200, 8, 44, "Main::RenderWorldSceneGraph entry"),
	(0x00875110, 8, 44, "Main::RenderFirstPerson entry"),
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
	write("SUN LIGHT MATCHES: %s @ 0x%08x" % (label, addr_int))
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
	center = toAddr(center_int)
	inst = listing.getInstructionContaining(center)
	if inst is None:
		write("  [instruction not found]")
		return
	cur = inst
	back = 0
	while back < before_count:
		prev = cur.getPrevious()
		if prev is None:
			break
		cur = prev
		back += 1
	count = 0
	limit = before_count + after_count + 1
	while cur is not None and count < limit:
		addr = cur.getAddress().getOffset()
		marker = " << TARGET" if addr == center_int else ""
		text = cur.toString()
		write("  0x%08x: %-50s%s" % (addr, text, marker))
		refs = cur.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				write("    ; CALL 0x%08x %s" % (tgt, label_for(tgt)))
		cur = cur.getNext()
		count += 1

def decompile_ref_functions(addr_int, label, limit):
	write("")
	write("=" * 70)
	write("DECOMPILE FUNCTIONS REFERENCING %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	seen = {}
	count = 0
	while refs.hasNext():
		ref = refs.next()
		func = fm.getFunctionContaining(ref.getFromAddress())
		if func is None:
			continue
		entry = func.getEntryPoint().getOffset()
		if seen.get(entry) is not None:
			continue
		seen[entry] = True
		decompile_at(entry, "%s ref function %s" % (label, func.getName()), 22000)
		print_matching_decompile_lines(entry, "%s ref function %s" % (label, func.getName()))
		find_and_print_calls_from(entry, "%s ref function %s" % (label, func.getName()))
		count += 1
		if count >= limit:
			write("  ... (ref-function decompile limit reached)")
			break
	write("  Ref functions printed: %d" % count)

def print_static_contract_notes():
	write("")
	write("=" * 70)
	write("Static layout candidates from NewVegasReloaded source to prove")
	write("=" * 70)
	write("  Sky::singleton global: *(Sky**)0x011DEA20")
	write("  Sky +0x28: Sun*")
	write("  Sky +0x60: sunAmbient NiColor candidate")
	write("  Sky +0x6C: sunDirectional NiColor candidate")
	write("  Sky +0xC0: sunFog NiColor candidate")
	write("  Sun +0x1C: NiDirectionalLight* candidate")
	write("  NiLight +0xC4: Dimmer")
	write("  NiLight +0xC8: ambient color")
	write("  NiLight +0xD4: diffuse color")
	write("  NiLight +0xE0: specular color")
	write("  NiDirectionalLight +0xF0: direction")
	write("  Main +0x1C: directionalLight candidate")
	write("  Main +0x68: Sky* candidate")

def run_refs():
	idx = 0
	while idx < len(REF_TARGETS):
		addr = REF_TARGETS[idx]
		find_refs_to(addr, label_for(addr))
		idx += 1

def run_decompiles():
	idx = 0
	while idx < len(FUNCTION_TARGETS):
		addr = FUNCTION_TARGETS[idx]
		decompile_at(addr, label_for(addr), 30000)
		print_matching_decompile_lines(addr, label_for(addr))
		find_and_print_calls_from(addr, label_for(addr))
		idx += 1

def run_disasm_windows():
	idx = 0
	while idx < len(DISASM_WINDOWS):
		item = DISASM_WINDOWS[idx]
		disasm_window(item[0], item[1], item[2], item[3])
		idx += 1

def main():
	write("FNV NATIVE SUN LIGHT CONTRACT AUDIT")
	write("")
	write("Questions:")
	write("1. Can PSY_SunDirection use renderer-owned Sun +0x1C / Main +0x1C NiDirectionalLight direction?")
	write("2. Can PSY_SunColor use final Sky +0x6C sunDirectional or NiDirectionalLight +0xD4 diffuse color?")
	write("3. Which source is safer than NewVegasReloaded's raw TESWeather::colors sun-color walk?")
	write("")
	write("Compatibility target:")
	write("Prefer final renderer-owned Sky/Sun/light fields. Do not expose TESWeather color fields unless a separate audit proves that raw layout is compatible with vanilla's generated weather property pipeline.")
	print_static_contract_notes()
	run_refs()
	run_decompiles()
	run_disasm_windows()
	decompile_ref_functions(0x011DEA20, "Sky::singleton", 10)

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_native_sun_light_contract_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
