# @category Analysis
# @description Bounded evidence pack for exterior object PBR pass/fog ownership and separate close, fade, and LandLOD contracts

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

DECOMPILE_TIMEOUT_SECONDS = 20
MAX_REFS = 48
MAX_CALLS = 120
MAX_INSTRUCTIONS = 50000
MAX_MATCHES = 180

TARGETS = [
	(0x00B4F9D0, "PPLighting pass description resolver", 14000),
	(0x00B7AF80, "PPLighting shader setup and pass constant dispatch", 26000),
	(0x00B7B450, "PPLighting per-pass constant flag and fog updater", 26000),
	(0x00B7E430, "PPLighting constant table registration", 30000),
	(0x00B994F0, "current geometry and selector writer", 18000),
	(0x00BDAF10, "close terrain material row emitter", 26000),
	(0x00BDAC00, "terrain zero-resource row emitter", 22000),
	(0x00BDF3E0, "LandO and terrain light-resource row emitter", 28000),
	(0x00BDF650, "terrain helper row emitter A", 18000),
	(0x00BDF6C0, "terrain helper row emitter B", 18000),
	(0x00BDF790, "PPLighting selector and pass-entry driver", 32000),
	(0x00BD4BA0, "current pass shader-interface apply", 26000),
	(0x00E90850, "current NiD3DPass writer", 20000),
]

CALL_TARGETS = [
	(0x00B4F9D0, "PPLighting pass description resolver"),
	(0x00B7AF80, "PPLighting shader setup and pass constant dispatch"),
	(0x00B7B450, "PPLighting per-pass constant flag and fog updater"),
	(0x00B994F0, "current geometry and selector writer"),
	(0x00BDAF10, "close terrain material row emitter"),
	(0x00BDAC00, "terrain zero-resource row emitter"),
	(0x00BDF3E0, "LandO and terrain light-resource row emitter"),
	(0x00BDF650, "terrain helper row emitter A"),
	(0x00BDF6C0, "terrain helper row emitter B"),
	(0x00BDF790, "PPLighting selector and pass-entry driver"),
	(0x00BD4BA0, "current pass shader-interface apply"),
	(0x00E90850, "current NiD3DPass writer"),
]

REF_TARGETS = [
	(0x00B4F9D0, "PPLighting pass description resolver"),
	(0x00B7AF80, "PPLighting shader setup and pass constant dispatch"),
	(0x00B7B450, "PPLighting per-pass constant flag and fog updater"),
	(0x00B994F0, "current geometry and selector writer"),
	(0x00BD4BA0, "current pass shader-interface apply"),
	(0x00BE1F90, "BSShader::SetShaders"),
	(0x011FA280, "PPLighting FogParam backing value"),
	(0x011FA290, "PPLighting FogColor backing value"),
	(0x011FC0A0, "PPLighting pixel constant flags"),
	(0x011FCC80, "PPLighting vertex constant flags"),
	(0x011F91E0, "current geometry slot"),
	(0x0126F74C, "current NiD3DPass"),
]

WINDOWS = [
	(0x00B4F9D0, 8, 48, "pass description resolver entry"),
	(0x00B7B450, 8, 56, "per-pass flag dispatch entry"),
	(0x00B7B5D4, 24, 32, "fog backing update path"),
	(0x00B994F0, 8, 64, "current geometry writer entry"),
	(0x00BDB1C7, 18, 28, "close terrain row 0x1F2 layer write"),
	(0x00BDB204, 18, 28, "close terrain row 0x1F3 layer write"),
	(0x00BDB28E, 18, 28, "close terrain row 0x1F4 layer write"),
	(0x00BDB334, 18, 28, "close terrain row 0x1F5 layer write"),
	(0x00BDF5F5, 24, 32, "LandO light-resource branch"),
	(0x00BD4C35, 20, 42, "pixel shader-interface apply"),
	(0x00BD4CBC, 20, 42, "vertex shader-interface apply"),
	(0x00BE1F90, 12, 58, "BSShader::SetShaders raw entry"),
	(0x00E90933, 24, 38, "current NiD3DPass write"),
]

CONTRACT_TARGETS = [
	(0x00B4F9D0, "PPLighting pass description resolver"),
	(0x00B7AF80, "PPLighting shader setup and pass constant dispatch"),
	(0x00B7B450, "PPLighting per-pass constant flag and fog updater"),
	(0x00B994F0, "current geometry and selector writer"),
	(0x00BDAF10, "close terrain material row emitter"),
	(0x00BDAC00, "terrain zero-resource row emitter"),
	(0x00BDF3E0, "LandO and terrain light-resource row emitter"),
	(0x00BDF650, "terrain helper row emitter A"),
	(0x00BDF6C0, "terrain helper row emitter B"),
	(0x00BDF790, "PPLighting selector and pass-entry driver"),
	(0x00BD4BA0, "current pass shader-interface apply"),
	(0x00E90850, "current NiD3DPass writer"),
]

NEEDLES = [
	"0x1f2",
	"0x1f3",
	"0x1f4",
	"0x1f5",
	"0x230",
	"0x218",
	"0xfe",
	"0x254",
	"0x258",
	"0x400",
	"0x800",
	"0x11fcc80",
	"0x11fc0a0",
	"0x11fa280",
	"0x11fa290",
	"0x11f91e0",
	"0x126f74c",
	"0x18",
	"0x24",
	"0x44",
	"0x5c",
	"0x68",
	"0xc0",
]

def write(msg):
	output.append(msg)
	print(msg)

def get_function_at_or_containing(addr_int):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	return func

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
	result = decomp.decompileFunction(func, DECOMPILE_TIMEOUT_SECONDS, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		write(code[:max_len])
		if len(code) > max_len:
			write("  ... [truncated, total chars=%d]" % len(code))
	else:
		write("  [decompilation failed or timed out after %d seconds]" % DECOMPILE_TIMEOUT_SECONDS)

def find_refs_to(addr_int, label):
	write("")
	write("-" * 70)
	write("References TO 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext() and count < MAX_REFS:
		ref = refs.next()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		fname = from_func.getName() if from_func else "???"
		write("  %s @ 0x%08x (in %s)" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname))
		count += 1
	if refs.hasNext():
		write("  ... [truncated at %d refs]" % MAX_REFS)
	write("  Printed: %d refs" % count)

def find_and_print_calls_from(addr_int, label):
	func = get_function_at_or_containing(addr_int)
	write("")
	write("--- Calls FROM %s (0x%08x) ---" % (label, addr_int))
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	seen = 0
	while inst_iter.hasNext() and seen < MAX_INSTRUCTIONS and count < MAX_CALLS:
		inst = inst_iter.next()
		seen += 1
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				tgt_func = fm.getFunctionAt(toAddr(tgt))
				name = tgt_func.getName() if tgt_func else "???"
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, name))
				count += 1
				if count >= MAX_CALLS:
					break
	if inst_iter.hasNext():
		write("  ... [bounded scan stopped]")
	write("  Total printed: %d calls" % count)

def disassemble_window(addr_int, before_count, after_count, label):
	write("")
	write("-" * 70)
	write("Disassembly %s around 0x%08x" % (label, addr_int))
	write("-" * 70)
	center = listing.getInstructionContaining(toAddr(addr_int))
	if center is None:
		write("  [instruction not found]")
		return
	items = []
	current = center
	count = 0
	while current is not None and count < before_count:
		current = current.getPrevious()
		if current is not None:
			items.insert(0, current)
		count += 1
	items.append(center)
	current = center
	count = 0
	while current is not None and count < after_count:
		current = current.getNext()
		if current is not None:
			items.append(current)
		count += 1
	for inst in items:
		marker = " << TARGET" if inst.getAddress().getOffset() == center.getAddress().getOffset() else ""
		write("  0x%08x: %-58s%s" % (inst.getAddress().getOffset(), inst.toString(), marker))

def scan_contract_instructions(addr_int, label):
	func = get_function_at_or_containing(addr_int)
	write("")
	write("=" * 70)
	write("CONTRACT INSTRUCTIONS: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	seen = 0
	matches = 0
	while inst_iter.hasNext() and seen < MAX_INSTRUCTIONS and matches < MAX_MATCHES:
		inst = inst_iter.next()
		seen += 1
		text = inst.toString().lower()
		matched = False
		for needle in NEEDLES:
			if needle in text:
				matched = True
				break
		if matched:
			write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
			matches += 1
	if inst_iter.hasNext():
		write("  ... [bounded scan stopped]")
	write("  Total printed: %d matches from %d instructions" % (matches, seen))

def run_decompiles():
	for item in TARGETS:
		decompile_at(item[0], item[1], item[2])

def run_calls():
	for item in CALL_TARGETS:
		find_and_print_calls_from(item[0], item[1])

def run_refs():
	for item in REF_TARGETS:
		find_refs_to(item[0], item[1])

def run_windows():
	for item in WINDOWS:
		disassemble_window(item[0], item[1], item[2], item[3])

def run_contract_scans():
	for item in CONTRACT_TARGETS:
		scan_contract_instructions(item[0], item[1])

write("FNV OMV PBR EXTERIOR AND TERRAIN CONTRACT EVIDENCE PACK")
write("Questions:")
write("1. Is SetShaders PassIndex the stable identity needed to separate base, additive, fade, LandLOD, and close terrain draws?")
write("2. Which pass rows enable FogParam/FogColor, and are additive object light passes intentionally unfogged?")
write("3. Where are current geometry and current NiD3DPass established relative to constant and shader-interface application?")
write("4. Which rows own close terrain material arrays, and which rows are zero-resource, LandO, point-light, or helper paths?")
write("5. Are terrain fade pass 560 and LandLOD pass 254 independent from the close terrain 0x1F2..0x1F5 material rows?")
write("6. Which exact state fields must runtime telemetry capture before any terrain family is enabled?")

run_decompiles()
run_calls()
run_refs()
run_windows()
run_contract_scans()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_omv_pbr_exterior_terrain_contract_evidence_pack.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
