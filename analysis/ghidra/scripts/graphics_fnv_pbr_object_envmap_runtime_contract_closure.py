# @category Analysis
# @description Close the FNV PPLighting object EnvMap runtime shader, resource, and transition contract

from ghidra.app.decompiler import DecompInterface

if currentProgram is None:
	raise RuntimeError("Open FalloutNV.exe in CodeBrowser and run this file from Script Manager; do not paste it into the Python console")

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

FUNCTION_TARGETS = [
	(0x00B690D0, "PPLighting material EnvMap serializer, not draw apply"),
	(0x00B70820, "PPLighting ambient and per-light color staging"),
	(0x00B78A90, "PPLighting current-draw light constant staging"),
	(0x00B7DAB0, "PPLighting pass resource and constant dispatcher"),
	(0x00B994F0, "PPLighting current geometry and selector publisher"),
	(0x00BA8EC0, "PPLighting pass entry constructor A"),
	(0x00BA9EE0, "PPLighting pass entry constructor B"),
	(0x00BB41E0, "PPLighting EnvMap predicate selector"),
	(0x00BB4740, "PPLighting distance and pass-list updater"),
	(0x00BC3E40, "PPLighting active object and EnvMap selector"),
	(0x00BD4BA0, "PPLighting current pass apply"),
	(0x00BD9540, "PPLighting EnvMap-adjacent pass emitter"),
	(0x00BDB4A0, "PPLighting selector setup variant A"),
	(0x00BDF790, "PPLighting selector setup variant B"),
]

REFERENCE_TARGETS = [
	(0x00B7DAB0, "pass resource and constant dispatcher"),
	(0x00BA8EC0, "pass entry constructor A"),
	(0x00BA9EE0, "pass entry constructor B"),
	(0x00BB41E0, "EnvMap predicate selector"),
	(0x00BB4740, "distance and pass-list updater"),
	(0x00BC3E40, "active object and EnvMap selector"),
	(0x00BD4BA0, "current pass apply"),
	(0x00BD9540, "EnvMap-adjacent pass emitter"),
	(0x011FDE5C, "PPLighting vertex group C base"),
	(0x011FDF24, "PPLighting vertex group C row 50"),
	(0x011FDF28, "PPLighting vertex group C row 51"),
	(0x011FDF2C, "PPLighting vertex group C row 52"),
	(0x011FDB08, "PPLighting pixel group B base"),
	(0x011FDBEC, "PPLighting pixel group B row 57"),
	(0x011FDBF0, "PPLighting pixel group B row 58"),
	(0x011FDBF4, "PPLighting pixel group B row 59"),
	(0x011F91E0, "current PPLighting geometry"),
	(0x0126F74C, "current PPLighting pass"),
	(0x010AEAE0, "lighting 2x vertex EnvMap source string"),
	(0x010AF054, "lighting 2x pixel EnvMap source string"),
	(0x010AEAD8, "ENVMAP define string"),
	(0x010AF04C, "WINDOW define string"),
	(0x010AEAD4, "EYE define string"),
]

MATCH_PATTERNS = [
	"011fde5c",
	"011fdf2",
	"011fdb08",
	"011fdbf",
	"011f91e0",
	"0126f74c",
	"010aeae0",
	"010af054",
	"010aead8",
	"010af04c",
	"010aead4",
	"00b7dab0",
	"00ba8ec0",
	"00ba9ee0",
	"0x32",
	"0x33",
	"0x34",
	"0x39",
	"0x3a",
	"0x3b",
	"0x57",
	"0x58",
	"0x59",
	"0xbc",
	"0xc0",
	"envmap",
	"sampler",
	"texture",
	"cube",
	"window",
	"eye",
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

def line_matches(line):
	lower = line.lower()
	index = 0
	while index < len(MATCH_PATTERNS):
		if lower.find(MATCH_PATTERNS[index]) >= 0:
			return True
		index += 1
	return False

def print_matching_lines(addr_int, label):
	write("")
	write("MATCHED CONTRACT LINES: %s @ 0x%08x" % (label, addr_int))
	code = decompile_text(addr_int)
	if code is None:
		write("  [decompilation failed]")
		return
	lines = code.splitlines()
	index = 0
	count = 0
	while index < len(lines):
		if line_matches(lines[index]):
			write("  L%04d: %s" % (index + 1, lines[index]))
			count += 1
		index += 1
	write("  Total matched lines: %d" % count)

def audit_functions():
	index = 0
	while index < len(FUNCTION_TARGETS):
		item = FUNCTION_TARGETS[index]
		decompile_at(item[0], item[1], 24000)
		find_and_print_calls_from(item[0], item[1])
		print_matching_lines(item[0], item[1])
		index += 1

def audit_references():
	index = 0
	while index < len(REFERENCE_TARGETS):
		item = REFERENCE_TARGETS[index]
		find_refs_to(item[0], item[1])
		index += 1

def main():
	write("FNV PBR OBJECT ENVMAP RUNTIME CONTRACT CLOSURE")
	write("")
	write("Questions:")
	write("1. Which draw predicates select VS rows 50-52 and PS rows 57-59?")
	write("2. Which sampler stages carry the cube and mask textures?")
	write("3. Which constants, render states, and LOD values are required?")
	write("4. How do base, skin, eye, and window vertex ABIs differ?")
	write("5. Does distance rebuild the pass list or only change EnvMap weights?")
	write("")
	write("FUN_00B690D0 is included only to separate serialization from runtime draw apply.")
	audit_functions()
	audit_references()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_object_envmap_runtime_contract_closure.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("")
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
