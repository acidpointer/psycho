# @category Analysis
# @description Close FNV object EnvMap owner selection, sampler binding, and runtime pass ownership

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
	(0x00B78980, "PPLighting shader initialization caller"),
	(0x00B7DAB0, "PPLighting current pass resource dispatcher"),
	(0x00BDD520, "PPLighting two-resource pass selector"),
	(0x00BFBF60, "EnvMap base skin window eye owner initializer"),
	(0x00BE0CF0, "shader sampler descriptor initializer"),
	(0x00E7EDF0, "shader sampler descriptor allocator"),
	(0x00E7F430, "shader constant interface record registrar"),
	(0x00E7EA00, "pass entry texture and state apply"),
	(0x00E802B0, "shader owner sampler descriptor append"),
]

OWNER_TARGETS = [
	(0x011FE918, "base EnvMap shader owner"),
	(0x011FE91C, "skin EnvMap shader owner"),
	(0x011FE920, "window EnvMap shader owner"),
	(0x011FE924, "eye EnvMap shader owner"),
]

OWNER_MASK_TARGETS = [
	(0x011FD5A0, "base EnvMap owner constant mask"),
	(0x011FD5A4, "skin EnvMap owner constant mask"),
	(0x011FD5A8, "window EnvMap owner constant mask"),
	(0x011FD5AC, "eye EnvMap owner constant mask"),
	(0x011FC9C0, "base EnvMap owner interface flags"),
	(0x011FC9C4, "skin EnvMap owner interface flags"),
	(0x011FC9C8, "window EnvMap owner interface flags"),
	(0x011FC9CC, "eye EnvMap owner interface flags"),
]

REFERENCE_TARGETS = OWNER_TARGETS + OWNER_MASK_TARGETS + [
	(0x00BFBF60, "EnvMap owner initializer"),
	(0x00E7EA00, "pass entry texture and state apply"),
	(0x00E88A20, "NiDX9RenderState SetTexture interior entry"),
	(0x0126F74C, "current NiD3DPass"),
]

DISASM_TARGETS = [
	(0x00B78A01, "first call to EnvMap owner initializer"),
	(0x00B7A819, "second call to EnvMap owner initializer outside a defined function"),
	(0x00E88A20, "NiDX9RenderState SetTexture interior entry"),
]

MATCH_PATTERNS = [
	"011fe918",
	"011fe91c",
	"011fe920",
	"011fe924",
	"011fd5a",
	"011fc9c",
	"0126f74c",
	"00bfbf60",
	"00e7ea00",
	"00e88a20",
	"0x30",
	"0x44",
	"0x5c",
	"0x78",
	"0xbc",
	"0xc0",
	"0xdc",
	"envmap",
	"texture",
	"sampler",
	"shader",
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

def instruction_before_steps(inst, steps):
	current = inst
	index = 0
	while current is not None and index < steps:
		previous = listing.getInstructionBefore(current.getAddress())
		if previous is None:
			break
		current = previous
		index += 1
	return current

def print_instruction_references(inst):
	refs = inst.getReferencesFrom()
	for ref in refs:
		write("      ref %-18s -> 0x%08x" % (str(ref.getReferenceType()), ref.getToAddress().getOffset()))

def disasm_window(center_int, before_count, after_count, label):
	write("")
	write("=" * 70)
	write("DISASM: %s around 0x%08x" % (label, center_int))
	write("=" * 70)
	inst = listing.getInstructionContaining(toAddr(center_int))
	if inst is None:
		write("  [instruction not found]")
		return
	current = instruction_before_steps(inst, before_count)
	limit = before_count + after_count + 1
	count = 0
	while current is not None and count < limit:
		marker = "=> " if current.getAddress().getOffset() == inst.getAddress().getOffset() else "   "
		write("%s0x%08x: %s" % (marker, current.getAddress().getOffset(), current.toString()))
		print_instruction_references(current)
		current = listing.getInstructionAfter(current.getAddress())
		count += 1

def collect_unique_ref_functions(targets):
	functions = {}
	orphans = {}
	target_index = 0
	while target_index < len(targets):
		item = targets[target_index]
		refs = ref_mgr.getReferencesTo(toAddr(item[0]))
		while refs.hasNext():
			ref = refs.next()
			func = fm.getFunctionContaining(ref.getFromAddress())
			if func is None:
				orphans[ref.getFromAddress().getOffset()] = item[1]
			else:
				functions[func.getEntryPoint().getOffset()] = func.getName()
		target_index += 1
	return functions, orphans

def audit_unique_ref_functions(targets):
	functions, orphans = collect_unique_ref_functions(targets)
	write("")
	write("=" * 70)
	write("UNIQUE FUNCTIONS REFERRING TO ENVMAP OWNERS OR OWNER FLAGS")
	write("=" * 70)
	addresses = functions.keys()
	addresses.sort()
	index = 0
	while index < len(addresses):
		addr_int = addresses[index]
		label = "owner/flag ref function %s" % functions[addr_int]
		decompile_at(addr_int, label, 32000)
		find_and_print_calls_from(addr_int, label)
		print_matching_lines(addr_int, label)
		index += 1
	write("  Total unique functions: %d" % len(addresses))
	orphan_addresses = orphans.keys()
	orphan_addresses.sort()
	index = 0
	while index < len(orphan_addresses):
		addr_int = orphan_addresses[index]
		disasm_window(addr_int, 56, 72, "orphan owner/flag ref for %s" % orphans[addr_int])
		index += 1
	write("  Total orphan reference sites: %d" % len(orphan_addresses))

def audit_functions():
	index = 0
	while index < len(FUNCTION_TARGETS):
		item = FUNCTION_TARGETS[index]
		decompile_at(item[0], item[1], 40000)
		find_and_print_calls_from(item[0], item[1])
		print_matching_lines(item[0], item[1])
		index += 1

def audit_references():
	index = 0
	while index < len(REFERENCE_TARGETS):
		item = REFERENCE_TARGETS[index]
		find_refs_to(item[0], item[1])
		index += 1

def audit_disasm():
	index = 0
	while index < len(DISASM_TARGETS):
		item = DISASM_TARGETS[index]
		disasm_window(item[0], 96, 112, item[1])
		index += 1

def main():
	write("FNV PBR OBJECT ENVMAP OWNER RUNTIME BINDING CLOSURE")
	write("")
	write("Known from the prior output:")
	write("- base owner: VS50 / PS57")
	write("- skin owner: VS51 / PS57")
	write("- window owner: VS50 / PS58")
	write("- eye owner: VS52 / PS59")
	write("")
	write("Questions:")
	write("1. Which runtime paths select each of the four owner objects?")
	write("2. Which material resources bind to owner sampler stages 0 through 3?")
	write("3. Which owner flags and interface records are consumed at draw time?")
	write("4. Can the EnvMap owners be replaced without changing pass construction or state ownership?")
	audit_functions()
	audit_references()
	audit_unique_ref_functions(OWNER_TARGETS + OWNER_MASK_TARGETS)
	audit_disasm()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_object_envmap_owner_runtime_binding_closure.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("")
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
