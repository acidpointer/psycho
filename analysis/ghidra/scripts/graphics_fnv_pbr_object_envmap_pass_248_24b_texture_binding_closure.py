# @category Analysis
# @description Close FNV PBR object EnvMap pass 0x248-0x24B cube and mask texture binding

from ghidra.app.decompiler import DecompInterface

if currentProgram is None:
	raise RuntimeError("Open FalloutNV.exe in CodeBrowser and run this file from Script Manager; do not paste it into the Python console")

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

PASS_IDS = [
	(0x248, "base EnvMap VS50 PS57"),
	(0x249, "skin EnvMap VS51 PS57"),
	(0x24A, "window EnvMap VS50 PS58"),
	(0x24B, "eye EnvMap VS52 PS59"),
]

FUNCTION_TARGETS = [
	(0x00B98E80, "PPLighting draw and default virtual resource dispatch"),
	(0x00BDF790, "PPLighting pass-list construction and EnvMap predicate"),
	(0x00BDBF60, "EnvMap pass 0x248-0x24B selector"),
	(0x00B7DAB0, "PPLighting current-pass resource dispatcher vtable slot +0x7C"),
	(0x00B7D200, "PPLighting texture binder vtable slot +0x78"),
	(0x00B7C0A0, "texture binder helper B7C0A0"),
	(0x00B7C0E0, "texture binder helper B7C0E0"),
	(0x00B7C120, "texture binder helper B7C120"),
	(0x00B7C190, "texture binder helper B7C190"),
	(0x00B7C290, "texture binder helper B7C290"),
	(0x00B7C2C0, "texture binder helper B7C2C0"),
	(0x00B71B10, "texture descriptor finalization helper"),
	(0x00E7EA00, "pass descriptor texture and sampler apply"),
	(0x00E88A20, "NiDX9RenderState SetTexture interior entry"),
]

REFERENCE_TARGETS = [
	(0x00B7D200, "PPLighting texture binder"),
	(0x010AF2F8, "PPLighting selector vtable"),
	(0x010AF370, "PPLighting selector vtable slot +0x78"),
	(0x011F91E0, "current PPLighting pass entry pointer"),
	(0x0126F74C, "current NiD3DPass"),
	(0x011FE918, "pass 0x248 base owner slot"),
	(0x011FE91C, "pass 0x249 skin owner slot"),
	(0x011FE920, "pass 0x24A window owner slot"),
	(0x011FE924, "pass 0x24B eye owner slot"),
]

MATCH_PATTERNS = [
	"0x248",
	"0x249",
	"0x24a",
	"0x24b",
	"0x20000",
	"0x200000",
	"0x80",
	"0xbc",
	"0xc0",
	"0xdc",
	"0x24",
	"0x44",
	"0x5c",
	"0x78",
	"0126f74c",
	"011f91e0",
	"texture",
	"sampler",
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

def print_instruction_references(inst):
	refs = inst.getReferencesFrom()
	for ref in refs:
		write("      ref %-18s -> 0x%08x" % (str(ref.getReferenceType()), ref.getToAddress().getOffset()))

def print_raw_range(start_int, end_int, label):
	write("")
	write("=" * 70)
	write("RAW DISASSEMBLY: %s 0x%08x-0x%08x" % (label, start_int, end_int))
	write("=" * 70)
	inst = listing.getInstructionAt(toAddr(start_int))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(start_int - 1))
	count = 0
	while inst is not None and inst.getAddress().getOffset() <= end_int:
		write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
		print_instruction_references(inst)
		inst = listing.getInstructionAfter(inst.getAddress())
		count += 1
		if count > 1200:
			write("  ... (instruction safety limit reached)")
			break
	write("  Total instructions: %d" % count)

def print_target_block(target_int, label):
	write("")
	write("-" * 70)
	write("MAPPED BLOCK: %s @ 0x%08x" % (label, target_int))
	write("-" * 70)
	inst = listing.getInstructionContaining(toAddr(target_int))
	if inst is None:
		write("  [instruction not found]")
		return
	count = 0
	while inst is not None and count < 160:
		write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
		print_instruction_references(inst)
		mnemonic = inst.getMnemonicString().upper()
		count += 1
		if mnemonic.startswith("RET"):
			break
		inst = listing.getInstructionAfter(inst.getAddress())
	write("  Total instructions: %d" % count)

def read_u8(addr_int):
	return memory.getByte(toAddr(addr_int)) & 0xff

def read_u32(addr_int):
	return memory.getInt(toAddr(addr_int)) & 0xffffffff

def resolve_pass_jump_target(pass_id):
	dispatch_index = read_u8(0x00B7D7B8 + pass_id - 2)
	target = read_u32(0x00B7D740 + dispatch_index * 4)
	return dispatch_index, target

def audit_pass_jump_table():
	write("")
	write("=" * 70)
	write("B7D200 BYTE-INDEXED JUMP TABLE FOR ENVMAP PASSES")
	write("=" * 70)
	write("Code contract: pass_id = word [*0x011F91E0 + 4]; index byte = [0x00B7D7B8 + pass_id - 2]; target = [0x00B7D740 + index * 4]")
	index = 0
	targets = {}
	while index < len(PASS_IDS):
		item = PASS_IDS[index]
		dispatch_index, target = resolve_pass_jump_target(item[0])
		write("  pass 0x%03x %-28s -> dispatch %3d -> 0x%08x" % (item[0], item[1], dispatch_index, target))
		targets[target] = item[1]
		index += 1
	addresses = targets.keys()
	addresses.sort()
	index = 0
	while index < len(addresses):
		target = addresses[index]
		print_target_block(target, targets[target])
		index += 1

def audit_neighbor_jump_table():
	write("")
	write("=" * 70)
	write("NEIGHBOR PASS JUMP-TABLE MAPPING 0x240-0x251")
	write("=" * 70)
	pass_id = 0x240
	while pass_id <= 0x251:
		dispatch_index, target = resolve_pass_jump_target(pass_id)
		write("  pass 0x%03x -> dispatch %3d -> 0x%08x" % (pass_id, dispatch_index, target))
		pass_id += 1

def audit_owner_table_relation():
	write("")
	write("=" * 70)
	write("PASS OWNER TABLE RELATION")
	write("=" * 70)
	index = 0
	while index < len(PASS_IDS):
		item = PASS_IDS[index]
		slot = 0x011FDFF8 + item[0] * 4
		write("  pass 0x%03x -> owner slot 0x%08x, static value 0x%08x (%s)" % (item[0], slot, read_u32(slot), item[1]))
		index += 1

def audit_vtable():
	write("")
	write("=" * 70)
	write("PPLIGHTING SELECTOR VTABLE RUNTIME SLOTS")
	write("=" * 70)
	offset = 0x70
	while offset <= 0x88:
		value = read_u32(0x010AF2F8 + offset)
		func = fm.getFunctionAt(toAddr(value))
		name = func.getName() if func else "???"
		write("  vtable +0x%02x @ 0x%08x -> 0x%08x %s" % (offset, 0x010AF2F8 + offset, value, name))
		offset += 4

def audit_functions():
	index = 0
	while index < len(FUNCTION_TARGETS):
		item = FUNCTION_TARGETS[index]
		decompile_at(item[0], item[1], 36000)
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
	write("FNV PBR OBJECT ENVMAP PASS 0x248-0x24B TEXTURE BINDING CLOSURE")
	write("")
	write("Established contract:")
	write("- pass 0x248: base, VS50 / PS57")
	write("- pass 0x249: skin, VS51 / PS57")
	write("- pass 0x24A: window, VS50 / PS58")
	write("- pass 0x24B: eye, VS52 / PS59")
	write("- E7EA00 applies descriptor +8 to the descriptor's final sampler stage")
	write("")
	write("Questions:")
	write("1. Which B7D200 jump-table block handles each EnvMap pass?")
	write("2. Which property fields populate each owner descriptor +8 texture pointer?")
	write("3. Which final stages receive diffuse, normal, cube, and mask resources?")
	write("4. Does any distance-dependent branch change resources or only fade constants?")
	audit_owner_table_relation()
	audit_vtable()
	audit_pass_jump_table()
	audit_neighbor_jump_table()
	print_raw_range(0x00B7D200, 0x00B7D73F, "complete B7D200 executable body before its jump tables")
	audit_functions()
	audit_references()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_object_envmap_pass_248_24b_texture_binding_closure.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("")
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
