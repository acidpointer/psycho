# @category Analysis
# @description Follow FNV PPLighting resolver output into source-texture renderer-data vtables

from ghidra.app.decompiler import DecompInterface
import re

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x0043B300: "name/global lookup helper used with DAT_011F444C",
	0x00653290: "attached-data/property helper used by resolver",
	0x006532C0: "helper called by 00653290",
	0x00A5FCA0: "NiSourceTexture destructor",
	0x00A7F810: "base constructor called by E88EB0 helper object",
	0x00AA13E0: "allocation helper",
	0x00AA1460: "free sized allocation/helper",
	0x00BA8A90: "resolver vtable +0x08 target",
	0x00E68A80: "NiDX9SourceTextureData load/create candidate",
	0x00E68EF0: "source-texture renderer-data factory; writes source +0x24",
	0x00E75A70: "renderer teardown/destructor-like function",
	0x00E88EB0: "post-resolver renderer helper object factory",
	0x00E90A80: "renderer +0x8C4 resolver constructor",
	0x00E90B10: "resolver slot +0x0C: resolves entry +8 to bindable texture pointer",
	0x00E90C70: "resolver slot +0x10 target used by renderer vtable +0xE0",
	0x00E90D20: "resolver slot +0x14 target",
	0x010EDA24: "persistent source texture renderer-data adjacent vtable candidate",
	0x010EDA44: "persistent source texture renderer-data adjacent vtable candidate",
	0x010EDA64: "persistent source texture renderer-data adjacent vtable candidate",
	0x010EDA84: "persistent source texture renderer-data adjacent vtable candidate",
	0x010EDAA4: "persistent source texture renderer-data adjacent vtable candidate",
	0x010EDAC4: "persistent source texture renderer-data adjacent vtable candidate",
	0x010EDAE4: "persistent source texture renderer-data adjacent vtable candidate",
	0x010EDAEC: "persistent source texture renderer-data adjacent vtable candidate",
	0x010EDAF4: "persistent source texture renderer-data adjacent vtable candidate",
	0x010EDAFC: "persistent source texture renderer-data adjacent vtable candidate",
	0x010EDB1C: "persistent source texture renderer-data adjacent vtable candidate",
	0x010EDB3C: "persistent source texture renderer-data adjacent vtable candidate",
	0x010EDB5C: "persistent source texture renderer-data adjacent vtable candidate",
	0x010EDB7C: "persistent source texture renderer-data adjacent vtable candidate",
	0x010EDB9C: "persistent source texture renderer-data adjacent vtable candidate",
	0x010EF718: "post-resolver helper object vtable",
	0x010F086C: "renderer +0x8C4 resolver vtable",
	0x011F444C: "source-texture renderer-data class/global key used by resolver",
	0x011F4748: "renderer/global root used for critical section at +0x180",
}

FOCUS_FUNCTIONS = [
	(0x00E90B10, "resolver slot +0x0C texture pointer resolver", 36000),
	(0x00E90C70, "resolver slot +0x10 validity/helper", 26000),
	(0x00E90D20, "resolver slot +0x14 auxiliary getter", 22000),
	(0x00BA8A90, "resolver slot +0x08 target", 18000),
	(0x00E68EF0, "source-texture renderer-data factory", 36000),
	(0x00E68A80, "NiDX9SourceTextureData load/create candidate", 42000),
	(0x00653290, "attached-data/property helper used by resolver", 12000),
	(0x006532C0, "attached-data helper callee", 18000),
	(0x0043B300, "DAT_011F444C lookup helper", 18000),
	(0x00E88EB0, "post-resolver renderer helper object factory", 16000),
	(0x00E90A80, "renderer +0x8C4 resolver constructor", 16000),
]

REF_TARGETS = [
	0x00E90B10,
	0x00E90C70,
	0x00E90D20,
	0x00BA8A90,
	0x00E68EF0,
	0x00E68A80,
	0x00653290,
	0x006532C0,
	0x0043B300,
	0x011F444C,
	0x011F4748,
]

RAW_WINDOWS = [
	(0x00E90B10, 0, 120, "resolver slot +0x0C entry"),
	(0x00E90BC2, 14, 70, "resolver slot +0x0C texture-return virtual calls"),
	(0x00E90C70, 0, 90, "resolver slot +0x10 entry"),
	(0x00E90D20, 0, 70, "resolver slot +0x14 entry"),
	(0x00E68EF0, 0, 140, "source-texture renderer-data factory"),
	(0x00E68A80, 0, 180, "NiDX9SourceTextureData load/create candidate"),
	(0x00653290, 0, 50, "attached-data/property helper"),
]

FIXED_VTABLE_BASES = [
	(0x010EDA24, "persistent source texture renderer-data adjacent vtable candidate"),
	(0x010EDA44, "persistent source texture renderer-data adjacent vtable candidate"),
	(0x010EDA64, "persistent source texture renderer-data adjacent vtable candidate"),
	(0x010EDA84, "persistent source texture renderer-data adjacent vtable candidate"),
	(0x010EDAA4, "persistent source texture renderer-data adjacent vtable candidate"),
	(0x010EDAC4, "persistent source texture renderer-data adjacent vtable candidate"),
	(0x010EDAE4, "persistent source texture renderer-data adjacent vtable candidate"),
	(0x010EDAEC, "persistent source texture renderer-data adjacent vtable candidate"),
	(0x010EDAF4, "persistent source texture renderer-data adjacent vtable candidate"),
	(0x010EDAFC, "persistent source texture renderer-data adjacent vtable candidate"),
	(0x010EDB1C, "persistent source texture renderer-data adjacent vtable candidate"),
	(0x010EDB3C, "persistent source texture renderer-data adjacent vtable candidate"),
	(0x010EDB5C, "persistent source texture renderer-data adjacent vtable candidate"),
	(0x010EDB7C, "persistent source texture renderer-data adjacent vtable candidate"),
	(0x010EDB9C, "persistent source texture renderer-data adjacent vtable candidate"),
	(0x010EF718, "post-resolver helper object vtable"),
	(0x010F086C, "renderer +0x8C4 resolver vtable"),
]

VTABLE_SLOTS = [
	(0x00, "destructor/release candidate"),
	(0x04, "ref/add candidate"),
	(0x08, "ref/release candidate"),
	(0x98, "resolver-called renderer-data slot +0x98"),
	(0x9C, "resolver-called texture/wrapper slot +0x9C"),
	(0xA0, "nearby renderer-data slot +0xA0"),
	(0xA4, "resolver-called renderer-data slot +0xA4"),
	(0xA8, "resolver-called renderer-data slot +0xA8"),
	(0xAC, "resolver-called renderer-data slot +0xAC"),
	(0xB0, "nearby renderer-data slot +0xB0"),
	(0xB4, "resolver-called wrapper slot +0xB4"),
	(0xB8, "nearby renderer-data slot +0xB8"),
	(0xDC, "nearby D3D/resource slot +0xDC"),
	(0x13C, "renderer slot used by E90D20"),
]

SELECTED_SLOTS = [
	0x98,
	0x9C,
	0xA4,
	0xA8,
	0xAC,
	0xB4,
]

MATCH_PATTERNS = [
	"011f444c",
	"011f4748",
	"e90b10",
	"e90c70",
	"e90d20",
	"e68ef0",
	"e68a80",
	"653290",
	"+ 0x24",
	"+0x24",
	"+ 0x40",
	"+0x40",
	"+ 0x98",
	"+0x98",
	"+ 0x9c",
	"+0x9c",
	"+ 0xa4",
	"+0xa4",
	"+ 0xa8",
	"+0xa8",
	"+ 0xac",
	"+0xac",
	"+ 0xb4",
	"+0xb4",
	"texture",
	"renderer",
	"resource",
	"source",
	"local_",
	"param_",
]

SCAN_FUNCTIONS_FOR_VTABLES = [
	(0x00E68EF0, "source-texture renderer-data factory"),
	(0x00E68A80, "NiDX9SourceTextureData load/create candidate"),
	(0x00E88EB0, "post-resolver renderer helper object factory"),
	(0x00E90A80, "renderer +0x8C4 resolver constructor"),
	(0x00BA8A90, "resolver slot +0x08 target"),
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
	try:
		func = fm.getFunctionAt(toAddr(addr_int))
		if func is not None:
			return func.getName()
		func = fm.getFunctionContaining(toAddr(addr_int))
		if func is not None:
			return "%s+0x%x" % (func.getName(), addr_int - func.getEntryPoint().getOffset())
	except:
		pass
	return "unknown"

def operand_text(inst, index):
	try:
		return inst.getDefaultOperandRepresentation(index)
	except:
		return "?"

def operand_scalar_int(inst, index):
	try:
		scalar = inst.getScalar(index)
		if scalar is None:
			return None
		value = scalar.getUnsignedValue()
		return int(value & 0xffffffff)
	except:
		return None

def ref_kind(ref):
	rt = ref.getReferenceType()
	name = rt.toString()
	kind = "?"
	try:
		if rt.isWrite():
			kind = "WRITE"
	except:
		pass
	try:
		if rt.isRead():
			if kind == "?":
				kind = "READ"
			else:
				kind = kind + "+READ"
	except:
		pass
	return "%s/%s" % (name, kind)

def ensure_function_at(addr_int, label):
	addr = toAddr(addr_int)
	func = fm.getFunctionAt(addr)
	if func is not None:
		return func
	containing = fm.getFunctionContaining(addr)
	if containing is not None:
		write("  NOTE: 0x%08x is inside existing %s @ 0x%08x" % (addr_int, containing.getName(), containing.getEntryPoint().getOffset()))
		return containing
	try:
		disassemble(addr)
	except Exception as err:
		write("  disassemble failed at 0x%08x (%s): %s" % (addr_int, label, err))
	try:
		func = createFunction(addr, "pbr_texturedata_followup_%08x" % addr_int)
		if func is not None:
			write("  created function at 0x%08x (%s)" % (addr_int, label))
		return func
	except Exception as err:
		write("  createFunction failed at 0x%08x (%s): %s" % (addr_int, label, err))
		return None

def decompile_text_for_func(func):
	if func is None:
		return None
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		return result.getDecompiledFunction().getC()
	return None

def decompile_at(addr_int, label, max_len=22000):
	write("")
	write("=" * 70)
	write("%s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	func = ensure_function_at(addr_int, label)
	if func is None:
		write("  [function not found]")
		return
	faddr = func.getEntryPoint().getOffset()
	write("  Function: %s @ 0x%08x, Size: %d bytes" % (func.getName(), faddr, func.getBody().getNumAddresses()))
	if faddr != addr_int:
		write("  NOTE: Requested 0x%08x is inside %s (entry at 0x%08x)" % (addr_int, func.getName(), faddr))
	code = decompile_text_for_func(func)
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
		write("  %s @ 0x%08x (in %s) %s" % (ref_kind(ref), from_addr.getOffset(), fname, inst_text))
		count += 1
		if count > 120:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)

def find_and_print_calls_from(addr_int, label):
	func = ensure_function_at(addr_int, label)
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

def call_target_from_inst(inst):
	refs = inst.getReferencesFrom()
	for ref in refs:
		if ref.getReferenceType().isCall():
			return ref.getToAddress().getOffset()
	return None

def instruction_before_steps(inst, steps):
	cur = inst
	count = 0
	while count < steps and cur is not None:
		cur = listing.getInstructionBefore(cur.getAddress())
		count += 1
	return cur

def disasm_window(center_int, before_count, after_count, label):
	write("")
	write("=" * 70)
	write("Raw disassembly %s around 0x%08x" % (label, center_int))
	write("=" * 70)
	inst = listing.getInstructionContaining(toAddr(center_int))
	if inst is None:
		inst = listing.getInstructionAt(toAddr(center_int))
	if inst is None:
		write("  [instruction not found]")
		return
	cur = instruction_before_steps(inst, before_count)
	if cur is None:
		cur = inst
	idx = 0
	limit = before_count + after_count + 1
	while cur is not None and idx < limit:
		addr_int = cur.getAddress().getOffset()
		marker = " << TARGET" if addr_int == inst.getAddress().getOffset() else ""
		extra = ""
		target = call_target_from_inst(cur)
		if target is not None:
			extra = " ; CALL 0x%08x %s" % (target, label_for(target))
		write("  0x%08x: %-58s%s%s" % (addr_int, cur.toString(), marker, extra))
		refs = cur.getReferencesFrom()
		for ref in refs:
			if not ref.getReferenceType().isCall():
				write("      ref %s -> 0x%08x %s" % (ref.getReferenceType(), ref.getToAddress().getOffset(), label_for(ref.getToAddress().getOffset())))
		cur = listing.getInstructionAfter(cur.getAddress())
		idx += 1

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
	write("MATCHED DECOMPILE LINES: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	func = ensure_function_at(addr_int, label)
	code = decompile_text_for_func(func)
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

def append_unique(items, value):
	if value is None:
		return
	idx = 0
	while idx < len(items):
		if items[idx] == value:
			return
		idx += 1
	items.append(value)

def is_probable_code_addr(value):
	return value is not None and value >= 0x00400000 and value < 0x01000000

def is_probable_vtable_base(value):
	if value is None:
		return False
	if value < 0x01000000 or value > 0x01280000:
		return False
	first = read_u32(value)
	if first is None:
		return False
	return is_probable_code_addr(first)

def parse_hex_constants(text):
	values = []
	matches = re.findall("0x[0-9a-fA-F]+", text)
	idx = 0
	while idx < len(matches):
		try:
			append_unique(values, int(matches[idx], 16))
		except:
			pass
		idx += 1
	return values

def list_contains_addr(items, addr_int):
	idx = 0
	while idx < len(items):
		if items[idx] == addr_int:
			return True
		idx += 1
	return False

def add_fixed_vtables(result):
	idx = 0
	while idx < len(FIXED_VTABLE_BASES):
		append_unique(result, FIXED_VTABLE_BASES[idx][0])
		idx += 1

def scan_function_for_vtables(addr_int, label, result):
	write("")
	write("=" * 70)
	write("VTABLE IMMEDIATE SCAN: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	func = ensure_function_at(addr_int, label)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	while inst_iter.hasNext():
		inst = inst_iter.next()
		text = inst.toString()
		lower = text.lower()
		op0 = operand_text(inst, 0)
		op1 = operand_text(inst, 1)
		scalar1 = operand_scalar_int(inst, 1)
		if lower.find("mov") == 0 and op0.find("[") >= 0:
			if is_probable_vtable_base(scalar1):
				append_unique(result, scalar1)
				write("  VTABLE-SCALAR 0x%08x: %-58s op0=%s op1=%s -> 0x%08x %s" % (inst.getAddress().getOffset(), text, op0, op1, scalar1, label_for(scalar1)))
		values = parse_hex_constants(text)
		idx = 0
		while idx < len(values):
			value = values[idx]
			if is_probable_vtable_base(value):
				append_unique(result, value)
				write("  VTABLE-HEX    0x%08x: %-58s -> 0x%08x %s" % (inst.getAddress().getOffset(), text, value, label_for(value)))
			idx += 1

def collect_vtable_bases():
	result = []
	add_fixed_vtables(result)
	idx = 0
	while idx < len(SCAN_FUNCTIONS_FOR_VTABLES):
		item = SCAN_FUNCTIONS_FOR_VTABLES[idx]
		scan_function_for_vtables(item[0], item[1], result)
		idx += 1
	return result

def print_vtable_slot_table(bases):
	write("")
	write("=" * 70)
	write("TEXTURE/RENDERER-DATA VTABLE SLOT TABLE")
	write("=" * 70)
	idx = 0
	while idx < len(bases):
		base = bases[idx]
		write("")
		write("vtable candidate @ 0x%08x (%s)" % (base, label_for(base)))
		slot_idx = 0
		while slot_idx < len(VTABLE_SLOTS):
			slot = VTABLE_SLOTS[slot_idx][0]
			desc = VTABLE_SLOTS[slot_idx][1]
			target = read_u32(base + slot)
			write("  +0x%03x @ 0x%08x -> 0x%08x %-48s ; %s" % (slot, base + slot, target if target is not None else 0, label_for(target), desc))
			slot_idx += 1
		idx += 1

def slot_selected(slot):
	idx = 0
	while idx < len(SELECTED_SLOTS):
		if SELECTED_SLOTS[idx] == slot:
			return True
		idx += 1
	return False

def collect_selected_slot_targets(bases):
	targets = []
	idx = 0
	while idx < len(bases):
		base = bases[idx]
		slot_idx = 0
		while slot_idx < len(VTABLE_SLOTS):
			slot = VTABLE_SLOTS[slot_idx][0]
			if slot_selected(slot):
				target = read_u32(base + slot)
				if is_probable_code_addr(target):
					append_unique(targets, target)
			slot_idx += 1
		idx += 1
	return targets

def audit_selected_slot_targets(bases):
	write("")
	write("=" * 70)
	write("SELECTED TEXTURE/RENDERER-DATA SLOT TARGET AUDIT")
	write("=" * 70)
	targets = collect_selected_slot_targets(bases)
	if len(targets) == 0:
		write("  [no selected slot targets]")
		return
	idx = 0
	while idx < len(targets):
		target = targets[idx]
		find_refs_to(target, "selected texture/renderer-data slot target %s" % label_for(target))
		disasm_window(target, 0, 120, "selected texture/renderer-data slot target %s" % label_for(target))
		decompile_at(target, "selected texture/renderer-data slot target %s" % label_for(target), 26000)
		find_and_print_calls_from(target, "selected texture/renderer-data slot target %s" % label_for(target))
		print_matching_decompile_lines(target, "selected texture/renderer-data slot target %s" % label_for(target))
		idx += 1
		if idx > 120:
			write("  ... selected slot target audit truncated")
			break

def audit_refs():
	idx = 0
	while idx < len(REF_TARGETS):
		find_refs_to(REF_TARGETS[idx], label_for(REF_TARGETS[idx]))
		idx += 1

def audit_raw_windows():
	idx = 0
	while idx < len(RAW_WINDOWS):
		item = RAW_WINDOWS[idx]
		disasm_window(item[0], item[1], item[2], item[3])
		idx += 1

def audit_focus_functions():
	idx = 0
	while idx < len(FOCUS_FUNCTIONS):
		item = FOCUS_FUNCTIONS[idx]
		decompile_at(item[0], item[1], item[2])
		find_and_print_calls_from(item[0], item[1])
		print_matching_decompile_lines(item[0], item[1])
		idx += 1

def audit_vtable_refs(bases):
	idx = 0
	while idx < len(bases):
		find_refs_to(bases[idx], "texture/renderer-data vtable candidate")
		idx += 1

def main():
	write("FNV PBR PPLIGHTING RESOLVER TEXTURE-DATA VTABLE FOLLOW-UP AUDIT")
	write("")
	write("Purpose:")
	write("1. Follow resolver slot +0x0C output below E90B10 into source +0x24 renderer-data.")
	write("2. Identify constructor/factory vtables for source-texture renderer data and returned wrappers.")
	write("3. Decompile slots +0x98/+0x9C/+0xA4/+0xA8/+0xAC/+0xB4 before assigning material-map semantics.")
	audit_refs()
	audit_raw_windows()
	audit_focus_functions()
	bases = collect_vtable_bases()
	print_vtable_slot_table(bases)
	audit_vtable_refs(bases)
	audit_selected_slot_targets(bases)

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_pplighting_resolver_texturedata_vtable_followup_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("")
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
