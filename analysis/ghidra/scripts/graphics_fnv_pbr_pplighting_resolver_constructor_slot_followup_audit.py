# @category Analysis
# @description Follow FNV PPLighting renderer +0x8C4 resolver constructor and vtable slots

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
	0x00A4D5F0: "unresolved adjacent vtable target candidate from prior broad scan",
	0x00A63840: "unresolved adjacent vtable target candidate from prior broad scan",
	0x00AA13E0: "allocation helper used for resolver object",
	0x00AA1460: "free sized allocation/helper",
	0x00E69640: "renderer main vtable +0xE0 wrapper: calls resolver slot +0x10",
	0x00E72E50: "unresolved adjacent target candidate from prior broad scan",
	0x00E72E60: "renderer D3D setup/device init; writes renderer +0x8C4",
	0x00E75A70: "renderer teardown/destructor-like function clearing +0x8C4",
	0x00E7EA00: "pass-entry downstream texture/state apply helper",
	0x00E88A20: "NiDX9RenderState::SetTexture",
	0x00E88EB0: "renderer helper called after +0x8C4 setup",
	0x00E8B490: "unresolved adjacent vtable target candidate from prior broad scan",
	0x00E90A80: "constructor for 0x10-byte resolver object stored at renderer +0x8C4",
	0x00E92590: "unresolved adjacent vtable target candidate from prior broad scan",
	0x010EDA24: "persistent source texture renderer-data adjacent vtable candidate",
	0x010EDA44: "persistent source texture renderer-data adjacent vtable candidate",
	0x010EDA64: "persistent source texture renderer-data adjacent vtable candidate",
	0x010EDA84: "persistent source texture renderer-data adjacent vtable candidate",
	0x010EDAA4: "persistent source texture renderer-data adjacent vtable candidate",
	0x010EDAC4: "persistent source texture renderer-data adjacent vtable candidate",
	0x010EDAE4: "persistent source texture renderer-data adjacent vtable candidate",
	0x010EE4BC: "renderer main vtable",
	0x0126F6C4: "renderer global object used by E7EA00",
	0x0126F6C8: "renderer-global render-state object from renderer +0x8B8",
}

FOCUS_FUNCTIONS = [
	(0x00E72E60, "renderer D3D setup/device init"),
	(0x00E90A80, "resolver object constructor"),
	(0x00E88EB0, "post-resolver renderer helper"),
	(0x00E69640, "renderer vtable +0xE0 -> resolver slot +0x10 wrapper"),
	(0x00E7EA00, "pass-entry apply -> resolver slot +0x0C callsite"),
	(0x00E75A70, "renderer teardown -> resolver slot +0x00 callsite"),
	(0x00AA13E0, "allocation helper"),
	(0x00E8B490, "prior unresolved candidate"),
	(0x00A4D5F0, "prior unresolved candidate"),
	(0x00E92590, "prior unresolved candidate"),
	(0x00A63840, "prior unresolved candidate"),
	(0x00E72E50, "prior unresolved candidate"),
]

REF_TARGETS = [
	0x00E72E60,
	0x00E90A80,
	0x00E88EB0,
	0x00E69640,
	0x00E7EA00,
	0x00E75A70,
	0x00AA13E0,
	0x010EE4BC,
	0x0126F6C4,
	0x0126F6C8,
]

RAW_WINDOWS = [
	(0x00E734E8, 0, 36, "E72E60 allocation path before resolver constructor"),
	(0x00E73502, 12, 36, "E72E60 resolver constructor call and +0x8C4 write"),
	(0x00E7351F, 16, 28, "E72E60 post-resolver helper call"),
	(0x00E69640, 8, 18, "renderer vtable +0xE0 wrapper into resolver slot +0x10"),
	(0x00E7EA66, 8, 32, "E7EA00 resolver slot +0x0C call"),
	(0x00E75F1D, 10, 28, "E75A70 resolver slot +0x00 destroy/null"),
	(0x00E90A80, 0, 90, "resolver constructor raw body"),
	(0x00E88EB0, 0, 90, "post-resolver helper raw body"),
]

RESOLVER_SLOTS = [
	(0x00, "destructor/release slot used by E75A70"),
	(0x04, "secondary destructor/release candidate"),
	(0x08, "small resolver helper candidate"),
	(0x0C, "resource resolver slot used by E7EA00"),
	(0x10, "renderer public wrapper target used by E69640"),
	(0x14, "extra slot candidate"),
	(0x18, "extra slot candidate"),
	(0x1C, "extra slot candidate"),
]

SLOT_TARGET_DECOMPILE_SLOTS = [
	0x00,
	0x0C,
	0x10,
]

MATCH_PATTERNS = [
	"0126f6c4",
	"0126f6c8",
	"0x8c4",
	"+ 0x8c4",
	"+0x8c4",
	"0x8b8",
	"+ 0x8b8",
	"+0x8b8",
	"00aa13e0",
	"00e90a80",
	"00e88eb0",
	"texture",
	"resource",
	"renderer",
	"settexture",
	"vtable",
	"param_1",
	"param_2",
	"param_3",
	"param_4",
	"local_",
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
		func = createFunction(addr, "pbr_resolver_followup_%08x" % addr_int)
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

def scan_constructor_for_vtables():
	write("")
	write("=" * 70)
	write("E90A80 CONSTRUCTOR WRITE/IMMEDIATE SCAN")
	write("=" * 70)
	candidates = []
	func = ensure_function_at(0x00E90A80, "resolver constructor")
	if func is None:
		write("  [constructor function not found]")
		return candidates
	inst_iter = listing.getInstructions(func.getBody(), True)
	while inst_iter.hasNext():
		inst = inst_iter.next()
		text = inst.toString()
		lower = text.lower()
		op0 = operand_text(inst, 0)
		op1 = operand_text(inst, 1)
		scalar1 = operand_scalar_int(inst, 1)
		if lower.find("mov") == 0 and (op0.lower().find("[ecx") >= 0 or op0.lower().find("[eax") >= 0 or op0.lower().find("[esi") >= 0):
			write("  WRITE 0x%08x: %-58s op0=%s op1=%s" % (inst.getAddress().getOffset(), text, op0, op1))
		if is_probable_vtable_base(scalar1):
			append_unique(candidates, scalar1)
			write("  VTABLE-SCALAR 0x%08x: %s -> 0x%08x %s" % (inst.getAddress().getOffset(), text, scalar1, label_for(scalar1)))
		values = parse_hex_constants(text)
		idx = 0
		while idx < len(values):
			value = values[idx]
			if is_probable_vtable_base(value):
				append_unique(candidates, value)
				write("  VTABLE-HEX    0x%08x: %s -> 0x%08x %s" % (inst.getAddress().getOffset(), text, value, label_for(value)))
			idx += 1
	if len(candidates) == 0:
		write("  No probable vtable immediate found. Inspect the constructor raw body above for indirect initialization.")
	else:
		write("  Total probable constructor vtable bases: %d" % len(candidates))
	return candidates

def print_vtable_slot_table(bases):
	write("")
	write("=" * 70)
	write("RESOLVER CONSTRUCTOR VTABLE SLOT TABLE")
	write("=" * 70)
	if len(bases) == 0:
		write("  [no constructor-derived vtable bases]")
		return
	idx = 0
	while idx < len(bases):
		base = bases[idx]
		write("")
		write("vtable candidate @ 0x%08x (%s)" % (base, label_for(base)))
		slot_idx = 0
		while slot_idx < len(RESOLVER_SLOTS):
			slot = RESOLVER_SLOTS[slot_idx][0]
			desc = RESOLVER_SLOTS[slot_idx][1]
			target = read_u32(base + slot)
			write("  +0x%03x @ 0x%08x -> 0x%08x %-48s ; %s" % (slot, base + slot, target if target is not None else 0, label_for(target), desc))
			slot_idx += 1
		idx += 1

def slot_selected(slot):
	idx = 0
	while idx < len(SLOT_TARGET_DECOMPILE_SLOTS):
		if SLOT_TARGET_DECOMPILE_SLOTS[idx] == slot:
			return True
		idx += 1
	return False

def collect_slot_targets(bases):
	targets = []
	idx = 0
	while idx < len(bases):
		base = bases[idx]
		slot_idx = 0
		while slot_idx < len(RESOLVER_SLOTS):
			slot = RESOLVER_SLOTS[slot_idx][0]
			if slot_selected(slot):
				target = read_u32(base + slot)
				if is_probable_code_addr(target):
					append_unique(targets, target)
			slot_idx += 1
		idx += 1
	return targets

def audit_slot_targets(bases):
	write("")
	write("=" * 70)
	write("SELECTED RESOLVER SLOT TARGET AUDIT")
	write("=" * 70)
	targets = collect_slot_targets(bases)
	if len(targets) == 0:
		write("  [no selected slot targets]")
		return
	idx = 0
	while idx < len(targets):
		target = targets[idx]
		find_refs_to(target, "resolver slot target %s" % label_for(target))
		disasm_window(target, 0, 120, "resolver slot target %s" % label_for(target))
		decompile_at(target, "resolver slot target %s" % label_for(target), 30000)
		find_and_print_calls_from(target, "resolver slot target %s" % label_for(target))
		print_matching_decompile_lines(target, "resolver slot target %s" % label_for(target))
		idx += 1

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
		addr = FOCUS_FUNCTIONS[idx][0]
		label = FOCUS_FUNCTIONS[idx][1]
		max_len = 24000
		if addr == 0x00E72E60:
			max_len = 80000
		if addr == 0x00E75A70:
			max_len = 70000
		decompile_at(addr, label, max_len)
		find_and_print_calls_from(addr, label)
		print_matching_decompile_lines(addr, label)
		idx += 1

def audit_vtable_refs(bases):
	idx = 0
	while idx < len(bases):
		find_refs_to(bases[idx], "constructor-derived resolver vtable candidate")
		idx += 1

def main():
	write("FNV PBR PPLIGHTING RESOLVER CONSTRUCTOR/SLOT FOLLOW-UP AUDIT")
	write("")
	write("Purpose:")
	write("1. Prove the real object stored at renderer +0x8C4 by forcing/decompiling E90A80.")
	write("2. Recover the constructor-written vtable and dump slots +0x00, +0x0C, and +0x10.")
	write("3. Decompile selected resolver slot targets before assigning PBR material-map semantics.")
	audit_refs()
	audit_raw_windows()
	audit_focus_functions()
	bases = scan_constructor_for_vtables()
	print_vtable_slot_table(bases)
	audit_vtable_refs(bases)
	audit_slot_targets(bases)

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_pplighting_resolver_constructor_slot_followup_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("")
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
