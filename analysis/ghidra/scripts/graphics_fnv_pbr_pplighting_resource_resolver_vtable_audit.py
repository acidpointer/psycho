# @category Analysis
# @description Audit FNV PPLighting resource resolver object behind renderer +0x8C4

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x00A63520: "class/name registration helper",
	0x00A98460: "renderer resource shutdown/helper called near NiPersistentSrcTextureRendererData",
	0x00AA10F0: "free array/helper",
	0x00AA1460: "free sized allocation/helper",
	0x00AA4060: "release/ref helper",
	0x00B71300: "texture/render resource setup helper",
	0x00E6E630: "renderer resource iterator helper",
	0x00E6E730: "persistent source texture renderer data helper A",
	0x00E6E7B0: "persistent source texture renderer data helper B",
	0x00E74D40: "texture/render resource setup helper",
	0x00E75A70: "renderer teardown/destructor-like function clearing +0x8C4",
	0x00E7DC90: "post-texture sampler helper called by E7EA00",
	0x00E7DF90: "renderer global matrix/helper using DAT_0126F6C4",
	0x00E7E8D0: "renderer global setter: DAT_0126F6C4/C0/C8",
	0x00E7EA00: "pass-entry downstream texture/state apply helper",
	0x00E7E940: "post-texture helper called by E7EA00",
	0x00E81940: "renderer setup: calls E7E8D0(renderer)",
	0x00E819F0: "renderer clear/shutdown: calls E7E8D0(0)",
	0x00E88A20: "NiDX9RenderState::SetTexture",
	0x00E88B00: "render-state vtable A destructor/reset",
	0x00E89060: "texture-stage-state tracker getter",
	0x010EDA24: "candidate renderer resource vtable",
	0x010EDA44: "candidate renderer resource vtable",
	0x010EDA64: "candidate renderer resource vtable",
	0x010EDA84: "candidate renderer resource vtable",
	0x010EDAA4: "candidate renderer resource vtable",
	0x010EDAC4: "candidate renderer resource vtable",
	0x010EDAE4: "candidate renderer resource vtable",
	0x010EDAEC: "candidate renderer resource vtable",
	0x010EDAF4: "candidate renderer resource vtable",
	0x010EDAFC: "candidate renderer resource vtable",
	0x010EDB1C: "candidate renderer resource vtable",
	0x010EDB3C: "candidate renderer resource vtable",
	0x010EDB5C: "candidate renderer resource vtable",
	0x010EDB7C: "candidate renderer resource vtable",
	0x010EDB9C: "candidate renderer resource vtable",
	0x010EE4BC: "renderer main vtable set by E75A70",
	0x010EF60C: "render-state vtable A",
	0x010F088C: "render-state vtable B",
	0x011BF558: "pass-entry bounded count used by E7EA00/E89410",
	0x0126F6C0: "renderer-global object from renderer +0x288",
	0x0126F6C4: "renderer global object used by E7EA00",
	0x0126F6C8: "renderer-global render-state object from renderer +0x8B8",
	0x0126F680: "pass-entry +8 cache table keyed by entry +4",
	0x0126F74C: "current NiD3DPass global",
	0x0126F99C: "render-state global used by E89250/E892D0",
}

FOCUS_FUNCTIONS = [
	(0x00E7EA00, "resource resolver callsite: E7EA00"),
	(0x00E7E8D0, "renderer global setter"),
	(0x00E81940, "renderer setup caller of E7E8D0"),
	(0x00E819F0, "renderer shutdown caller of E7E8D0"),
	(0x00E75A70, "renderer teardown/destructor-like function"),
	(0x00E6E630, "renderer resource iterator helper"),
	(0x00E6E730, "persistent source texture renderer data helper A"),
	(0x00E6E7B0, "persistent source texture renderer data helper B"),
	(0x00A63520, "class/name registration helper"),
	(0x00A98460, "renderer resource shutdown/helper"),
	(0x00B71300, "texture/render resource setup helper"),
	(0x00E74D40, "texture/render resource setup helper"),
	(0x00E7DC90, "post-texture sampler helper"),
	(0x00E7DF90, "renderer global DAT_0126F6C4 helper"),
	(0x00E7E940, "post-texture helper"),
	(0x00E88A20, "NiDX9RenderState::SetTexture"),
]

REF_TARGETS = [
	0x00E7EA00,
	0x00E7E8D0,
	0x00E81940,
	0x00E819F0,
	0x00E75A70,
	0x00E6E630,
	0x00E6E730,
	0x00E6E7B0,
	0x00A63520,
	0x00A98460,
	0x00B71300,
	0x00E74D40,
	0x00E7DC90,
	0x00E7DF90,
	0x00E7E940,
	0x00E88A20,
	0x010EDA24,
	0x010EDA44,
	0x010EDA64,
	0x010EDA84,
	0x010EDAA4,
	0x010EDAC4,
	0x010EDAE4,
	0x010EDAEC,
	0x010EDAF4,
	0x010EDAFC,
	0x010EDB1C,
	0x010EDB3C,
	0x010EDB5C,
	0x010EDB7C,
	0x010EDB9C,
	0x010EE4BC,
	0x0126F6C4,
	0x0126F6C8,
	0x0126F680,
	0x0126F99C,
]

DATA_WINDOWS = [
	0x010EDA24,
	0x010EDA44,
	0x010EDA64,
	0x010EDA84,
	0x010EDAA4,
	0x010EDAC4,
	0x010EDAE4,
	0x010EDAEC,
	0x010EDAF4,
	0x010EDAFC,
	0x010EDB1C,
	0x010EDB3C,
	0x010EDB5C,
	0x010EDB7C,
	0x010EDB9C,
	0x010EE4BC,
	0x0126F6C4,
	0x0126F6C8,
	0x0126F680,
	0x0126F99C,
]

RAW_WINDOWS = [
	(0x00E7EA00, 24, 120, "E7EA00 resolver callsite"),
	(0x00E7E8D0, 18, 120, "E7E8D0 renderer global setter"),
	(0x00E81940, 18, 90, "E81940 renderer setup"),
	(0x00E819F0, 18, 90, "E819F0 renderer shutdown"),
	(0x00E75A70, 20, 140, "E75A70 renderer teardown start"),
	(0x00E75F1D, 14, 32, "E75A70 +0x8C4 release/null sequence"),
	(0x00E76009, 12, 52, "NiPersistentSrcTextureRendererData teardown cluster"),
	(0x00E76099, 12, 64, "E75A70 resource helper teardown cluster"),
	(0x00E7DC90, 14, 80, "E7DC90 DAT_0126F6C4 helper"),
	(0x00E7DF90, 14, 100, "E7DF90 DAT_0126F6C4 helper"),
	(0x00E88A20, 14, 90, "SetTexture final bind"),
]

VTABLE_BASES = [
	(0x010EDA24, "candidate renderer resource vtable"),
	(0x010EDA44, "candidate renderer resource vtable"),
	(0x010EDA64, "candidate renderer resource vtable"),
	(0x010EDA84, "candidate renderer resource vtable"),
	(0x010EDAA4, "candidate renderer resource vtable"),
	(0x010EDAC4, "candidate renderer resource vtable"),
	(0x010EDAE4, "candidate renderer resource vtable"),
	(0x010EDAEC, "candidate renderer resource vtable"),
	(0x010EDAF4, "candidate renderer resource vtable"),
	(0x010EDAFC, "candidate renderer resource vtable"),
	(0x010EDB1C, "candidate renderer resource vtable"),
	(0x010EDB3C, "candidate renderer resource vtable"),
	(0x010EDB5C, "candidate renderer resource vtable"),
	(0x010EDB7C, "candidate renderer resource vtable"),
	(0x010EDB9C, "candidate renderer resource vtable"),
	(0x010EE4BC, "renderer main vtable"),
	(0x010EF60C, "render-state vtable A"),
	(0x010F088C, "render-state vtable B"),
]

VTABLE_SLOTS = [
	(0x00, "slot +0x00 destructor/release-like candidate"),
	(0x04, "slot +0x04 destructor/release-like candidate"),
	(0x08, "slot +0x08 helper candidate"),
	(0x0C, "slot +0x0C resolver candidate used by E7EA00 for renderer +0x8C4 object"),
	(0x10, "slot +0x10 helper candidate"),
	(0x14, "slot +0x14 helper candidate"),
	(0x18, "slot +0x18 helper candidate"),
	(0x1C, "slot +0x1C helper candidate"),
	(0x20, "slot +0x20 helper candidate"),
	(0x8C, "slot +0x8C observed in render-state helper cluster"),
	(0x9C, "slot +0x9C observed in render-state helper cluster"),
	(0xA0, "slot +0xA0 capability/count getter candidate"),
	(0xA4, "slot +0xA4 count getter candidate"),
	(0xA8, "slot +0xA8 flag getter candidate"),
	(0xB0, "slot +0xB0 resource getter candidate"),
	(0xB4, "slot +0xB4 resource getter candidate"),
	(0xC0, "render-state texture-stage setter candidate"),
	(0xCC, "render-state sampler setter candidate"),
	(0xDC, "render-state SetTexture candidate"),
]

SLOT_TARGET_DECOMPILE_SLOTS = [
	0x00,
	0x04,
	0x08,
	0x0C,
	0xA0,
	0xA4,
	0xA8,
	0xB0,
	0xB4,
]

MATCH_PATTERNS = [
	"0126f6c4",
	"0126f6c8",
	"0126f680",
	"0126f99c",
	"011bf558",
	"0x8c4",
	"+ 0x8c4",
	"+0x8c4",
	"0x8b8",
	"+ 0x8b8",
	"+0x8b8",
	"010eda",
	"010edb",
	"010ee4bc",
	"010ef60c",
	"010f088c",
	"nipersistentsrctexturerendererdata",
	"persistent",
	"texture",
	"resource",
	"render",
	"settexture",
	"sampler",
	"stage",
	"vtable",
	"0xa0",
	"+ 0xa0",
	"+0xa0",
	"0xb0",
	"+ 0xb0",
	"+0xb0",
]

OFFSET_PATTERNS = [
	"0x8c4",
	"+ 0x8c4",
	"+0x8c4",
]

def write(msg):
	output.append(msg)
	print(msg)

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

def read_dword(addr_int):
	try:
		return memory.getInt(toAddr(addr_int)) & 0xffffffff
	except:
		return None

def operand_text(inst, index):
	try:
		return inst.getDefaultOperandRepresentation(index)
	except:
		return "?"

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

def decompile_at(addr_int, label, max_len=18000):
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
		write("  %s @ 0x%08x (in %s) %s" % (ref_kind(ref), from_addr.getOffset(), fname, inst_text))
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
	write("-" * 70)
	write("Disassembly %s around 0x%08x" % (label, center_int))
	write("-" * 70)
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

def dump_data_window(addr_int, before_slots, after_slots):
	write("")
	write("=" * 70)
	write("DATA WINDOW AROUND 0x%08x (%s)" % (addr_int, label_for(addr_int)))
	write("=" * 70)
	start = addr_int - before_slots * 4
	idx = 0
	total = before_slots + after_slots + 1
	while idx < total:
		slot_addr = start + idx * 4
		value = read_dword(slot_addr)
		marker = " << target" if slot_addr == addr_int else ""
		if value is None:
			write("  0x%08x: ????????%s" % (slot_addr, marker))
		else:
			write("  0x%08x: 0x%08x %-48s%s" % (slot_addr, value, label_for(value), marker))
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

def list_contains_addr(items, addr_int):
	idx = 0
	while idx < len(items):
		if items[idx] == addr_int:
			return True
		idx += 1
	return False

def slot_is_selected(slot):
	idx = 0
	while idx < len(SLOT_TARGET_DECOMPILE_SLOTS):
		if SLOT_TARGET_DECOMPILE_SLOTS[idx] == slot:
			return True
		idx += 1
	return False

def text_has_offset_pattern(text):
	lower = text.lower()
	idx = 0
	while idx < len(OFFSET_PATTERNS):
		if lower.find(OFFSET_PATTERNS[idx]) >= 0:
			return True
		idx += 1
	return False

def scan_all_instructions_for_8c4():
	write("")
	write("=" * 70)
	write("GLOBAL INSTRUCTION SCAN FOR +0x8C4")
	write("=" * 70)
	inst_iter = listing.getInstructions(True)
	count = 0
	printed = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		text = inst.toString()
		if not text_has_offset_pattern(text):
			continue
		func = fm.getFunctionContaining(inst.getAddress())
		fname = func.getName() if func else "???"
		addr_int = inst.getAddress().getOffset()
		write("  HIT 0x%08x in %s: %s" % (addr_int, fname, text))
		write("    op0=%s op1=%s op2=%s" % (operand_text(inst, 0), operand_text(inst, 1), operand_text(inst, 2)))
		disasm_window(addr_int, 8, 12, "+0x8C4 hit")
		printed += 1
		count += 1
		if printed > 120:
			write("  ... scan truncated")
			break
	write("  Total printed +0x8C4 hits: %d" % printed)

def print_vtable_slots():
	write("")
	write("=" * 70)
	write("CANDIDATE VTABLE SLOT TABLE")
	write("=" * 70)
	idx = 0
	while idx < len(VTABLE_BASES):
		base = VTABLE_BASES[idx][0]
		name = VTABLE_BASES[idx][1]
		write("")
		write("%s @ 0x%08x" % (name, base))
		slot_idx = 0
		while slot_idx < len(VTABLE_SLOTS):
			slot = VTABLE_SLOTS[slot_idx][0]
			desc = VTABLE_SLOTS[slot_idx][1]
			target = read_dword(base + slot)
			write("  +0x%03x @ 0x%08x -> 0x%08x %-48s ; %s" % (slot, base + slot, target if target is not None else 0, label_for(target), desc))
			slot_idx += 1
		idx += 1

def collect_selected_vtable_targets():
	result = []
	idx = 0
	while idx < len(VTABLE_BASES):
		base = VTABLE_BASES[idx][0]
		slot_idx = 0
		while slot_idx < len(VTABLE_SLOTS):
			slot = VTABLE_SLOTS[slot_idx][0]
			if slot_is_selected(slot):
				target = read_dword(base + slot)
				if target is not None and target != 0 and not list_contains_addr(result, target):
					result.append(target)
			slot_idx += 1
		idx += 1
	return result

def audit_selected_vtable_targets():
	write("")
	write("=" * 70)
	write("SELECTED VTABLE TARGET DECOMPILES")
	write("=" * 70)
	targets = collect_selected_vtable_targets()
	idx = 0
	while idx < len(targets):
		target = targets[idx]
		decompile_at(target, "selected vtable target %s" % label_for(target), 14000)
		find_and_print_calls_from(target, "selected vtable target %s" % label_for(target))
		print_matching_decompile_lines(target, "selected vtable target %s" % label_for(target))
		idx += 1
		if idx > 80:
			write("  ... selected vtable target audit truncated")
			break

def audit_refs():
	idx = 0
	while idx < len(REF_TARGETS):
		find_refs_to(REF_TARGETS[idx], label_for(REF_TARGETS[idx]))
		idx += 1

def audit_data_windows():
	idx = 0
	while idx < len(DATA_WINDOWS):
		dump_data_window(DATA_WINDOWS[idx], 4, 28)
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
		max_len = 22000
		if addr == 0x00E75A70:
			max_len = 70000
		if addr == 0x00E7DF90:
			max_len = 52000
		decompile_at(addr, label, max_len)
		find_and_print_calls_from(addr, label)
		print_matching_decompile_lines(addr, label)
		idx += 1

def main():
	write("FNV PBR PPLIGHTING RESOURCE RESOLVER VTABLE AUDIT")
	write("")
	write("Purpose:")
	write("1. Identify the object stored at renderer +0x8C4 that E7EA00 uses as a resource resolver.")
	write("2. Resolve candidate vtable slot +0x0C targets and decompile the selected slot methods.")
	write("3. Prove whether entry +8 resources become textures, render targets, persistent source textures, or non-material resources before visible PBR replacement.")
	audit_refs()
	scan_all_instructions_for_8c4()
	print_vtable_slots()
	audit_selected_vtable_targets()
	audit_data_windows()
	audit_raw_windows()
	audit_focus_functions()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_pplighting_resource_resolver_vtable_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("")
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
