# @category Analysis
# @description Deep audit FNV PPLighting B-range constructors and +0xDC ownership

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
	0x00439410: "Land/render object store candidate for B66F50 result",
	0x004B6360: "Caller of B668B0/B675C0 +0xDC setter path",
	0x00539960: "TESLand path constructing 0x104 shader object via B66F50",
	0x00B4E150: "+0xDC writer candidate class ctor",
	0x00B4E1E0: "+0xDC release/update candidate",
	0x00B5AAC0: "+0xDC writer candidate class ctor",
	0x00B5E0F0: "+0xDC refcounted writer candidate class ctor",
	0x00B5E5A0: "+0xDC release/reset candidate",
	0x00B54B60: "Texture/runtime object helper used after B66F50",
	0x00B57E30: "Texture/runtime object release helper candidate",
	0x00B660D0: "Shader-property init/copy helper candidate",
	0x00B66640: "B66F50 texture/flag setup helper candidate",
	0x00B666D0: "PPLighting-like vtable method 04 candidate",
	0x00B668B0: "Shader object accessor/allocation helper candidate",
	0x00B66AD0: "Shader object setup helper candidate",
	0x00B66B80: "PPLighting-like vtable method 09 candidate",
	0x00B66C40: "PPLighting-like vtable method 10 candidate",
	0x00B66F50: "0x104 shader object constructor candidate",
	0x00B671E0: "PPLighting-like vtable method 00 candidate",
	0x00B671F0: "PPLighting-like vtable method 01 candidate",
	0x00B67200: "PPLighting-like vtable method 02 candidate",
	0x00B67260: "PPLighting-like vtable method 03 candidate",
	0x00B67290: "PPLighting-like vtable method 05 candidate",
	0x00B672E0: "PPLighting-like vtable method 06 candidate",
	0x00B67330: "PPLighting-like vtable method 07 candidate",
	0x00B67380: "+0xDC destructor/release candidate",
	0x00B675C0: "+0xDC setter candidate",
	0x00B676A0: "+0xDC copy/assign candidate",
	0x00B68660: "Texture slot setter on B66F50 object candidate",
	0x00B68B10: "PPLighting-like vtable method 08 candidate",
	0x00B690D0: "+0xDC reader fanout candidate",
	0x00B6A6C0: "+0xDC flat copy candidate",
	0x00B9DDA0: "Runtime object attach helper after B9FDA0",
	0x00B9FDA0: "+0xDC candidate object copy/init",
	0x00BC3E40: "Additional caller of BD9D00 pass builder",
	0x00BDB4A0: "PPLighting setup geometry variant",
	0x00BD9D00: "PPLighting +0xDC pass builder",
	0x00BD9F90: "PPLighting +0xDC +0x6C pass builder",
	0x00BDC030: "PPLighting +0xDC late pass builder",
	0x00BDF790: "PPLighting setup geometry",
	0x010A8F90: "Vtable/data immediate from B4E150",
	0x010ADCF8: "Vtable/data immediate from B5E0F0",
	0x010AE1B8: "PPLighting-like vtable start 0",
	0x010AE1E4: "PPLighting-like setup variant slot 0",
	0x010AE1E8: "PPLighting-like setup slot 0",
	0x010B8418: "SpeedTreeBillboardShaderProperty vtable start",
	0x010B8444: "SpeedTreeBillboardShaderProperty setup variant slot",
	0x010B8448: "SpeedTreeBillboardShaderProperty setup slot",
	0x010B9420: "SpeedTreeBranchShaderProperty vtable start",
	0x010B944C: "SpeedTreeBranchShaderProperty setup variant slot",
	0x010B9450: "SpeedTreeBranchShaderProperty setup slot",
	0x010B9578: "SpeedTree shader-property vtable start",
	0x010B95A4: "SpeedTree shader-property setup variant slot",
	0x010B95A8: "SpeedTree shader-property setup slot",
	0x010B99F8: "DistantTree shader-property vtable start",
	0x010B9A24: "DistantTree shader-property setup variant slot",
	0x010B9A28: "DistantTree shader-property setup slot",
	0x010BACE0: "Light/beam-adjacent shader-property vtable start",
	0x010BAD0C: "Light/beam-adjacent shader-property setup variant slot",
	0x010BAD10: "Light/beam-adjacent shader-property setup slot",
	0x010BCC48: "BeamShaderProperty vtable start",
	0x010BCC74: "BeamShaderProperty setup variant slot",
	0x010BCC78: "BeamShaderProperty setup slot",
}

DATA_WINDOWS = [
	0x010A8F90,
	0x010ADCF8,
	0x010AE1B8,
	0x010B8418,
	0x010B9420,
	0x010B9578,
	0x010B99F8,
	0x010BACE0,
	0x010BCC48,
]

FUNCTION_TARGETS = [
	0x00539960,
	0x004B6360,
	0x00439410,
	0x00B66F50,
	0x00B66640,
	0x00B668B0,
	0x00B66AD0,
	0x00B68660,
	0x00B54B60,
	0x00B57E30,
	0x00B671E0,
	0x00B671F0,
	0x00B67200,
	0x00B67260,
	0x00B666D0,
	0x00B67290,
	0x00B672E0,
	0x00B67330,
	0x00B68B10,
	0x00B66B80,
	0x00B66C40,
	0x00B67380,
	0x00B675C0,
	0x00B676A0,
	0x00B690D0,
	0x00B6A6C0,
	0x00B5AAC0,
	0x00B5E0F0,
	0x00B5E5A0,
	0x00B4E150,
	0x00B4E1E0,
	0x00BC3E40,
	0x00BDB4A0,
	0x00BDF790,
	0x00BD9D00,
	0x00BD9F90,
	0x00BDC030,
	0x00B9FDA0,
	0x00B9DDA0,
]

REF_TARGETS = [
	0x00B66F50,
	0x00B66640,
	0x00B668B0,
	0x00B66AD0,
	0x00B68660,
	0x00B675C0,
	0x00B676A0,
	0x00B67380,
	0x00BDB4A0,
	0x00BDF790,
	0x00BD9D00,
	0x00BD9F90,
	0x00BDC030,
	0x010AE1B8,
	0x010B8418,
	0x010B9420,
	0x010B9578,
	0x010B99F8,
	0x010BACE0,
	0x010BCC48,
]

MATCH_PATTERNS = [
	"+ 0xdc",
	"+0xdc",
	"param_1[0x37]",
	"+ 0x6c",
	"+0x6c",
	"0x104",
	"0x010",
	"010a",
	"010b",
	"00b66f50",
	"00b66640",
	"00b68660",
	"00b675c0",
	"00b676a0",
	"00b67380",
	"00bdb4a0",
	"00bdf790",
	"00bd9d00",
	"00bd9f90",
	"00bdc030",
	"texture",
	"slot",
	"vtable",
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

def read_dword(addr_int):
	try:
		return memory.getInt(toAddr(addr_int)) & 0xffffffff
	except:
		return None

def decompile_at(addr_int, label, max_len=42000):
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
		inst = listing.getInstructionContaining(ref.getFromAddress())
		inst_text = inst.toString() if inst is not None else ""
		write("  %s @ 0x%08x (in %s) %s" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname, inst_text))
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
				name = tgt_func.getName() if tgt_func else label_for(tgt)
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, name))
				count += 1
	write("  Total: %d calls" % count)

def text_has_pattern(line):
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
		if text_has_pattern(line):
			write("  L%04d: %s" % (idx + 1, line))
			count += 1
		idx += 1
	write("  Total matched lines: %d" % count)

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
		write("  0x%08x: %-56s%s%s" % (addr_int, inst.toString(), marker, extra))
		inst = inst.getNext()
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
			write("  0x%08x: 0x%08x %s%s" % (slot_addr, value, label_for(value), marker))
		idx += 1

def extract_data_immediates(text):
	values = []
	tokens = re.findall("0x[0-9a-fA-F]+", text)
	idx = 0
	while idx < len(tokens):
		try:
			value = int(tokens[idx][2:], 16)
			if value >= 0x01000000 and value <= 0x01100000:
				values.append(value)
		except:
			pass
		idx += 1
	return values

def scan_function_immediates(addr_int, label):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	write("")
	write("=" * 70)
	write("DATA/VPTABLE IMMEDIATES IN %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	seen = {}
	while inst_iter.hasNext():
		inst = inst_iter.next()
		text = inst.toString()
		values = extract_data_immediates(text)
		if len(values) == 0:
			continue
		write("  0x%08x: %s" % (inst.getAddress().getOffset(), text))
		idx = 0
		while idx < len(values):
			value = values[idx]
			seen[value] = True
			write("    immediate 0x%08x %s" % (value, label_for(value)))
			idx += 1
		count += 1
		if count > 80:
			write("  ... immediate scan truncated")
			break
	keys = seen.keys()
	keys.sort()
	idx = 0
	while idx < len(keys):
		dump_data_window(keys[idx], 8, 20)
		idx += 1
	write("  Total instructions with data/vtable immediates: %d" % count)

def scan_function_markers(addr_int, label):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	write("")
	write("=" * 70)
	write("INSTRUCTION MARKERS IN %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		text = inst.toString().lower()
		if text.find("+ 0xdc") >= 0 or text.find("+0xdc") >= 0 or text.find("00b66f50") >= 0 or text.find("00b68660") >= 0 or text.find("00b675c0") >= 0 or text.find("0x010") >= 0:
			write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
			disasm_window(inst.getAddress().getOffset(), 8, 14, "marker")
			count += 1
			if count > 80:
				write("  ... marker scan truncated")
				break
	write("  Total marker instructions: %d" % count)

def audit_data_windows():
	idx = 0
	while idx < len(DATA_WINDOWS):
		dump_data_window(DATA_WINDOWS[idx], 12, 28)
		idx += 1

def audit_refs():
	idx = 0
	while idx < len(REF_TARGETS):
		addr = REF_TARGETS[idx]
		find_refs_to(addr, label_for(addr))
		idx += 1

def audit_functions():
	idx = 0
	while idx < len(FUNCTION_TARGETS):
		addr = FUNCTION_TARGETS[idx]
		label = label_for(addr)
		decompile_at(addr, label)
		find_and_print_calls_from(addr, label)
		print_matching_decompile_lines(addr, label)
		scan_function_immediates(addr, label)
		scan_function_markers(addr, label)
		idx += 1

def print_header():
	write("FNV PPLIGHTING B-RANGE CONSTRUCTOR +0xDC DEEP AUDIT")
	write("")
	write("Questions:")
	write("1. Does FUN_00B66F50 construct the object whose vtable contains BDB4A0/BDF790?")
	write("2. Which vtable immediate does FUN_00B66F50 assign, if any?")
	write("3. Are +0xDC setter/copy/destructor helpers near B66F50 part of the same object type?")
	write("4. Do texture slot setters B66640/B68660 connect source texture slots to draw-time PPLighting stages?")
	write("5. What is the role of the extra BD9D00 caller FUN_00BC3E40?")

def main():
	print_header()
	audit_data_windows()
	audit_refs()
	audit_functions()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pplighting_brange_constructor_dc_deep_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("")
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
