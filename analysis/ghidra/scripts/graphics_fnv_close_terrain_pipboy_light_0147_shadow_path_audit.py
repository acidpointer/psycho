# @category Analysis
# @description Trace PipBoyLight form 0x147 from player toggle/equip paths into ShadowSceneLight classification

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.lang import OperandType
from ghidra.program.model.scalar import Scalar

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

OUTPATH = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_close_terrain_pipboy_light_0147_shadow_path_audit.txt"

TARGETS = [
	(0x00483A00, "runtime GetFormByID"),
	(0x009673D0, "player Pip-Boy light input/toggle dispatcher"),
	(0x00822B90, "Pip-Boy light state query candidate"),
	(0x00824400, "Pip-Boy toggle ExtraData mutation candidate"),
	(0x0093CCD0, "player singleton getter candidate"),
	(0x00881D30, "actor process/3D refresh with shadow candidate publication"),
	(0x00B5C450, "shadow classification setter caller A"),
	(0x00B5CBD0, "shadow candidate find/create"),
	(0x00B5CD00, "shadow classification setter caller B"),
	(0x00B5AF30, "shadow candidate source association"),
	(0x00B9DCB0, "ShadowSceneLight shadow-casting setter"),
	(0x00B9DDA0, "ShadowSceneLight NiLight association/type classifier"),
	(0x00B9E970, "ShadowSceneLight runtime update/fade"),
	(0x00B70390, "PPLighting light-list sorter"),
	(0x00B70590, "first active general light iterator"),
	(0x00B70600, "first active non-shadow light iterator"),
	(0x00B70680, "next active general light iterator"),
	(0x00B70700, "next active non-shadow light iterator"),
	(0x00BDF3E0, "vanilla close-land light pass builder"),
]

WINDOW_SITES = [
	(0x009674FB, "Pip-Boy state query call"),
	(0x00967572, "Pip-Boy-on player getter/vcall setup"),
	(0x009675A3, "Pip-Boy-off ExtraData mutation"),
	(0x00882A5A, "actor refresh shadow candidate create call"),
	(0x00B5C47F, "shadow setter call A"),
	(0x00B5CC84, "shadow candidate create sets shadow-casting"),
	(0x00B5CD70, "shadow setter call B"),
]

def write(msg):
	output.append(msg)
	print(msg)

def checkpoint_output():
	fout = open(OUTPATH, "w")
	fout.write("\n".join(output))
	fout.close()

def function_at_or_containing(addr_int):
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

def print_disassembly_window(addr_int, label, before_count=24, after_count=12):
	center = listing.getInstructionAt(toAddr(addr_int))
	write("")
	write("=" * 70)
	write("DISASSEMBLY WINDOW: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	if center is None:
		write("  [instruction not found]")
		return
	items = [center]
	inst = center
	count = 0
	while count < before_count:
		inst = listing.getInstructionBefore(inst.getAddress())
		if inst is None:
			break
		items.insert(0, inst)
		count += 1
	inst = center
	count = 0
	while count < after_count:
		inst = listing.getInstructionAfter(inst.getAddress())
		if inst is None:
			break
		items.append(inst)
		count += 1
	index = 0
	while index < len(items):
		item = items[index]
		marker = "=>" if item.getAddress() == center.getAddress() else "  "
		write("%s 0x%08x: %-64s" % (marker, item.getAddress().getOffset(), item.toString()))
		refs = item.getReferencesFrom()
		for ref in refs:
			target = ref.getToAddress()
			target_func = fm.getFunctionAt(target)
			name = target_func.getName() if target_func else "???"
			write("      %s -> 0x%08x %s" % (ref.getReferenceType(), target.getOffset(), name))
		index += 1

def instruction_has_scalar(inst, wanted):
	operand_index = 0
	while operand_index < inst.getNumOperands():
		if not OperandType.isScalar(inst.getOperandType(operand_index)):
			operand_index += 1
			continue
		objects = inst.getOpObjects(operand_index)
		object_index = 0
		while object_index < len(objects):
			obj = objects[object_index]
			if isinstance(obj, Scalar) and obj.getUnsignedValue() == wanted:
				return True
			object_index += 1
		operand_index += 1
	return False

def scan_pipboy_form_id():
	write("")
	write("=" * 70)
	write("PIPBOYLIGHT BASE FORM ID 0x00000147 SCALAR USES")
	write("=" * 70)
	hits = []
	seen_functions = {}
	inst_iter = listing.getInstructions(True)
	while inst_iter.hasNext():
		inst = inst_iter.next()
		if not instruction_has_scalar(inst, 0x147):
			continue
		func = fm.getFunctionContaining(inst.getAddress())
		fname = func.getName() if func else "???"
		entry = func.getEntryPoint().getOffset() if func else 0
		hits.append((inst.getAddress().getOffset(), fname, inst.toString()))
		if func is not None:
			seen_functions[entry] = func
	write("Instruction hits: %d" % len(hits))
	index = 0
	while index < len(hits):
		item = hits[index]
		write("  0x%08x in %-24s %s" % (item[0], item[1], item[2]))
		index += 1
	entries = seen_functions.keys()
	entries.sort()
	write("Unique containing functions: %d" % len(entries))
	index = 0
	while index < len(entries):
		entry = entries[index]
		func = seen_functions[entry]
		decompile_at(entry, "PipBoyLight 0x147 scalar user %s" % func.getName(), 32000)
		find_and_print_calls_from(entry, "PipBoyLight 0x147 scalar user %s" % func.getName())
		checkpoint_output()
		index += 1

def audit_targets():
	index = 0
	while index < len(TARGETS):
		item = TARGETS[index]
		find_refs_to(item[0], item[1])
		decompile_at(item[0], item[1], 40000)
		find_and_print_calls_from(item[0], item[1])
		checkpoint_output()
		index += 1

def audit_windows():
	index = 0
	while index < len(WINDOW_SITES):
		item = WINDOW_SITES[index]
		print_disassembly_window(item[0], item[1])
		checkpoint_output()
		index += 1

def main():
	write("FNV CLOSE-TERRAIN PIPBOYLIGHT 0x147 SHADOW PATH AUDIT")
	write("")
	write("Grounded identity: xNVSE maps base form 0x00000147 to PipBoyLight.")
	write("Questions:")
	write("1. Where does the player toggle/equip path resolve or mutate PipBoyLight 0x147?")
	write("2. Does the player actor refresh publish its attached light through shadow candidate creation?")
	write("3. Which callers pass 0 or 1 to ShadowSceneLight +0xEC?")
	write("4. Can close terrain safely use general active lights without changing shadow ownership?")
	scan_pipboy_form_id()
	audit_targets()
	audit_windows()
	checkpoint_output()
	write("")
	write("OUTPUT COMPLETE: %s (%d lines)" % (OUTPATH, len(output)))

try:
	main()
finally:
	checkpoint_output()
	decomp.dispose()
