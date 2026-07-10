# @category Analysis
# @description Trace direct GameHeap Default-slot virtual dispatches

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

GAME_HEAP_BASE = 0x011F6238
DEFAULT_SLOT = GAME_HEAP_BASE + 0x110
DEFAULT_SLOT_HEX = "%08X" % DEFAULT_SLOT
GAME_HEAP_BASE_HEX = "%08X" % GAME_HEAP_BASE
TRACKED_REGISTERS = ["EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP"]

def write(msg):
	output.append(msg)
	print(msg)

def func_at_or_containing(addr_int):
	addr = toAddr(addr_int)
	func = fm.getFunctionAt(addr)
	if func is None:
		func = fm.getFunctionContaining(addr)
	return func

def func_name(func):
	if func is None:
		return "???"
	return "%s @ 0x%08x" % (func.getName(), func.getEntryPoint().getOffset())

def decompile_at(addr_int, label, max_len=22000):
	func = func_at_or_containing(addr_int)
	write("")
	write("=" * 70)
	write("%s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	if func is None:
		write("  [function not found]")
		return
	write("  Function: %s @ 0x%08x, Size: %d bytes" % (func.getName(), func.getEntryPoint().getOffset(), func.getBody().getNumAddresses()))
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		write(code[:max_len])
		if len(code) > max_len:
			write("  [decompile truncated at %d chars]" % max_len)
	else:
		write("  [decompilation failed]")

def find_refs_to(addr_int, label, limit=200):
	write("")
	write("-" * 70)
	write("References TO 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		write("  %s @ 0x%08x (in %s)" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), func_name(from_func)))
		count += 1
		if count >= limit:
			write("  ... (truncated at %d)" % limit)
			break
	write("  Total printed: %d" % count)

def find_and_print_calls_from(addr_int, label, limit=240):
	func = func_at_or_containing(addr_int)
	write("")
	write("-" * 70)
	write("Calls FROM %s (0x%08x)" % (label, addr_int))
	write("-" * 70)
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
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, func_name(func_at_or_containing(tgt))))
				count += 1
				if count >= limit:
					write("  ... (truncated at %d)" % limit)
					write("  Total printed: %d" % count)
					return
	write("  Total printed: %d" % count)

def functions_referencing(addr_int):
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	seen = {}
	functions = []
	while refs.hasNext():
		ref = refs.next()
		func = fm.getFunctionContaining(ref.getFromAddress())
		if func is None:
			continue
		entry = func.getEntryPoint().getOffset()
		if seen.has_key(entry):
			continue
		seen[entry] = True
		functions.append(func)
	return functions

def upper_operand(inst, index):
	return inst.getDefaultOperandRepresentation(index).upper().replace(" ", "")

def operand_register(text):
	idx = 0
	while idx < len(TRACKED_REGISTERS):
		reg = TRACKED_REGISTERS[idx]
		if text == reg:
			return reg
		idx += 1
	return None

def memory_uses_tag(text, register, offset):
	if text.find("[") < 0 or text.find("]") < 0 or text.find(register) < 0:
		return False
	if offset is None:
		return text.find("+") < 0 and text.find("-") < 0
	return text.find("+" + offset) >= 0

def trace_function(func):
	tags = {}
	idx = 0
	while idx < len(TRACKED_REGISTERS):
		tags[TRACKED_REGISTERS[idx]] = None
		idx += 1
	loads = []
	paths = []
	inst_iter = listing.getInstructions(func.getBody(), True)
	while inst_iter.hasNext():
		inst = inst_iter.next()
		mnemonic = inst.getMnemonicString().upper()
		count = inst.getNumOperands()
		dest = None
		src = ""
		if count > 0:
			dest = operand_register(upper_operand(inst, 0))
		if count > 1:
			src = upper_operand(inst, 1)
		if (mnemonic == "MOV" or mnemonic == "LEA") and dest is not None:
			if src.find(DEFAULT_SLOT_HEX) >= 0 and mnemonic == "MOV":
				tags[dest] = "default_heap"
				loads.append((inst.getAddress().getOffset(), inst.toString()))
			elif src.find(GAME_HEAP_BASE_HEX) >= 0:
				tags[dest] = "game_heap"
			elif operand_register(src) is not None:
				tags[dest] = tags[operand_register(src)]
			else:
				matched = False
				reg_idx = 0
				while reg_idx < len(TRACKED_REGISTERS):
					base = TRACKED_REGISTERS[reg_idx]
					if tags[base] == "game_heap" and memory_uses_tag(src, base, "0X110"):
						tags[dest] = "default_heap"
						loads.append((inst.getAddress().getOffset(), inst.toString()))
						matched = True
						break
					if tags[base] == "default_heap" and memory_uses_tag(src, base, None):
						tags[dest] = "default_vtable"
						matched = True
						break
					reg_idx += 1
				if not matched:
					tags[dest] = None
		elif mnemonic == "CALL":
			call_text = upper_operand(inst, 0)
			reg_idx = 0
			while reg_idx < len(TRACKED_REGISTERS):
				base = TRACKED_REGISTERS[reg_idx]
				if tags[base] == "default_vtable" and (memory_uses_tag(call_text, base, "0X8") or memory_uses_tag(call_text, base, "0XC")):
					paths.append((inst.getAddress().getOffset(), inst.toString()))
					break
				reg_idx += 1
		elif dest is not None and mnemonic != "CMP" and mnemonic != "TEST":
			tags[dest] = None
	return (loads, paths)

def audit_direct_default_slot_dispatches():
	write("")
	write("=" * 70)
	write("Direct Default-slot virtual dispatches")
	write("=" * 70)
	write("DAT_011f6238 is an embedded GameHeap object. Its Default slot is")
	write("the fixed address 0x%08x, not a pointer loaded from 0x%08x." % (DEFAULT_SLOT, GAME_HEAP_BASE))
	write("A report requires Default-slot load -> vtable load -> CALL [vtable + 0x8/+0xc].")
	write("This linear register trace can miss branch-spanning or stack-spilled paths;")
	write("it does not prove absence of bypasses.")
	functions = functions_referencing(DEFAULT_SLOT)
	write("  Functions referencing Default slot: %d" % len(functions))
	loads_found = []
	paths_found = []
	idx = 0
	while idx < len(functions):
		func = functions[idx]
		result = trace_function(func)
		loads = result[0]
		paths = result[1]
		if len(loads) > 0:
			loads_found.append((func, loads))
		if len(paths) > 0:
			paths_found.append((func, loads, paths))
		idx += 1
	write("  Functions loading Default slot: %d" % len(loads_found))
	write("  Provenance-complete virtual dispatches: %d" % len(paths_found))
	idx = 0
	while idx < len(loads_found):
		item = loads_found[idx]
		func = item[0]
		loads = item[1]
		write("  Default-slot load in %s" % func_name(func))
		load_idx = 0
		while load_idx < len(loads):
			load = loads[load_idx]
			write("    0x%08x: %s" % (load[0], load[1]))
			load_idx += 1
		idx += 1
	idx = 0
	while idx < len(paths_found):
		item = paths_found[idx]
		func = item[0]
		loads = item[1]
		paths = item[2]
		write("")
		write("Dispatch in %s" % func_name(func))
		path_idx = 0
		while path_idx < len(paths):
			path = paths[path_idx]
			write("  Virtual call: 0x%08x: %s" % (path[0], path[1]))
			path_idx += 1
		decompile_at(func.getEntryPoint().getOffset(), "Direct Default-slot dispatch", 16000)
		idx += 1

def main():
	write("AUDIT: gheap direct Default-heap dispatch provenance")
	write("=" * 70)
	write("The previous version incorrectly treated DAT_011f6238 as a pointer.")
	write("This version audits the actual embedded Default slot at 0x%08x." % DEFAULT_SLOT)
	find_refs_to(DEFAULT_SLOT, "GameHeap Default slot")
	decompile_at(0x00866E00, "SBM Default/File heap construction")
	find_and_print_calls_from(0x00866E00, "SBM Default/File heap construction")
	decompile_at(0x00AA3E40, "GameHeap Allocate virtual dispatch")
	decompile_at(0x00AA4060, "GameHeap Free dispatch")
	audit_direct_default_slot_dispatches()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/memory/gheap_default_heap_dispatch_provenance_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
