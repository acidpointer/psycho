# @category Analysis
# @description Close FNV PBR query-free hot-path contracts for constants, texture ownership, and pass-cache invalidation

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

OUTPATH = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_continuity_hotpath_contract_closure.txt"
MAX_REFS = 160
MAX_CALLS = 180
MAX_VIRTUAL_HITS_PER_METHOD = 80
MAX_CANDIDATE_DECOMPILES = 18

KNOWN = {
	0x00B70390: "PPLighting property light-list sorter",
	0x00B71BF0: "PPLighting vertex descriptor constructor",
	0x00B74210: "PPLighting pixel descriptor constructor",
	0x00B7A870: "PPLighting shader-interface record registration",
	0x00B7E430: "PPLighting constant table registration",
	0x00B994F0: "current geometry and selector writer",
	0x00BA8C50: "pass-entry reused-entry array setter",
	0x00BA8EC0: "pass-entry constructor",
	0x00BA9EE0: "pass-entry append/reuse helper",
	0x00BB4740: "PPLighting property dirty/pass updater",
	0x00BDAF10: "close-terrain material row emitter",
	0x00BDB4A0: "PPLighting selector setup F0 family",
	0x00BDF790: "PPLighting selector/pass-entry driver F4 family",
	0x00BD4BA0: "current pass shader-interface apply",
	0x00BE1F90: "BSShader::SetShaders",
	0x00E7F430: "shader-interface record finalizer",
	0x00E7F5D0: "shader-interface record allocator",
	0x00E826D0: "shader-interface record D3D apply",
	0x00E88A20: "NiDX9RenderState::SetTexture",
	0x00E90850: "current NiD3DPass writer",
	0x011F91E0: "current geometry slot",
	0x0126F74C: "current NiD3DPass global",
}

FOCUS_DECOMPILES = [
	(0x00B70390, "PPLighting property light-list sorter", 18000),
	(0x00B7A870, "PPLighting shader-interface record registration", 30000),
	(0x00B7E430, "PPLighting constant table registration", 32000),
	(0x00B994F0, "current geometry and selector writer", 18000),
	(0x00BA9EE0, "pass-entry append/reuse helper", 22000),
	(0x00BB4740, "PPLighting property dirty/pass updater", 26000),
	(0x00BDB4A0, "PPLighting selector setup F0 family", 30000),
	(0x00BDF790, "PPLighting selector/pass-entry driver F4 family", 36000),
	(0x00BD4BA0, "current pass shader-interface apply", 26000),
	(0x00BE1F90, "BSShader::SetShaders", 22000),
	(0x00E7F430, "shader-interface record finalizer", 12000),
	(0x00E826D0, "shader-interface record D3D apply", 22000),
	(0x00E88A20, "NiDX9RenderState::SetTexture", 16000),
	(0x00E90850, "current NiD3DPass writer", 18000),
]

RAW_BLOCKS = [
	(0x00BE1F90, "BSShader::SetShaders standalone block", 80),
	(0x00E88A20, "NiDX9RenderState::SetTexture standalone block", 40),
]

REF_TARGETS = [
	(0x00E7F430, "shader-interface record finalizer"),
	(0x00E88A20, "NiDX9RenderState::SetTexture"),
	(0x00BA9EE0, "pass-entry append/reuse helper"),
	(0x00B70390, "PPLighting property light-list sorter"),
	(0x00BB4740, "PPLighting property dirty/pass updater"),
	(0x00BD4BA0, "current pass shader-interface apply"),
	(0x011F91E0, "current geometry slot"),
	(0x0126F74C, "current NiD3DPass global"),
]

CALL_TARGETS = [
	(0x00B70390, "PPLighting property light-list sorter"),
	(0x00B7A870, "PPLighting shader-interface record registration"),
	(0x00B994F0, "current geometry and selector writer"),
	(0x00BA9EE0, "pass-entry append/reuse helper"),
	(0x00BB4740, "PPLighting property dirty/pass updater"),
	(0x00BDB4A0, "PPLighting selector setup F0 family"),
	(0x00BDF790, "PPLighting selector/pass-entry driver F4 family"),
	(0x00BD4BA0, "current pass shader-interface apply"),
	(0x00BE1F90, "BSShader::SetShaders"),
	(0x00E826D0, "shader-interface record D3D apply"),
	(0x00E88A20, "NiDX9RenderState::SetTexture"),
	(0x00E90850, "current NiD3DPass writer"),
]

OFFSET_SCAN_TARGETS = [
	(0x00B70390, "property light-list sorter", [0x38, 0x60, 0x74]),
	(0x00BB4740, "property dirty/pass updater", [0x38, 0x60, 0x74]),
	(0x00B994F0, "current geometry and selector writer", [0x3C, 0x68, 0xC0]),
	(0x00BA9EE0, "pass-entry append/reuse helper", [0x04, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x10]),
	(0x00BDB4A0, "selector setup F0 family", [0x38, 0x3C, 0xA8, 0xC4, 0xCC]),
	(0x00BDF790, "selector/pass-entry driver F4 family", [0x38, 0x3C, 0xA8, 0xC4, 0xCC]),
	(0x00BD4BA0, "current pass shader-interface apply", [0x04, 0x0C, 0x44, 0x68]),
	(0x00E90850, "current NiD3DPass writer", [0x04, 0x0C, 0x44]),
]

TARGET_REGISTERS = {
	0x20: "c32",
	0x21: "c33",
	0x59: "c89",
	0x5A: "c90",
}

D3D_METHODS = {
	0x14: "vtable +0x14 Apply candidate",
	0xEC: "vtable +0xEC CreateStateBlock candidate",
	0xF0: "vtable +0xF0 BeginStateBlock candidate",
	0xF4: "vtable +0xF4 EndStateBlock candidate",
	0x100: "vtable +0x100 GetTexture candidate",
	0x104: "vtable +0x104 SetTexture candidate",
	0x170: "vtable +0x170 SetVertexShader candidate",
	0x174: "vtable +0x174 GetVertexShader candidate",
	0x178: "vtable +0x178 SetVertexShaderConstantF candidate",
	0x17C: "vtable +0x17C GetVertexShaderConstantF candidate",
	0x1AC: "vtable +0x1AC SetPixelShader candidate",
	0x1B0: "vtable +0x1B0 GetPixelShader candidate",
	0x1B4: "vtable +0x1B4 SetPixelShaderConstantF candidate",
	0x1B8: "vtable +0x1B8 GetPixelShaderConstantF candidate",
}

def write(msg):
	output.append(msg)
	print(msg)

def checkpoint_output():
	fout = open(OUTPATH, "w")
	fout.write("\n".join(output))
	fout.close()

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

def function_at_or_containing(addr_int):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	return func

def function_label(addr_int):
	label = KNOWN.get(addr_int)
	if label is not None:
		return label
	func = function_at_or_containing(addr_int)
	if func is None:
		return "unknown"
	entry = func.getEntryPoint().getOffset()
	if entry == addr_int:
		return func.getName()
	return "%s+0x%x" % (func.getName(), addr_int - entry)

def scalar_value(inst, operand_index):
	values = scalar_values(inst, operand_index)
	if len(values) == 0:
		return None
	return values[0]

def scalar_values(inst, operand_index):
	values = []
	try:
		objects = inst.getOpObjects(operand_index)
		index = 0
		while index < len(objects):
			obj = objects[index]
			try:
				values.append(obj.getValue() & 0xffffffff)
			except:
				pass
			index += 1
	except:
		pass
	return values

def instruction_has_scalar(inst, target):
	index = 0
	while index < inst.getNumOperands():
		if target in scalar_values(inst, index):
			return True
		index += 1
	return False

def instruction_method_offset(inst, methods):
	index = 0
	while index < inst.getNumOperands():
		values = scalar_values(inst, index)
		value_index = 0
		while value_index < len(values):
			if values[value_index] in methods:
				return values[value_index]
			value_index += 1
		index += 1
	return None

def register_name(inst, operand_index):
	try:
		reg = inst.getRegister(operand_index)
		if reg is None:
			return None
		return reg.getName()
	except:
		return None

def instruction_writes_register(inst, reg_name):
	if reg_name is None:
		return False
	mnemonic = inst.getMnemonicString().upper()
	if mnemonic not in ["MOV", "LEA", "POP", "XOR", "ADD", "SUB", "AND", "OR", "MOVZX", "MOVSX"]:
		return False
	return register_name(inst, 0) == reg_name

def previous_instruction(inst):
	func = fm.getFunctionContaining(inst.getAddress())
	prev = listing.getInstructionBefore(inst.getAddress())
	if prev is None:
		return None
	if func is None:
		return prev
	if not func.getBody().contains(prev.getAddress()):
		return None
	return prev

def instruction_owner_entry(inst):
	func = fm.getFunctionContaining(inst.getAddress())
	if func is not None:
		return func.getEntryPoint().getOffset()
	current = inst
	steps = 0
	while current is not None and steps < 160:
		prev = listing.getInstructionBefore(current.getAddress())
		if prev is None:
			break
		mnemonic = prev.getMnemonicString().upper()
		if mnemonic.startswith("RET") or mnemonic == "INT3":
			break
		current = prev
		steps += 1
	return current.getAddress().getOffset()

def instruction_before_steps(inst, steps):
	current = inst
	index = 0
	while current is not None and index < steps:
		previous = previous_instruction(current)
		if previous is None:
			break
		current = previous
		index += 1
	return current

def disasm_window(center_int, before_count, after_count, label):
	write("")
	write("-" * 70)
	write("Disassembly %s around 0x%08x" % (label, center_int))
	write("-" * 70)
	center = listing.getInstructionContaining(toAddr(center_int))
	if center is None:
		write("  [instruction not found]")
		return
	current = instruction_before_steps(center, before_count)
	count = 0
	limit = before_count + after_count + 1
	while current is not None and count < limit:
		addr_int = current.getAddress().getOffset()
		marker = " << TARGET" if addr_int == center.getAddress().getOffset() else ""
		extra = ""
		refs = current.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				target = ref.getToAddress().getOffset()
				extra = " ; CALL 0x%08x %s" % (target, function_label(target))
		write("  0x%08x: %-58s%s%s" % (addr_int, current.toString(), marker, extra))
		current = listing.getInstructionAfter(current.getAddress())
		count += 1

def disasm_forward_block(start_int, label, max_instructions):
	write("")
	write("=" * 70)
	write("RAW STANDALONE BLOCK: %s @ 0x%08x" % (label, start_int))
	write("=" * 70)
	current = listing.getInstructionContaining(toAddr(start_int))
	if current is None:
		write("  [instruction not found]")
		return
	count = 0
	while current is not None and count < max_instructions:
		addr_int = current.getAddress().getOffset()
		extra = ""
		refs = current.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				target = ref.getToAddress().getOffset()
				extra = " ; CALL 0x%08x %s" % (target, function_label(target))
		write("  0x%08x: %-58s%s" % (addr_int, current.toString(), extra))
		count += 1
		if current.getMnemonicString().upper().startswith("RET"):
			break
		current = listing.getInstructionAfter(current.getAddress())
	write("  Total block instructions: %d" % count)

def nearest_push_scalars(call_inst, max_steps, max_pushes):
	values = []
	current = previous_instruction(call_inst)
	steps = 0
	while current is not None and steps < max_steps and len(values) < max_pushes:
		if current.getMnemonicString().upper() == "PUSH":
			values.append(scalar_value(current, 0))
		if current.getMnemonicString().upper() in ["RET", "CALL"]:
			break
		current = previous_instruction(current)
		steps += 1
	return values

def call_uses_method_offset(inst, target_offset):
	if instruction_has_scalar(inst, target_offset):
		return True
	call_reg = register_name(inst, 0)
	if call_reg is None:
		return False
	current = previous_instruction(inst)
	steps = 0
	while current is not None and steps < 12:
		if instruction_writes_register(current, call_reg):
			return instruction_has_scalar(current, target_offset)
		current = previous_instruction(current)
		steps += 1
	return False

def string_at(value):
	if value is None:
		return "?"
	try:
		data = listing.getDataAt(toAddr(value))
		if data is None:
			return "?"
		text = str(data.getValue())
		if len(text) > 120:
			return text[:120]
		return text
	except:
		return "?"

def direct_call_target(inst):
	refs = inst.getReferencesFrom()
	for ref in refs:
		if ref.getReferenceType().isCall():
			return ref.getToAddress().getOffset()
	return None

def audit_constant_register_records():
	write("")
	write("=" * 70)
	write("CONSTANT-TABLE REGISTER COVERAGE")
	write("=" * 70)
	write("The +0x08 interface method receives name, type, selector, register start, and register count as its first five arguments.")
	write("Coverage below is numeric only. Vertex/pixel ownership must be resolved from the enclosing table constructor stage.")
	func = function_at_or_containing(0x00B7E430)
	if func is None:
		write("  [constant-table registration function not found]")
		return
	owners = {}
	targets = TARGET_REGISTERS.keys()
	targets.sort()
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		if inst.getMnemonicString().upper() != "CALL":
			continue
		if not call_uses_method_offset(inst, 0x08):
			continue
		values = nearest_push_scalars(inst, 40, 12)
		if len(values) < 5:
			continue
		start = values[3]
		register_count = values[4]
		if start is None or register_count is None:
			continue
		if start > 0x200 or register_count == 0 or register_count > 0x200:
			continue
		end = start + register_count - 1
		owned = []
		index = 0
		while index < len(targets):
			target = targets[index]
			if start <= target and target <= end:
				owned.append(TARGET_REGISTERS[target])
				entries = owners.get(target)
				if entries is None:
					entries = []
					owners[target] = entries
				entries.append(inst.getAddress().getOffset())
			index += 1
		write("  0x%08x name=%-38s registers=c%d..c%d count=%d target_overlap=%s" % (inst.getAddress().getOffset(), string_at(values[0]), start, end, register_count, str(owned)))
		if len(owned) > 0:
			disasm_window(inst.getAddress().getOffset(), 18, 8, "target-register constant record")
		count += 1
	write("  Total decoded +0x08 constant records: %d" % count)
	write("")
	write("Numeric target-overlap summary, before stage separation:")
	index = 0
	while index < len(targets):
		target = targets[index]
		entries = owners.get(target, [])
		write("  %-4s covered_by=%s" % (TARGET_REGISTERS[target], str(entries)))
		index += 1

def method_offset_from_call(inst):
	offset = instruction_method_offset(inst, D3D_METHODS)
	if offset is not None:
		return offset
	call_reg = register_name(inst, 0)
	if call_reg is None:
		return None
	current = previous_instruction(inst)
	steps = 0
	while current is not None and steps < 12:
		if instruction_writes_register(current, call_reg):
			return instruction_method_offset(current, D3D_METHODS)
		current = previous_instruction(current)
		steps += 1
	return None

def scan_d3d_virtual_calls():
	write("")
	write("=" * 70)
	write("BOUNDED INTERFACE-UNPROVEN VTABLE-OFFSET CANDIDATES")
	write("=" * 70)
	write("Only CALL operands or the final register-defining MOV with an exact vtable displacement are accepted.")
	write("A matching displacement does not prove a D3D receiver. Decompile or object-field provenance is mandatory.")
	hits = []
	by_function = {}
	total_by_method = {}
	retained_by_method = {}
	inst_iter = listing.getInstructions(True)
	while inst_iter.hasNext():
		if monitor.isCancelled():
			break
		inst = inst_iter.next()
		if inst.getMnemonicString().upper() != "CALL":
			continue
		offset = method_offset_from_call(inst)
		if offset is None:
			continue
		total_by_method[offset] = total_by_method.get(offset, 0) + 1
		retained = retained_by_method.get(offset, 0)
		if retained >= MAX_VIRTUAL_HITS_PER_METHOD:
			continue
		retained_by_method[offset] = retained + 1
		entry = instruction_owner_entry(inst)
		item = (inst.getAddress().getOffset(), entry, offset)
		hits.append(item)
		values = by_function.get(entry)
		if values is None:
			values = []
			by_function[entry] = values
		values.append(item)
	index = 0
	while index < len(hits):
		item = hits[index]
		write("  0x%08x in 0x%08x %s: %s" % (item[0], item[1], function_label(item[1]), D3D_METHODS[item[2]]))
		index += 1
	write("  Total retained virtual-call candidates: %d" % len(hits))
	method_offsets = total_by_method.keys()
	method_offsets.sort()
	index = 0
	while index < len(method_offsets):
		offset = method_offsets[index]
		write("  %-52s total=%d retained=%d" % (D3D_METHODS[offset], total_by_method[offset], retained_by_method.get(offset, 0)))
		index += 1
	write("")
	write("Candidate functions selected for decompilation:")
	entries = by_function.keys()
	entries.sort()
	selected = 0
	index = 0
	while index < len(entries) and selected < MAX_CANDIDATE_DECOMPILES:
		entry = entries[index]
		items = by_function[entry]
		function_method_offsets = {}
		item_index = 0
		while item_index < len(items):
			function_method_offsets[items[item_index][2]] = True
			item_index += 1
		interesting = 0x104 in function_method_offsets or 0xEC in function_method_offsets or 0xF0 in function_method_offsets or 0xF4 in function_method_offsets or 0x1B4 in function_method_offsets
		if interesting and (len(function_method_offsets) > 1 or entry >= 0x00E00000):
			write("  0x%08x %s methods=%s" % (entry, function_label(entry), str(function_method_offsets.keys())))
			decompile_at(entry, "D3D virtual-call candidate %s" % function_label(entry), 22000)
			item_index = 0
			while item_index < len(items):
				disasm_window(items[item_index][0], 10, 8, D3D_METHODS[items[item_index][2]])
				item_index += 1
			selected += 1
		index += 1
	index = 0
	while index < len(method_offsets):
		offset = method_offsets[index]
		if total_by_method[offset] > retained_by_method.get(offset, 0):
			write("  WARNING: %s candidates truncated at %d" % (D3D_METHODS[offset], MAX_VIRTUAL_HITS_PER_METHOD))
		index += 1

def audit_pass_entry_mutators():
	write("")
	write("=" * 70)
	write("PASS-ENTRY CONSTRUCTION AND MUTATION CALLS")
	write("=" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(0x00BA9EE0))
	count = 0
	callers = {}
	while refs.hasNext() and count < MAX_REFS:
		ref = refs.next()
		if not ref.getReferenceType().isCall():
			continue
		call_addr = ref.getFromAddress().getOffset()
		if call_addr < 0x00B00000 or call_addr > 0x00C20000:
			continue
		inst = listing.getInstructionContaining(ref.getFromAddress())
		func = fm.getFunctionContaining(ref.getFromAddress())
		entry = func.getEntryPoint().getOffset() if func is not None else 0
		callers[entry] = callers.get(entry, 0) + 1
		values = nearest_push_scalars(inst, 20, 10) if inst is not None else []
		write("  0x%08x in %s nearest_pushes=%s" % (call_addr, function_label(call_addr), str(values)))
		count += 1
	write("  Total printed pass-entry calls: %d" % count)
	write("")
	write("Pass-entry callers and call counts:")
	entries = callers.keys()
	entries.sort()
	index = 0
	while index < len(entries):
		entry = entries[index]
		write("  0x%08x %-46s calls=%d" % (entry, function_label(entry), callers[entry]))
		index += 1

def scan_function_offsets(addr_int, label, offsets):
	write("")
	write("=" * 70)
	write("STRUCTURE OFFSET HITS: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	func = function_at_or_containing(addr_int)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		text = inst.toString()
		if "[" not in text:
			continue
		index = 0
		while index < len(offsets):
			if instruction_has_scalar(inst, offsets[index]):
				write("  0x%08x offset=0x%x %s" % (inst.getAddress().getOffset(), offsets[index], text))
				count += 1
				break
			index += 1
	write("  Total structure-offset hits: %d" % count)

def run_refs():
	index = 0
	while index < len(REF_TARGETS):
		item = REF_TARGETS[index]
		find_refs_to(item[0], item[1])
		index += 1

def run_calls():
	index = 0
	while index < len(CALL_TARGETS):
		item = CALL_TARGETS[index]
		find_and_print_calls_from(item[0], item[1])
		index += 1

def run_offset_scans():
	index = 0
	while index < len(OFFSET_SCAN_TARGETS):
		item = OFFSET_SCAN_TARGETS[index]
		scan_function_offsets(item[0], item[1], item[2])
		index += 1

def run_raw_blocks():
	index = 0
	while index < len(RAW_BLOCKS):
		item = RAW_BLOCKS[index]
		disasm_forward_block(item[0], item[1], item[2])
		index += 1

def run_focus_decompiles():
	index = 0
	while index < len(FOCUS_DECOMPILES):
		if monitor.isCancelled():
			return
		item = FOCUS_DECOMPILES[index]
		decompile_at(item[0], item[1], item[2])
		checkpoint_output()
		index += 1

def write_header():
	write("FNV PBR CONTINUITY HOT-PATH CONTRACT CLOSURE")
	write("")
	write("Questions:")
	write("1. Which native PPLighting records own c32/c33, and does vanilla own c89/c90 at all?")
	write("2. When are those records applied relative to SetShaders, draw dispatch, and the next native constant update?")
	write("3. Does any engine D3D SetTexture path bypass NiDX9RenderState::SetTexture?")
	write("4. Can Begin/End/CreateStateBlock or another direct D3D path change textures without that hook?")
	write("5. Is there a direct current pass-entry bridge, or what exact selector/property/pass key can cache ownership?")
	write("6. Which functions build, mutate, clear, or invalidate selector +0x3C entries and property +0x38/+0x74 state?")
	write("")
	write("The script uses exact callsite argument and virtual-call patterns. A method displacement alone still does not prove the receiver interface.")

def main():
	write_header()
	audit_constant_register_records()
	audit_pass_entry_mutators()
	run_refs()
	run_offset_scans()
	run_calls()
	run_raw_blocks()
	scan_d3d_virtual_calls()
	run_focus_decompiles()
	checkpoint_output()
	write("")
	write("OUTPUT COMPLETE: %s (%d lines)" % (OUTPATH, len(output)))

try:
	main()
finally:
	checkpoint_output()
	decomp.dispose()
