# @category Analysis
# @description Close FNV PBR draw identity, vertex binding, and projected-shadow slot/resource contracts

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

OUTPATH = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_continuity_draw_resource_contract_closure.txt"
MAX_VIRTUAL_HITS_PER_METHOD = 80
MAX_BINDER_DECOMPILES = 20

KNOWN = {
	0x00871290: "vanilla RenderShadowMaps owner",
	0x00B5CDE0: "shadow candidate ranking/replacement/fade",
	0x00B66640: "PPLighting material-array flag initializer",
	0x00B67BE0: "PPLighting projected resource refresh",
	0x00B68450: "PPLighting selector material-array resize/mutation",
	0x00B68660: "PPLighting material texture-array writer",
	0x00B7DAB0: "PPLighting pass resource dispatcher",
	0x00B7AD00: "alternate current NiD3DPass writer",
	0x00B7AF80: "PPLighting current NiD3DPass writer",
	0x00B988E0: "selector texture-state reset helper",
	0x00B99390: "selector/source cache transition",
	0x00B994F0: "current geometry and selector writer",
	0x00B9DFC0: "shadow candidate physical-slot setup",
	0x00B9E970: "shadow transition and render updater",
	0x00B9F780: "shadow-map rendering/postprocess",
	0x00B97550: "image-space shadow resource consumer",
	0x00BA30F0: "render-slot synchronization release",
	0x00BA3130: "render-slot synchronization acquire",
	0x00BA3390: "render-slot task/resource record setup",
	0x00BA8C50: "pass-entry resource/argument attachment",
	0x00BA8EC0: "pass-entry constructor",
	0x00BA9EE0: "pass-entry append/reuse helper",
	0x00BDAF10: "close-terrain material row emitter",
	0x00BDB4A0: "PPLighting selector setup F0 family",
	0x00BDF3E0: "LandO/light-resource row emitter",
	0x00BDF650: "projected-shadow row 0x10..0x13 emitter",
	0x00BDF790: "PPLighting selector/pass-entry driver F4 family",
	0x00BD4BA0: "current pass shader-interface apply",
	0x00BC3E40: "property-specific projected resource refresh driver",
	0x00E7CC10: "shader-interface virtual wrapper",
	0x00E7EA00: "pass-entry texture record resolver",
	0x00E7EB00: "texture record apply",
	0x00E826D0: "shader-interface D3D apply",
	0x00E88A20: "NiDX9RenderState::SetTexture",
	0x00E88A60: "NiDX9RenderState clear texture from all stages",
	0x00E90B10: "source texture-data resolver",
	0x00E91590: "NiDX9RenderState virtual wrapper candidate",
	0x00EBFF30: "late renderer SetTexture-offset candidate",
	0x011F91E0: "current geometry slot",
	0x0126F74C: "current NiD3DPass global",
}

FOCUS_DECOMPILES = [
	(0x00871290, "vanilla RenderShadowMaps owner", 36000),
	(0x00B5CDE0, "shadow candidate ranking/replacement/fade", 34000),
	(0x00B66640, "PPLighting material-array flag initializer", 22000),
	(0x00B67BE0, "PPLighting projected resource refresh", 32000),
	(0x00B68450, "PPLighting selector material-array resize/mutation", 28000),
	(0x00B68660, "PPLighting material texture-array writer", 24000),
	(0x00B7DAB0, "PPLighting pass resource dispatcher", 30000),
	(0x00B7AD00, "alternate current NiD3DPass writer", 26000),
	(0x00B7AF80, "PPLighting current NiD3DPass writer", 22000),
	(0x00B988E0, "selector texture-state reset helper", 18000),
	(0x00B99390, "selector/source cache transition", 22000),
	(0x00B994F0, "current geometry and selector writer", 18000),
	(0x00B9DFC0, "shadow candidate physical-slot setup", 30000),
	(0x00B9E970, "shadow transition and render updater", 36000),
	(0x00B9F780, "shadow-map rendering/postprocess", 32000),
	(0x00B97550, "image-space shadow resource consumer", 24000),
	(0x00BA30F0, "render-slot synchronization release", 16000),
	(0x00BA3130, "render-slot synchronization acquire", 16000),
	(0x00BA3390, "render-slot task/resource record setup", 26000),
	(0x00BA8C50, "pass-entry resource/argument attachment", 18000),
	(0x00BA8EC0, "pass-entry constructor", 14000),
	(0x00BA9EE0, "pass-entry append/reuse helper", 22000),
	(0x00BDAF10, "close-terrain material row emitter", 30000),
	(0x00BDF3E0, "LandO/light-resource row emitter", 30000),
	(0x00BDF650, "projected-shadow row 0x10..0x13 emitter", 22000),
	(0x00BD4BA0, "current pass shader-interface apply", 26000),
	(0x00BC3E40, "property-specific projected resource refresh driver", 36000),
	(0x00E7CC10, "shader-interface virtual wrapper", 12000),
	(0x00E7EA00, "pass-entry texture record resolver", 22000),
	(0x00E7EB00, "texture record apply", 18000),
	(0x00E91590, "NiDX9RenderState virtual wrapper candidate", 18000),
	(0x00EBFF30, "late renderer SetTexture-offset candidate", 26000),
	(0x00E90B10, "source texture-data resolver", 18000),
]

RAW_BLOCKS = [
	(0x00E88A20, "NiDX9RenderState::SetTexture standalone block", 40),
	(0x00E88A60, "NiDX9RenderState clear texture from all stages", 40),
	(0x00E90B10, "renderer +0x8C4 source texture-data resolver", 80),
]

REF_TARGETS = [
	(0x00B9DFC0, "shadow candidate physical-slot setup"),
	(0x00B67BE0, "PPLighting projected resource refresh"),
	(0x00BC3E40, "property-specific projected resource refresh driver"),
	(0x00B7AF80, "PPLighting current NiD3DPass writer"),
	(0x00BA8C50, "pass-entry resource/argument attachment"),
	(0x00B7DAB0, "PPLighting pass resource dispatcher"),
	(0x00BDF650, "projected-shadow row 0x10..0x13 emitter"),
	(0x00E7EA00, "pass-entry texture record resolver"),
	(0x00E88A20, "NiDX9RenderState::SetTexture"),
	(0x00BA3390, "render-slot task/resource record setup"),
	(0x011F91E0, "current geometry slot"),
	(0x0126F74C, "current NiD3DPass global"),
]

CALL_TARGETS = [
	(0x00871290, "vanilla RenderShadowMaps owner"),
	(0x00B5CDE0, "shadow candidate ranking/replacement/fade"),
	(0x00B67BE0, "PPLighting projected resource refresh"),
	(0x00B7DAB0, "PPLighting pass resource dispatcher"),
	(0x00B7AD00, "alternate current NiD3DPass writer"),
	(0x00B7AF80, "PPLighting current NiD3DPass writer"),
	(0x00B9DFC0, "shadow candidate physical-slot setup"),
	(0x00B9E970, "shadow transition and render updater"),
	(0x00B9F780, "shadow-map rendering/postprocess"),
	(0x00B97550, "image-space shadow resource consumer"),
	(0x00BA30F0, "render-slot synchronization release"),
	(0x00BA3130, "render-slot synchronization acquire"),
	(0x00BA3390, "render-slot task/resource record setup"),
	(0x00BA8C50, "pass-entry resource/argument attachment"),
	(0x00BA9EE0, "pass-entry append/reuse helper"),
	(0x00BC3E40, "property-specific projected resource refresh driver"),
	(0x00BDAF10, "close-terrain material row emitter"),
	(0x00BDF3E0, "LandO/light-resource row emitter"),
	(0x00BDF650, "projected-shadow row 0x10..0x13 emitter"),
	(0x00BD4BA0, "current pass shader-interface apply"),
	(0x00E7EA00, "pass-entry texture record resolver"),
	(0x00E7EB00, "texture record apply"),
	(0x00E90B10, "source texture-data resolver"),
]

FOCUS_WINDOWS = [
	(0x00871880, 36, 72, "physical shadow slot assignment and render dispatch"),
	(0x00871970, 28, 54, "unused physical shadow slot cleanup"),
	(0x00B67CD0, 28, 40, "projected resource refresh callsite A"),
	(0x00B68337, 28, 40, "projected resource refresh callsite B"),
	(0x00BC3EC9, 32, 52, "property driver to projected resource refresh"),
	(0x00B7AF91, 24, 36, "PPLighting current NiD3DPass publication"),
	(0x00BDB1C7, 22, 34, "close-terrain companion row 0x1F2"),
	(0x00BDB204, 22, 34, "close-terrain companion row 0x1F3"),
	(0x00BDB28E, 22, 34, "close-terrain companion row 0x1F4"),
	(0x00BDB334, 22, 34, "close-terrain companion row 0x1F5"),
	(0x00BDF67D, 22, 34, "projected-shadow row 0x10 construction"),
	(0x00BDF68C, 22, 34, "projected-shadow row 0x11 construction"),
	(0x00BDF6A2, 22, 34, "projected-shadow row 0x12 construction"),
	(0x00BDF6B1, 22, 34, "projected-shadow row 0x13 construction"),
	(0x00BD4C35, 24, 44, "current pixel shader-interface apply"),
	(0x00BD4CBC, 24, 44, "current vertex shader-interface apply"),
	(0x00E7EA2D, 24, 36, "pass texture-stage tracker lookup"),
	(0x00E7EAC7, 26, 38, "post-texture helper A"),
	(0x00E7EACE, 26, 38, "post-texture helper B"),
	(0x00E90B10, 0, 80, "renderer +0x8C4 texture-data resolver body"),
]

FIELD_SCAN_TARGETS = [
	(0x00871290, "RenderShadowMaps slot owner", [0x11, 0x12, 0x13, 0x14, 0x1A0]),
	(0x00B5CDE0, "shadow candidate ranking/replacement", [0xD8, 0xDC, 0xEC, 0xF8, 0x1A0]),
	(0x00B67BE0, "projected resource refresh", [0x11, 0x12, 0x13, 0x14, 0x1A0]),
	(0x00B9DFC0, "shadow candidate physical-slot setup", [0x11, 0x12, 0x13, 0x14, 0xD8, 0xDC, 0xEC, 0xF8, 0x1A0]),
	(0x00B9E970, "shadow transition and render updater", [0xD8, 0xDC, 0xEC, 0xF8, 0x1A0]),
	(0x00BA8C50, "pass-entry resource attachment", [0x00, 0x04, 0x08, 0x0C]),
	(0x00B66640, "material-array flag initializer", [0x3C, 0xA8, 0xC4, 0xCC]),
	(0x00B68450, "material-array resize/mutation", [0x3C, 0xA8, 0xC4, 0xCC]),
	(0x00B68660, "material texture-array writer", [0x3C, 0xA8, 0xC4, 0xCC]),
	(0x00B7DAB0, "pass resource dispatcher", [0x00, 0x04, 0x0B, 0x0C, 0x68, 0x78]),
	(0x00B994F0, "current geometry and selector writer", [0x3C, 0x68, 0xC0]),
	(0x00BDAF10, "close-terrain material row emitter", [0x1F2, 0x1F3, 0x1F4, 0x1F5, 0x3C, 0xA8, 0xC4, 0xCC]),
	(0x00BDF3E0, "LandO/light-resource row emitter", [0x1F7, 0x22E, 0x230, 0x3C]),
	(0x00BDF650, "projected-shadow row emitter", [0x10, 0x11, 0x12, 0x13, 0x3C]),
]

D3D_VERTEX_METHODS = {
	0x144: "IDirect3DDevice9::DrawPrimitive",
	0x148: "IDirect3DDevice9::DrawIndexedPrimitive",
	0x158: "IDirect3DDevice9::CreateVertexDeclaration",
	0x15C: "IDirect3DDevice9::SetVertexDeclaration",
	0x160: "IDirect3DDevice9::GetVertexDeclaration",
	0x164: "IDirect3DDevice9::SetFVF",
	0x168: "IDirect3DDevice9::GetFVF",
	0x170: "IDirect3DDevice9::SetVertexShader",
	0x190: "IDirect3DDevice9::SetStreamSource",
	0x194: "IDirect3DDevice9::GetStreamSource",
	0x198: "IDirect3DDevice9::SetStreamSourceFreq",
	0x19C: "IDirect3DDevice9::GetStreamSourceFreq",
	0x1A0: "IDirect3DDevice9::SetIndices",
	0x1A4: "IDirect3DDevice9::GetIndices",
}

RENDERER_DEVICE_METHODS = {
	0x14: "COM +0x14 Apply candidate",
	0xEC: "device +0xEC CreateStateBlock candidate",
	0xF0: "device +0xF0 BeginStateBlock candidate",
	0xF4: "device +0xF4 EndStateBlock candidate",
	0x100: "device +0x100 GetTexture candidate",
	0x104: "device +0x104 SetTexture candidate",
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

def run_raw_blocks():
	index = 0
	while index < len(RAW_BLOCKS):
		item = RAW_BLOCKS[index]
		disasm_forward_block(item[0], item[1], item[2])
		index += 1

def method_offset_from_call(inst):
	offset = instruction_method_offset(inst, D3D_VERTEX_METHODS)
	if offset is not None:
		return offset
	call_reg = register_name(inst, 0)
	if call_reg is None:
		return None
	current = previous_instruction(inst)
	steps = 0
	while current is not None and steps < 12:
		if instruction_writes_register(current, call_reg):
			return instruction_method_offset(current, D3D_VERTEX_METHODS)
		current = previous_instruction(current)
		steps += 1
	return None

def method_offset_from_call_for_methods(inst, methods):
	offset = instruction_method_offset(inst, methods)
	if offset is not None:
		return offset
	call_reg = register_name(inst, 0)
	if call_reg is None:
		return None
	current = previous_instruction(inst)
	steps = 0
	while current is not None and steps < 12:
		if instruction_writes_register(current, call_reg):
			return instruction_method_offset(current, methods)
		current = previous_instruction(current)
		steps += 1
	return None

def previous_instructions_have_scalar(inst, target, max_steps):
	current = previous_instruction(inst)
	steps = 0
	while current is not None and steps < max_steps:
		if instruction_has_scalar(current, target):
			return True
		mnemonic = current.getMnemonicString().upper()
		if mnemonic.startswith("RET") or mnemonic == "INT3":
			break
		current = previous_instruction(current)
		steps += 1
	return False

def scan_renderer_device_provenance():
	write("")
	write("=" * 70)
	write("NIDX9RENDERSTATE +0x10F8 DEVICE-PROVENANCE CALLS")
	write("=" * 70)
	write("A matching vtable offset is retained only when the same local call window loads the NiDX9RenderState device field +0x10F8.")
	write("COM +0x14 calls without that provenance remain interface-unproven and are intentionally excluded.")
	hits = []
	inst_iter = listing.getInstructions(True)
	while inst_iter.hasNext():
		if monitor.isCancelled():
			break
		inst = inst_iter.next()
		if inst.getMnemonicString().upper() != "CALL":
			continue
		offset = method_offset_from_call_for_methods(inst, RENDERER_DEVICE_METHODS)
		if offset is None:
			continue
		if not previous_instructions_have_scalar(inst, 0x10F8, 28):
			continue
		hits.append((inst.getAddress().getOffset(), instruction_owner_entry(inst), offset))
	index = 0
	while index < len(hits):
		item = hits[index]
		write("  0x%08x in 0x%08x %s: %s" % (item[0], item[1], function_label(item[1]), RENDERER_DEVICE_METHODS[item[2]]))
		disasm_window(item[0], 14, 10, "provenance window for %s" % RENDERER_DEVICE_METHODS[item[2]])
		index += 1
	write("  Total +0x10F8-provenance calls: %d" % len(hits))

def scan_vertex_draw_virtual_calls():
	write("")
	write("=" * 70)
	write("VERTEX LAYOUT/STREAM/DRAW VTABLE-OFFSET CANDIDATES")
	write("=" * 70)
	write("These are exact call-target offsets but the receiver interface is not proven by offset alone.")
	write("Only candidates whose decompile proves D3D device lineage may be used as engine-contract evidence.")
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
		items = by_function.get(entry)
		if items is None:
			items = []
			by_function[entry] = items
		items.append(item)
	index = 0
	while index < len(hits):
		item = hits[index]
		write("  0x%08x in 0x%08x %s: %s" % (item[0], item[1], function_label(item[1]), D3D_VERTEX_METHODS[item[2]]))
		index += 1
	write("  Total retained virtual-call candidates: %d" % len(hits))
	method_offsets = total_by_method.keys()
	method_offsets.sort()
	index = 0
	while index < len(method_offsets):
		offset = method_offsets[index]
		write("  %-52s total=%d retained=%d" % (D3D_VERTEX_METHODS[offset], total_by_method[offset], retained_by_method.get(offset, 0)))
		index += 1
	write("")
	write("Strong draw-binder candidates with stream + layout + draw:")
	entries = by_function.keys()
	entries.sort()
	selected = 0
	index = 0
	while index < len(entries) and selected < MAX_BINDER_DECOMPILES:
		entry = entries[index]
		items = by_function[entry]
		function_method_offsets = {}
		item_index = 0
		while item_index < len(items):
			function_method_offsets[items[item_index][2]] = True
			item_index += 1
		has_draw = 0x144 in function_method_offsets or 0x148 in function_method_offsets
		has_stream = 0x190 in function_method_offsets
		has_layout = 0x15C in function_method_offsets or 0x164 in function_method_offsets
		if has_draw and has_stream and has_layout:
			write("  0x%08x %s methods=%s" % (entry, function_label(entry), str(function_method_offsets.keys())))
			decompile_at(entry, "strong vertex/draw binder %s" % function_label(entry), 30000)
			item_index = 0
			while item_index < len(items):
				disasm_window(items[item_index][0], 12, 10, D3D_VERTEX_METHODS[items[item_index][2]])
				item_index += 1
			selected += 1
		index += 1
	if selected == 0:
		write("  No single function contained all three method classes; use the full candidate list to follow wrapper boundaries.")
	index = 0
	while index < len(method_offsets):
		offset = method_offsets[index]
		if total_by_method[offset] > retained_by_method.get(offset, 0):
			write("  WARNING: %s candidates truncated at %d" % (D3D_VERTEX_METHODS[offset], MAX_VIRTUAL_HITS_PER_METHOD))
		index += 1

def scan_function_fields(addr_int, label, fields):
	write("")
	write("=" * 70)
	write("ORDERED FIELD/ROW HITS: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	func = function_at_or_containing(addr_int)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		index = 0
		while index < len(fields):
			if instruction_has_scalar(inst, fields[index]):
				write("  0x%08x value=0x%x %s" % (inst.getAddress().getOffset(), fields[index], inst.toString()))
				count += 1
				break
			index += 1
	write("  Total field/row hits: %d" % count)

def print_target_callsites(target_addr, label, max_count):
	write("")
	write("=" * 70)
	write("CALLSITES TO %s @ 0x%08x" % (label, target_addr))
	write("=" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(target_addr))
	count = 0
	while refs.hasNext() and count < max_count:
		ref = refs.next()
		if not ref.getReferenceType().isCall():
			continue
		call_addr = ref.getFromAddress().getOffset()
		write("  0x%08x in %s" % (call_addr, function_label(call_addr)))
		disasm_window(call_addr, 18, 18, "call to %s" % label)
		count += 1
	write("  Total printed callsites: %d" % count)

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

def run_windows():
	index = 0
	while index < len(FOCUS_WINDOWS):
		item = FOCUS_WINDOWS[index]
		disasm_window(item[0], item[1], item[2], item[3])
		index += 1

def run_field_scans():
	index = 0
	while index < len(FIELD_SCAN_TARGETS):
		item = FIELD_SCAN_TARGETS[index]
		scan_function_fields(item[0], item[1], item[2])
		index += 1

def run_bridge_callsites():
	print_target_callsites(0x00B9DFC0, "shadow candidate physical-slot setup", 24)
	print_target_callsites(0x00B67BE0, "PPLighting projected resource refresh", 32)
	print_target_callsites(0x00BA8C50, "pass-entry resource/argument attachment", 36)
	print_target_callsites(0x00B7DAB0, "PPLighting pass resource dispatcher", 24)
	print_target_callsites(0x00E7EA00, "pass-entry texture record resolver", 24)

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
	write("FNV PBR CONTINUITY DRAW/RESOURCE CONTRACT CLOSURE")
	write("Revision: focused cache-key and physical-slot follow-up")
	write("")
	write("Questions:")
	write("1. Which exact selector/pass-entry state distinguishes close exterior terrain from LandO, helpers, projected rows, TerrainFade, and interiors?")
	write("2. Where is the active pass entry/resource attached to the authoritative current geometry and NiD3DPass?")
	write("3. Which native functions bind vertex declaration/FVF, streams, indices, and draw for the same geometry path?")
	write("4. Can the close-terrain vertex ABI be recovered statically, or which exact binder must focused runtime capture observe?")
	write("5. How does the shadow candidate selected into physical slot 0x11..0x14 reach a PPLighting pass argument/resource?")
	write("6. How do projected rows 0x10..0x13 resolve that resource through E7EA00/E7EB00/E90B10 to final SetTexture?")
	write("7. Which SetTexture/state-block-looking calls have NiDX9RenderState +0x10F8 device provenance, and which are only offset collisions?")
	write("8. Does a stable builder-time owner/pass key survive through current NiD3DPass publication without a per-draw selector scan?")
	write("")
	write("The broad virtual-call scan requires exact call-operand dataflow but does not infer interface identity from an offset.")
	write("Physical slots 0x11..0x14, projected pass rows 0x10..0x13, and image-space IDs remain separate namespaces.")

def main():
	write_header()
	run_windows()
	run_raw_blocks()
	run_refs()
	run_field_scans()
	run_calls()
	run_bridge_callsites()
	scan_renderer_device_provenance()
	scan_vertex_draw_virtual_calls()
	run_focus_decompiles()
	checkpoint_output()
	write("")
	write("OUTPUT COMPLETE: %s (%d lines)" % (OUTPATH, len(output)))

try:
	main()
finally:
	checkpoint_output()
	decomp.dispose()
