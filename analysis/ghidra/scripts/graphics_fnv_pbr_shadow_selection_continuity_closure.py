# @category Analysis
# @description Close FNV shadow candidate ranking, four-slot continuity, camera provenance, and projected-shadow texture binding

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.block import BasicBlockModel
import struct

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)
block_model = BasicBlockModel(currentProgram)

output = []
decompile_cache = {}

OUTPATH = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_shadow_selection_continuity_closure.txt"

FRAME_TARGETS = [
	(0x008707C0, "shadow frame caller A"),
	(0x00870A00, "shadow frame caller B"),
	(0x00870BD0, "shadow frame caller C"),
	(0x00871260, "pre-shadow gate"),
	(0x00871290, "vanilla RenderShadowMaps selection and render owner"),
	(0x00871A10, "shadow-render enable gate"),
	(0x00871A30, "shadow candidate source-array accessor"),
	(0x00871A50, "post-shadow tail"),
]

SELECTION_TARGETS = [
	(0x00404010, "candidate scalar/vector operation"),
	(0x0043D450, "selection comparison vector source"),
	(0x00472380, "candidate source count"),
	(0x004EAF60, "special candidate eligibility"),
	(0x00500940, "fallback selection vector source"),
	(0x0050EA90, "candidate virtual argument source"),
	(0x00525420, "secondary shadow state gate"),
	(0x005BF770, "shadow state toggle"),
	(0x005BF7B0, "global shadow enabled state"),
	(0x005F36F0, "maximum-count branch selector"),
	(0x0084D030, "candidate threshold comparison primitive"),
	(0x0087F200, "candidate eligibility gate B"),
	(0x008C51C0, "candidate exclusion gate"),
	(0x00950090, "alternate special-candidate gate"),
	(0x00950BB0, "special candidate/render object source"),
	(0x009611E0, "candidate eligibility gate A"),
	(0x00979260, "assigned-shadow threshold comparator"),
	(0x00A5BDD0, "selection vector fallback decision"),
]

CANDIDATE_TARGETS = [
	(0x00B5A8D0, "shadow candidate unlink/remove"),
	(0x00B5A930, "shadow candidate collection search"),
	(0x00B5A980, "shadow candidate comparator"),
	(0x00B5ADE0, "shadow candidate erase variant A"),
	(0x00B5AEA0, "shadow candidate erase variant B"),
	(0x00B5AF30, "shadow source-to-record setup"),
	(0x00B5AFC0, "first renderable shadow candidate"),
	(0x00B5B010, "next renderable shadow candidate"),
	(0x00B5B060, "shadow candidate invalidation cleanup"),
	(0x00B5B1F0, "shadow rendered-texture cleanup"),
	(0x00B5B4D0, "shadow candidate metric producer A"),
	(0x00B5B610, "shadow candidate metric producer B"),
	(0x00B5B880, "shadow candidate publication/final pass"),
	(0x00B5BCA0, "shadow candidate score producer"),
	(0x00B5C360, "shadow dependent-array append/resize"),
	(0x00B5C3C0, "shadow candidate owner reset"),
	(0x00B5CBD0, "shadow candidate find/create"),
	(0x00B5CDE0, "shadow candidate ranking/replacement/fade"),
	(0x00B5D040, "shadow candidate list/refcount transfer"),
	(0x00B5D270, "shadow candidate update"),
	(0x00B5D300, "shadow candidate render-list construction"),
	(0x00B702E0, "generic list insertion/splice"),
	(0x00B9DCB0, "shadow candidate initialization"),
	(0x00B9FDA0, "0x250-byte shadow candidate constructor"),
	(0x00A5A310, "shadow candidate ownership insertion"),
	(0x00C1B4A0, "shadow list copy/anchor initialization"),
]

SLOT_RENDER_TARGETS = [
	(0x004EA970, "shadow slot/channel object accessor"),
	(0x00BA30F0, "shadow slot mode-0 operation"),
	(0x00BA3130, "shadow slot mode-1 operation"),
	(0x00B9D150, "shadow camera transform/setup"),
	(0x00B9DFC0, "shadow candidate slot setup"),
	(0x00B9E970, "shadow scene render"),
	(0x00B9EF30, "rejected shadow candidate cleanup"),
	(0x00B9F780, "shadow-map rendering and postprocess"),
	(0x00B9FBA0, "shadow renderer state finalization"),
	(0x00BA0110, "shadow render-object collection insertion"),
	(0x00BA02B0, "shadow render collection finalization"),
	(0x00B6B260, "rendered texture acquisition"),
	(0x00B6B8D0, "offscreen rendering start"),
	(0x00B6B790, "offscreen rendering stop"),
	(0x00B6C0D0, "camera/render-target association"),
	(0x00B6D3F0, "render target/depth helper"),
	(0x00B6D4C0, "rendered texture release"),
	(0x00B97550, "shadow image-space effect application"),
]

PROJECTED_BRIDGE_TARGETS = [
	(0x00A59D30, "active texture/property fallback"),
	(0x00B55560, "shader-interface object selector"),
	(0x00B67BE0, "PPLighting updater and projected resource refresh"),
	(0x00BA8C50, "pass light/resource attachment"),
	(0x00BA8EC0, "pass-entry storage"),
	(0x00BA9EE0, "pass-entry construction"),
	(0x00B7B930, "PPLighting texture interface helper"),
	(0x00B7DAB0, "PPLighting pass resource dispatcher"),
	(0x00B7DD50, "PPLighting texture-record helper A"),
	(0x00B7DDE0, "PPLighting interface apply A"),
	(0x00B7DED0, "PPLighting interface apply B"),
	(0x00B7DFE0, "PPLighting interface apply C"),
	(0x00B7E150, "PPLighting interface apply D"),
	(0x00B7E430, "PPLighting constant-map initialization"),
	(0x00B79950, "LandLOD projected-shadow shader interface"),
	(0x00B80600, "close-land projected-shadow shader interface"),
	(0x00BDA060, "related projected resource pass helper"),
	(0x00BDE170, "adjacent projected pass family"),
	(0x00BDF650, "projected-shadow rows 0x10 through 0x13"),
	(0x00BC3E40, "alternate projected-shadow pass caller"),
	(0x00BD22C0, "final optional shader-interface path"),
	(0x00BEBD20, "LandLOD projected-shadow family owner"),
	(0x00BFC860, "close-land projected-shadow family owner"),
	(0x00E7EA00, "low-level texture record dispatcher"),
	(0x00E7EB00, "texture record apply"),
	(0x00E826D0, "shader-interface texture apply bridge"),
	(0x00E88A20, "NiDX9RenderState SetTexture"),
	(0x00E90B10, "source texture data resolver"),
]

RAW_FUNCTIONS = [
	(0x00871290, "vanilla RenderShadowMaps"),
	(0x00B5CBD0, "shadow candidate find/create"),
	(0x00B5CDE0, "shadow candidate ranking/replacement/fade"),
	(0x00B5B880, "shadow candidate publication"),
	(0x00B9F780, "shadow-map rendering and postprocess"),
	(0x00BDF650, "projected-shadow pass row construction"),
	(0x00B67BE0, "projected-shadow cached resource refresh"),
]

CALLSITE_TARGETS = [
	(0x00871290, "RenderShadowMaps"),
	(0x00B5CBD0, "candidate find/create"),
	(0x00B5CDE0, "candidate ranking/replacement/fade"),
	(0x00B5D300, "candidate render-list construction"),
	(0x00B9F780, "shadow-map render"),
	(0x00BDF650, "projected-shadow pass helper"),
	(0x00E88A20, "final SetTexture"),
]

GLOBAL_TARGETS = [
	(0x011AD834, "shadow transition global A"),
	(0x011AD838, "shadow transition global B"),
	(0x011F426C, "fallback selection vector"),
	(0x011F4748, "active renderer/camera owner"),
	(0x011F917C, "active renderer camera state"),
	(0x011F91C8, "active PPLighting transform state"),
	(0x0126F74C, "current NiD3DPass"),
	(0x011FDE70, "LandLOD projected-shadow VS slot 5"),
	(0x011FDB20, "LandLOD projected-shadow PS slot 6"),
	(0x011FDF30, "close-land projected-shadow VS slot 53"),
	(0x011FDBF8, "close-land projected-shadow PS slot 60"),
	(0x011FDF34, "close-land alpha projected-shadow VS slot 54"),
	(0x011FDBFC, "close-land alpha projected-shadow PS slot 61"),
]

CONSTANT_TARGETS = [
	(0x01021928, "shadow selection scale"),
	(0x01082CB0, "assigned-shadow comparison threshold"),
	(0x0103C7C8, "shadow constant candidate A"),
	(0x0106B9E8, "shadow constant candidate B"),
	(0x0101FFA0, "shared floating constant"),
	(0x011AD834, "shadow transition global A"),
	(0x011AD838, "shadow transition global B"),
]

SHADOW_SETTING_TARGETS = [
	(0x00F3FEB0, "iShadowMode Display setting"),
	(0x00F40C10, "fShadowLODStartFade Display setting"),
	(0x00F40C50, "fShadowLODRange Display setting"),
	(0x00F40C80, "fShadowLODMinStartFade Display setting"),
	(0x00F40CB0, "fShadowLODMaxStartFade Display setting"),
	(0x00F410E0, "bActorSelfShadowing Display setting"),
	(0x00F41140, "iShadowMapResolution Display setting"),
	(0x00F411A0, "iShadowFilter Display setting"),
	(0x00F41410, "fShadowFadeTime Display setting"),
]

OWNER_FIELDS = [0xC0, 0xC4, 0xC8, 0xCC, 0xD0, 0xD4, 0xD8, 0xDC, 0x128, 0x1E0]
CANDIDATE_FIELDS = [0xD8, 0xDC, 0xF8, 0x104, 0x10C, 0x110, 0x124, 0x128, 0x140, 0x1A0, 0x208, 0x20C, 0x210, 0x214, 0x218, 0x21C, 0x220, 0x224, 0x228, 0x22C, 0x230, 0x234, 0x238, 0x23C, 0x240]

FOCUS_WINDOWS = [
	(0x008713B2, 32, 42, "configured/effective shadow maximum"),
	(0x00871439, 32, 52, "source candidate enumeration and admission cap"),
	(0x00871480, 24, 36, "candidate owner synchronization"),
	(0x008715E0, 30, 50, "candidate distance/rank threshold"),
	(0x00871712, 28, 52, "renderable candidate iteration and cap"),
	(0x00871880, 32, 64, "slot assignment and render dispatch"),
	(0x00871970, 20, 48, "unused slot cleanup"),
	(0x00B67CD0, 24, 36, "projected-shadow helper call A"),
	(0x00B68337, 24, 36, "projected-shadow helper call B"),
	(0x00BC42EA, 24, 36, "projected-shadow helper call C"),
	(0x00BEDA6D, 20, 28, "LandLOD projected-shadow VS apply"),
	(0x00BEDA7A, 20, 28, "LandLOD projected-shadow PS apply"),
	(0x00BFD7AB, 20, 36, "close-land projected-shadow VS apply"),
	(0x00BFD7E0, 20, 36, "close-land projected-shadow PS apply"),
	(0x00C006C0, 20, 28, "close-land alpha projected-shadow VS apply"),
	(0x00C006CE, 20, 28, "close-land alpha projected-shadow PS apply"),
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

def function_label(addr_int):
	func = function_at_or_containing(addr_int)
	if func is None:
		return "unknown"
	entry = func.getEntryPoint().getOffset()
	if entry == addr_int:
		return func.getName()
	return "%s+0x%x" % (func.getName(), addr_int - entry)

def read_u8(addr_int):
	try:
		return memory.getByte(toAddr(addr_int)) & 0xff
	except:
		return None

def read_u32(addr_int):
	try:
		return memory.getInt(toAddr(addr_int)) & 0xffffffff
	except:
		return None

def read_bytes(addr_int, count):
	values = []
	index = 0
	while index < count:
		value = read_u8(addr_int + index)
		if value is None:
			return None
		values.append(value)
		index += 1
	return values

def decode_float(addr_int):
	values = read_bytes(addr_int, 4)
	if values is None:
		return None
	try:
		return struct.unpack("<f", "".join([chr(value) for value in values]))[0]
	except:
		return None

def decode_double(addr_int):
	values = read_bytes(addr_int, 8)
	if values is None:
		return None
	try:
		return struct.unpack("<d", "".join([chr(value) for value in values]))[0]
	except:
		return None

def instruction_bytes(inst):
	try:
		values = inst.getBytes()
		parts = []
		index = 0
		while index < len(values):
			parts.append("%02x" % (values[index] & 0xff))
			index += 1
		return " ".join(parts)
	except:
		return "??"

def outgoing_refs_text(inst):
	parts = []
	refs = inst.getReferencesFrom()
	for ref in refs:
		target = ref.getToAddress()
		if target is not None:
			parts.append("%s->0x%08x" % (str(ref.getReferenceType()), target.getOffset()))
	return ", ".join(parts)

def decompile_text(addr_int):
	func = function_at_or_containing(addr_int)
	if func is None:
		return None
	entry = func.getEntryPoint().getOffset()
	if decompile_cache.has_key(entry):
		return decompile_cache[entry]
	result = decomp.decompileFunction(func, 180, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		decompile_cache[entry] = code
		return code
	decompile_cache[entry] = None
	return None

def decompile_at(addr_int, label, max_len=1000000):
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
	write("  Decompiled characters: %d" % len(code))
	if len(code) > max_len:
		write(code[:max_len])
		write("  [decompile truncated from %d characters]" % len(code))
	else:
		write(code)

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
		text = inst.toString() if inst is not None else ""
		write("  %s @ 0x%08x (in %s) %s" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname, text))
		count += 1
		if count >= 240:
			write("  ... (truncated)")
			break
	write("  Total printed refs: %d" % count)

def find_and_print_calls_from(addr_int, label):
	func = function_at_or_containing(addr_int)
	if func is None:
		write("  [function not found at 0x%08x]" % addr_int)
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	write("")
	write("--- Calls FROM %s (0x%08x) ---" % (label, addr_int))
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				target = ref.getToAddress().getOffset()
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), target, function_label(target)))
				count += 1
	write("  Total: %d calls" % count)

def print_full_function_disassembly(addr_int, label):
	func = function_at_or_containing(addr_int)
	write("")
	write("=" * 70)
	write("RAW FUNCTION: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	if func is None:
		write("  [function not found]")
		return
	entry = func.getEntryPoint().getOffset()
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		address = inst.getAddress().getOffset()
		write("  0x%08x +0x%04x  %-24s %-46s %s" % (address, address - entry, instruction_bytes(inst), inst.toString(), outgoing_refs_text(inst)))
		count += 1
	write("  Total instructions: %d" % count)

def print_function_cfg(addr_int, label):
	func = function_at_or_containing(addr_int)
	write("")
	write("=" * 70)
	write("CONTROL FLOW: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	if func is None:
		write("  [function not found]")
		return
	blocks = block_model.getCodeBlocksContaining(func.getBody(), monitor)
	count = 0
	while blocks.hasNext():
		block = blocks.next()
		start = block.getFirstStartAddress().getOffset()
		end = block.getMaxAddress().getOffset()
		flow = str(block.getFlowType())
		parts = []
		destinations = block.getDestinations(monitor)
		while destinations.hasNext():
			destination = destinations.next()
			target = destination.getDestinationAddress()
			if target is not None:
				parts.append("0x%08x/%s" % (target.getOffset(), str(destination.getFlowType())))
		write("  block %03d 0x%08x..0x%08x flow=%s successors=%s" % (count, start, end, flow, ", ".join(parts)))
		last = listing.getInstructionAt(block.getMaxAddress())
		if last is None:
			last = listing.getInstructionBefore(block.getMaxAddress())
		if last is not None:
			write("    terminal: 0x%08x %-24s %s" % (last.getAddress().getOffset(), instruction_bytes(last), last.toString()))
		count += 1
	write("  Total blocks: %d" % count)

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

def disasm_window(center_int, before_count, after_count, label):
	write("")
	write("-" * 70)
	write("DISASM WINDOW: %s around 0x%08x" % (label, center_int))
	write("-" * 70)
	inst = listing.getInstructionContaining(toAddr(center_int))
	if inst is None:
		write("  [instruction not found]")
		return
	current = instruction_before_steps(inst, before_count)
	index = 0
	limit = before_count + after_count + 1
	while current is not None and index < limit:
		address = current.getAddress().getOffset()
		marker = " << TARGET" if address == center_int else ""
		write("  0x%08x  %-24s %-46s %s%s" % (address, instruction_bytes(current), current.toString(), outgoing_refs_text(current), marker))
		current = listing.getInstructionAfter(current.getAddress())
		index += 1

def print_callers_with_windows(addr_int, label):
	write("")
	write("=" * 70)
	write("CALLERS: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		if not ref.getReferenceType().isCall():
			continue
		source = ref.getFromAddress().getOffset()
		func = fm.getFunctionContaining(ref.getFromAddress())
		name = func.getName() if func is not None else "???"
		write("  Caller %d: 0x%08x in %s" % (count + 1, source, name))
		disasm_window(source, 20, 24, "call to %s" % label)
		count += 1
		if count >= 80:
			write("  ... caller scan truncated")
			break
	write("  Total callers printed: %d" % count)

def scalar_values_for_instruction(inst):
	values = []
	op_index = 0
	while op_index < inst.getNumOperands():
		objects = inst.getOpObjects(op_index)
		object_index = 0
		while object_index < len(objects):
			obj = objects[object_index]
			try:
				values.append(obj.getValue() & 0xffffffff)
			except:
				pass
			object_index += 1
		op_index += 1
	return values

def print_field_scalar_hits(addr_int, label):
	func = function_at_or_containing(addr_int)
	write("")
	write("OWNER/CANDIDATE FIELD-SCALAR CANDIDATES: %s @ 0x%08x" % (label, addr_int))
	if func is None:
		write("  [function not found]")
		return
	fields = OWNER_FIELDS + CANDIDATE_FIELDS
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		values = scalar_values_for_instruction(inst)
		field_index = 0
		while field_index < len(fields):
			field = fields[field_index]
			if field in values:
				write("  +0x%03x candidate @ 0x%08x: %-24s %s" % (field, inst.getAddress().getOffset(), instruction_bytes(inst), inst.toString()))
				count += 1
			field_index += 1
	write("  Total candidates: %d" % count)
	write("  NOTE: Receiver provenance must separate owner, candidate, stack, and unrelated object offsets.")

def print_constant_value(addr_int, label):
	values = read_bytes(addr_int, 8)
	raw = "unreadable"
	if values is not None:
		raw = " ".join(["%02x" % value for value in values])
	write("  0x%08x %-42s raw=%s u32=%s float=%s double=%s" % (addr_int, label, raw, str(read_u32(addr_int)), str(decode_float(addr_int)), str(decode_double(addr_int))))

def is_executable_address(addr_int):
	try:
		block = memory.getBlock(toAddr(addr_int))
		return block is not None and block.isExecute()
	except:
		return False

def vtable_candidate_has_executable_neighbors(base_int):
	offsets = [0x1C8, 0x1CC, 0x1D0, 0x1D4, 0x20C, 0x210, 0x214, 0x218]
	valid = 0
	index = 0
	while index < len(offsets):
		target = read_u32(base_int + offsets[index])
		if target is not None and is_executable_address(target):
			valid += 1
		index += 1
	return valid >= 6

def discover_candidate_vtables():
	write("")
	write("=" * 70)
	write("DYNAMIC VTABLE DISCOVERY FOR +0x1D0 AND +0x214")
	write("=" * 70)
	start = 0x01000000
	end = 0x01100000
	address = start
	count = 0
	while address + 0x218 < end:
		first = read_u32(address + 0x1D0)
		second = read_u32(address + 0x214)
		if first is not None and second is not None and is_executable_address(first) and is_executable_address(second):
			if vtable_candidate_has_executable_neighbors(address):
				write("  candidate vtable 0x%08x: +1D0=0x%08x %s +214=0x%08x %s" % (address, first, function_label(first), second, function_label(second)))
				find_refs_to(address, "candidate vtable with +1D0/+214")
				decompile_at(first, "candidate virtual +0x1D0")
				decompile_at(second, "candidate virtual +0x214")
				count += 1
				if count >= 48:
					write("  ... vtable discovery truncated")
					break
		address += 4
	write("  Total candidate vtables: %d" % count)

def find_shadow_strings():
	write("")
	write("=" * 70)
	write("SHADOW SETTING/STRING PROVENANCE")
	write("=" * 70)
	data_iter = listing.getDefinedData(True)
	count = 0
	while data_iter.hasNext():
		data = data_iter.next()
		value = data.getValue()
		if value is None:
			continue
		text = str(value)
		lower = text.lower()
		if lower.find("shadow") < 0:
			continue
		if lower.find("count") < 0 and lower.find("max") < 0 and lower.find("fade") < 0 and lower.find("actor") < 0 and lower.find("mode") < 0:
			continue
		address = data.getAddress().getOffset()
		write("  string 0x%08x: %s" % (address, text))
		find_refs_to(address, "shadow-related string")
		count += 1
		if count >= 100:
			write("  ... shadow string scan truncated")
			break
	write("  Total shadow-related strings: %d" % count)

def audit_target_list(targets, include_fields):
	index = 0
	while index < len(targets):
		item = targets[index]
		find_refs_to(item[0], item[1])
		decompile_at(item[0], item[1])
		find_and_print_calls_from(item[0], item[1])
		if include_fields:
			print_field_scalar_hits(item[0], item[1])
		checkpoint_output()
		index += 1

def audit_raw_functions():
	index = 0
	while index < len(RAW_FUNCTIONS):
		item = RAW_FUNCTIONS[index]
		print_full_function_disassembly(item[0], item[1])
		print_function_cfg(item[0], item[1])
		checkpoint_output()
		index += 1

def audit_callers():
	index = 0
	while index < len(CALLSITE_TARGETS):
		item = CALLSITE_TARGETS[index]
		print_callers_with_windows(item[0], item[1])
		checkpoint_output()
		index += 1

def audit_globals():
	index = 0
	while index < len(GLOBAL_TARGETS):
		item = GLOBAL_TARGETS[index]
		find_refs_to(item[0], item[1])
		index += 1

def audit_constants():
	write("")
	write("=" * 70)
	write("SHADOW FLOATING CONSTANT DECODING")
	write("=" * 70)
	index = 0
	while index < len(CONSTANT_TARGETS):
		item = CONSTANT_TARGETS[index]
		print_constant_value(item[0], item[1])
		index += 1

def audit_setting_targets():
	index = 0
	while index < len(SHADOW_SETTING_TARGETS):
		item = SHADOW_SETTING_TARGETS[index]
		find_refs_to(item[0], item[1])
		decompile_at(item[0], item[1])
		index += 1

def audit_focus_windows():
	index = 0
	while index < len(FOCUS_WINDOWS):
		item = FOCUS_WINDOWS[index]
		disasm_window(item[0], item[1], item[2], item[3])
		index += 1

def print_questions():
	write("FNV PBR SHADOW SELECTION CONTINUITY CLOSURE")
	write("")
	write("Required closure:")
	write("1. Prove source candidate ownership, filtering, rank inputs, and configured/effective cap.")
	write("2. Prove candidate list topology and every keep/remove/move/replace/fade action.")
	write("3. Recover x87 comparisons and equality behavior in FUN_00B5CDE0 from raw instructions.")
	write("4. Separate selection-distance, shadow-render, and active renderer camera provenance.")
	write("5. Prove ownership and cleanup of physical slots 0x11 through 0x14.")
	write("6. Trace camera +0x1A0 through projected rows 0x10 through 0x13 to final D3D sampler.")
	write("7. Determine whether candidate replacement is continuous and identify a safe fix point if not.")
	write("")
	write("Do not conflate physical slot 0x11, PPLighting row 0x11, and image-space effect ID 0x11.")

def main():
	print_questions()
	audit_constants()
	audit_globals()
	checkpoint_output()
	audit_target_list(FRAME_TARGETS, False)
	audit_target_list(SELECTION_TARGETS, False)
	audit_target_list(CANDIDATE_TARGETS, True)
	audit_target_list(SLOT_RENDER_TARGETS, True)
	audit_target_list(PROJECTED_BRIDGE_TARGETS, False)
	audit_raw_functions()
	audit_callers()
	audit_focus_windows()
	audit_setting_targets()
	find_shadow_strings()
	checkpoint_output()
	discover_candidate_vtables()
	checkpoint_output()
	write("")
	write("OUTPUT COMPLETE: %s (%d lines)" % (OUTPATH, len(output)))

try:
	main()
finally:
	checkpoint_output()
	decomp.dispose()
