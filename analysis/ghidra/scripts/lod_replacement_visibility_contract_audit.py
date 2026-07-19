# @category Analysis
# @description Prove the FNV near-cell versus distant LOD visibility, attachment, fade, frame-phase, and fallback contract

from ghidra.app.decompiler import DecompInterface
import re

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []
decompiled = {}

REPLACEMENT_RTTI = [
	(0x01184D5C, "ExtraDistantData", 16, 0x01015C84),
	(0x01185714, "AttachDistant3DTask", 20, 0x01016BEC),
	(0x011A3038, "BSFadeNodeCuller", 24, 0x01082CCC),
	(0x011ABC00, "NiSwitchNode", 48, 0x010A001C),
	(0x011ABCC0, "NiScreenLODData", 24, 0x010A051C),
	(0x011ABCE0, "NiLODData", 24, 0x010A2254),
	(0x011ABD18, "NiRangeLODData", 24, 0x010A073C),
	(0x011ABDF8, "NiLODNode", 48, 0x010A0B64),
]

ROOT_GLOBALS = [
	(0x011DEA14, "LODRoot"),
	(0x011AD808, "value published immediately after LandLOD root creation; identity to prove"),
	(0x011DEA18, "ObjectLODRoot"),
	(0x011DEA1C, "WaterLOD root"),
	(0x011D8A80, "active BSSceneGraph root"),
]

LOD_SETTING_INITIALIZERS = [
	(0x00F37F30, "fLODBoundRadiusMult"),
	(0x00F37F60, "fLODFadeOutPercent"),
	(0x00F38AE0, "fLODFadeOutMultActors"),
	(0x00F38B10, "fLODFadeOutMultItems"),
	(0x00F38B40, "fLODFadeOutMultObjects"),
	(0x00F819E0, "fLodDistance"),
	(0x00FA2B50, "fLODLandVerticalBias"),
	(0x00FA2C10, "fLODLandDropAmount"),
	(0x00FA2C70, "fLODFadeOutObjectMultComplex"),
	(0x00FA2CA0, "fLODFadeOutItemMultComplex"),
	(0x00FA2CD0, "fLODFadeOutActorMultComplex"),
	(0x00FA2D00, "fLODFadeOutObjectMultCity"),
	(0x00FA2D30, "fLODFadeOutItemMultCity"),
	(0x00FA2D60, "fLODFadeOutActorMultCity"),
	(0x00FA2D90, "fLODFadeOutObjectMultInterior"),
	(0x00FA2DC0, "fLODFadeOutItemMultInterior"),
	(0x00FA2DF0, "fLODFadeOutActorMultInterior"),
]

SETTING_STRING_PATTERNS = [
	"ugridstoload",
	"uexterior cell buffer",
	"uexteriorcellbuffer",
	"ffadeintime:lod",
	"ffadeouttime:lod",
	"flodfade",
	"floddistance",
	"flodmulttrees",
]

RELEVANT_RANGES = [
	(0x00440000, 0x00470000),
	(0x00520000, 0x00590000),
	(0x006E0000, 0x00720000),
	(0x007F0000, 0x00890000),
	(0x00900000, 0x00980000),
	(0x00A50000, 0x00A70000),
	(0x00B40000, 0x00BD0000),
	(0x00C3C000, 0x00C50000),
]

FOLLOW_CALLEE_TYPES = {
	"AttachDistant3DTask": True,
	"BSFadeNode": True,
}

FIELD_SCAN_RANGES = [
	(0x00440000, 0x00470000),
	(0x00520000, 0x00590000),
	(0x006E0000, 0x00720000),
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

def read_u32(addr_int):
	try:
		return memory.getInt(toAddr(addr_int)) & 0xffffffff
	except:
		return None

def read_ascii(addr_int, max_len):
	chars = []
	idx = 0
	while idx < max_len:
		try:
			value = memory.getByte(toAddr(addr_int + idx)) & 0xff
		except:
			break
		if value == 0:
			break
		if value < 0x20 or value > 0x7e:
			chars.append("?")
		else:
			chars.append(chr(value))
		idx += 1
	return "".join(chars)

def function_in_ranges(addr_int, ranges):
	idx = 0
	while idx < len(ranges):
		item = ranges[idx]
		if item[0] <= addr_int < item[1]:
			return True
		idx += 1
	return False

def decompile_once(addr_int, label, max_len):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	if func is None:
		decompile_at(addr_int, label, max_len)
		return
	entry = func.getEntryPoint().getOffset()
	if entry in decompiled:
		write("  [already decompiled 0x%08x as %s]" % (entry, decompiled[entry]))
		return
	decompiled[entry] = label
	decompile_at(entry, label, max_len)

def collect_ref_functions(addr_int, calls_only):
	functions = {}
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	while refs.hasNext():
		ref = refs.next()
		if calls_only and not ref.getReferenceType().isCall():
			continue
		func = fm.getFunctionContaining(ref.getFromAddress())
		if func is not None:
			functions[func.getEntryPoint().getOffset()] = True
	return sorted(functions.keys())

def collect_callees(addr_int, ranges):
	functions = {}
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	if func is None:
		return []
	inst_iter = listing.getInstructions(func.getBody(), True)
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if not ref.getReferenceType().isCall():
				continue
			target = ref.getToAddress().getOffset()
			target_func = fm.getFunctionAt(toAddr(target))
			if target_func is None:
				continue
			entry = target_func.getEntryPoint().getOffset()
			if function_in_ranges(entry, ranges):
				functions[entry] = True
	return sorted(functions.keys())

def collect_data_targets(addr_int):
	targets = {}
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	if func is None:
		return []
	inst_iter = listing.getInstructions(func.getBody(), True)
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				continue
			target = ref.getToAddress().getOffset()
			if 0x01100000 <= target < 0x01300000 and target != 0x011C16BC:
				targets[target] = True
	return sorted(targets.keys())

def find_pointer_words(value, max_hits):
	hits = []
	addr_int = 0x01000000
	while addr_int < 0x01280000 and len(hits) < max_hits:
		if read_u32(addr_int) == value:
			hits.append(addr_int)
		addr_int += 4
	return hits

def collect_pointer_sources(value, max_hits):
	sources = {}
	refs = ref_mgr.getReferencesTo(toAddr(value))
	while refs.hasNext():
		ref = refs.next()
		source = ref.getFromAddress().getOffset()
		if read_u32(source) == value:
			sources[source] = True
	if len(sources) == 0:
		fallback = find_pointer_words(value, max_hits)
		idx = 0
		while idx < len(fallback):
			sources[fallback[idx]] = True
			idx += 1
	return sorted(sources.keys())

def collect_rtti_vtables(rtti_addr):
	vtables = {}
	type_source_map = {}
	type_sources = collect_pointer_sources(rtti_addr, 80)
	idx = 0
	while idx < len(type_sources):
		type_source_map[type_sources[idx]] = True
		idx += 1
	fallback = find_pointer_words(rtti_addr, 80)
	idx = 0
	while idx < len(fallback):
		type_source_map[fallback[idx]] = True
		idx += 1
	type_sources = sorted(type_source_map.keys())
	idx = 0
	while idx < len(type_sources):
		type_source = type_sources[idx]
		col = type_source - 12
		if read_u32(col + 12) == rtti_addr:
			col_source_map = {}
			col_sources = collect_pointer_sources(col, 40)
			jdx = 0
			while jdx < len(col_sources):
				col_source_map[col_sources[jdx]] = True
				jdx += 1
			fallback = find_pointer_words(col, 40)
			jdx = 0
			while jdx < len(fallback):
				col_source_map[fallback[jdx]] = True
				jdx += 1
			col_sources = sorted(col_source_map.keys())
			jdx = 0
			while jdx < len(col_sources):
				vtable = col_sources[jdx] + 4
				first = read_u32(vtable)
				if first is not None and 0x00400000 <= first < 0x01000000:
					vtables[vtable] = True
				jdx += 1
		idx += 1
	return sorted(vtables.keys())

def print_vtable(vtable, label, max_slots):
	methods = []
	write("")
	write("-" * 70)
	write("%s vtable @ 0x%08x" % (label, vtable))
	write("-" * 70)
	idx = 0
	while idx < max_slots:
		target = read_u32(vtable + idx * 4)
		if target is None:
			write("  [%02d] unreadable" % idx)
			break
		func = fm.getFunctionAt(toAddr(target))
		if func is None:
			func = fm.getFunctionContaining(toAddr(target))
		name = func.getName() if func is not None else "???"
		write("  [%02d] +0x%02x -> 0x%08x %s" % (idx, idx * 4, target, name))
		if 0x00400000 <= target < 0x01000000:
			methods.append(target)
		elif idx >= 5:
			break
		idx += 1
	return methods

def decompile_callers(addr_int, label, max_functions, max_len):
	callers = collect_ref_functions(addr_int, True)
	idx = 0
	while idx < len(callers) and idx < max_functions:
		entry = callers[idx]
		decompile_once(entry, "%s caller %d" % (label, idx + 1), max_len)
		find_and_print_calls_from(entry, "%s caller %d" % (label, idx + 1))
		idx += 1
	write("  Caller functions considered: %d of %d" % (idx, len(callers)))

def decompile_relevant_callees(addr_int, label, max_functions, max_len):
	callees = collect_callees(addr_int, RELEVANT_RANGES)
	idx = 0
	while idx < len(callees) and idx < max_functions:
		decompile_once(callees[idx], "%s relevant callee %d" % (label, idx + 1), max_len)
		find_and_print_calls_from(callees[idx], "%s relevant callee %d" % (label, idx + 1))
		idx += 1
	write("  Relevant callees considered: %d of %d" % (idx, len(callees)))

def audit_rtti_type(rtti_addr, label, max_slots, seed_vtable):
	write("")
	write("#" * 70)
	write("REPLACEMENT TYPE: %s" % label)
	write("#" * 70)
	write("  RTTI name: %s" % read_ascii(rtti_addr + 8, 120))
	find_refs_to(rtti_addr, "%s RTTI type descriptor" % label)
	vtable_map = {}
	vtables = collect_rtti_vtables(rtti_addr)
	vidx = 0
	while vidx < len(vtables):
		vtable_map[vtables[vidx]] = True
		vidx += 1
	vtable_map[seed_vtable] = True
	vtables = sorted(vtable_map.keys())
	write("  Resolved vtables: %d" % len(vtables))
	vidx = 0
	while vidx < len(vtables):
		vtable = vtables[vidx]
		methods = print_vtable(vtable, label, max_slots)
		writers = collect_ref_functions(vtable, False)
		widx = 0
		while widx < len(writers) and widx < 12:
			writer = writers[widx]
			decompile_once(writer, "%s constructor or vtable writer %d" % (label, widx + 1), 40000)
			find_and_print_calls_from(writer, "%s constructor or vtable writer %d" % (label, widx + 1))
			decompile_callers(writer, "%s producer" % label, 12, 40000)
			widx += 1
		midx = 0
		while midx < len(methods):
			decompile_once(methods[midx], "%s vtable slot %d" % (label, midx), 50000)
			find_and_print_calls_from(methods[midx], "%s vtable slot %d" % (label, midx))
			if label in FOLLOW_CALLEE_TYPES:
				decompile_relevant_callees(methods[midx], "%s vtable slot %d" % (label, midx), 16, 40000)
			midx += 1
		vidx += 1

def audit_all_rtti_types():
	idx = 0
	while idx < len(REPLACEMENT_RTTI):
		item = REPLACEMENT_RTTI[idx]
		audit_rtti_type(item[0], item[1], item[2], item[3])
		idx += 1

def audit_seed_vtable(vtable, label, max_slots):
	write("")
	write("#" * 70)
	write("SEEDED VTABLE TYPE: %s" % label)
	write("#" * 70)
	methods = print_vtable(vtable, label, max_slots)
	writers = collect_ref_functions(vtable, False)
	widx = 0
	while widx < len(writers) and widx < 12:
		writer = writers[widx]
		decompile_once(writer, "%s constructor or vtable writer %d" % (label, widx + 1), 40000)
		find_and_print_calls_from(writer, "%s constructor or vtable writer %d" % (label, widx + 1))
		decompile_callers(writer, "%s producer" % label, 12, 40000)
		widx += 1
	midx = 0
	while midx < len(methods):
		decompile_once(methods[midx], "%s vtable slot %d" % (label, midx), 50000)
		find_and_print_calls_from(methods[midx], "%s vtable slot %d" % (label, midx))
		if label in FOLLOW_CALLEE_TYPES:
			decompile_relevant_callees(methods[midx], "%s vtable slot %d" % (label, midx), 16, 40000)
		midx += 1

def valid_col(col):
	if col is None or not (0x01000000 <= col < 0x01280000):
		return False
	type_desc = read_u32(col + 12)
	if type_desc is None or not (0x01000000 <= type_desc < 0x01280000):
		return False
	name = read_ascii(type_desc + 8, 8)
	return name.startswith(".?")

def find_vtable_base_from_slot(slot_addr):
	candidate = slot_addr
	steps = 0
	while steps < 96 and candidate >= 0x01000004:
		col = read_u32(candidate - 4)
		first = read_u32(candidate)
		if valid_col(col) and first is not None and 0x00400000 <= first < 0x01000000:
			return candidate
		candidate -= 4
		steps += 1
	return None

def find_exact_string_addresses(name):
	addresses = []
	data_iter = listing.getDefinedData(True)
	while data_iter.hasNext():
		data = data_iter.next()
		try:
			if not data.hasStringValue():
				continue
			value = str(data.getValue())
		except:
			continue
		if value == name:
			addresses.append(data.getAddress().getOffset())
	return addresses

def audit_nirtti_name(name):
	write("")
	write("#" * 70)
	write("NI RTTI AND VTABLE DISCOVERY: %s" % name)
	write("#" * 70)
	strings = find_exact_string_addresses(name)
	idx = 0
	while idx < len(strings):
		string_addr = strings[idx]
		find_refs_to(string_addr, "%s NiRTTI name" % name)
		name_sources = collect_pointer_sources(string_addr, 40)
		jdx = 0
		while jdx < len(name_sources):
			nirtti = name_sources[jdx]
			write("  Candidate NiRTTI object: 0x%08x" % nirtti)
			getters = collect_ref_functions(nirtti, False)
			gidx = 0
			while gidx < len(getters):
				getter = getters[gidx]
				decompile_once(getter, "%s GetRTTI candidate" % name, 20000)
				getter_sources = collect_pointer_sources(getter, 80)
				sidx = 0
				while sidx < len(getter_sources):
					slot = getter_sources[sidx]
					vtable = find_vtable_base_from_slot(slot)
					if vtable is not None:
						methods = print_vtable(vtable, "%s discovered through NiRTTI" % name, 48)
						midx = 0
						while midx < len(methods):
							decompile_once(methods[midx], "%s discovered vtable slot %d" % (name, midx), 50000)
							find_and_print_calls_from(methods[midx], "%s discovered vtable slot %d" % (name, midx))
							midx += 1
					sidx += 1
				gidx += 1
			jdx += 1
		idx += 1
	write("  Exact NiRTTI name strings found: %d" % len(strings))

def audit_root_consumers():
	write("")
	write("#" * 70)
	write("LOD ROOT PUBLICATION, MUTATION, CULL, AND DRAW CONSUMERS")
	write("#" * 70)
	idx = 0
	while idx < len(ROOT_GLOBALS):
		item = ROOT_GLOBALS[idx]
		find_refs_to(item[0], item[1])
		functions = collect_ref_functions(item[0], False)
		jdx = 0
		printed = 0
		while jdx < len(functions) and printed < 24:
			entry = functions[jdx]
			if function_in_ranges(entry, RELEVANT_RANGES):
				decompile_once(entry, "%s consumer %d" % (item[1], printed + 1), 60000)
				find_and_print_calls_from(entry, "%s consumer %d" % (item[1], printed + 1))
				printed += 1
			jdx += 1
		idx += 1

def audit_setting_initializer(addr_int, label):
	decompile_once(addr_int, "%s setting initializer" % label, 16000)
	find_and_print_calls_from(addr_int, "%s setting initializer" % label)
	targets = collect_data_targets(addr_int)
	idx = 0
	while idx < len(targets):
		target = targets[idx]
		find_refs_to(target, "%s candidate setting object/global" % label)
		functions = collect_ref_functions(target, False)
		jdx = 0
		printed = 0
		while jdx < len(functions) and printed < 16:
			entry = functions[jdx]
			if entry < 0x00F00000:
				decompile_once(entry, "%s consumer %d" % (label, printed + 1), 50000)
				find_and_print_calls_from(entry, "%s consumer %d" % (label, printed + 1))
				printed += 1
			jdx += 1
		idx += 1

def audit_all_setting_initializers():
	write("")
	write("#" * 70)
	write("OBJECT, ACTOR, ITEM, TERRAIN, TREE, AND CELL-GRID LOD SETTINGS")
	write("#" * 70)
	idx = 0
	while idx < len(LOD_SETTING_INITIALIZERS):
		item = LOD_SETTING_INITIALIZERS[idx]
		audit_setting_initializer(item[0], item[1])
		idx += 1

def first_string_pattern_offset(value):
	lower = value.lower()
	idx = 0
	best = -1
	while idx < len(SETTING_STRING_PATTERNS):
		offset = lower.find(SETTING_STRING_PATTERNS[idx])
		if offset >= 0 and (best < 0 or offset < best):
			best = offset
		idx += 1
	return best

def audit_discovered_setting_strings(max_matches):
	write("")
	write("#" * 70)
	write("DISCOVERED CELL GRID AND LOD TIMING SETTING STRINGS")
	write("#" * 70)
	data_iter = listing.getDefinedData(True)
	count = 0
	while data_iter.hasNext() and count < max_matches:
		data = data_iter.next()
		try:
			if not data.hasStringValue():
				continue
			value = str(data.getValue())
		except:
			continue
		offset = first_string_pattern_offset(value)
		if offset < 0:
			continue
		addr_int = data.getAddress().getOffset() + offset
		matched_value = value[offset:]
		write("  String @ 0x%08x: %s" % (addr_int, matched_value[:180]))
		find_refs_to(addr_int, matched_value[:100])
		functions = collect_ref_functions(addr_int, False)
		idx = 0
		while idx < len(functions):
			audit_setting_initializer(functions[idx], matched_value[:80])
			idx += 1
		count += 1
	write("  Matching setting strings audited: %d" % count)

def instruction_matches(text, patterns):
	lower = text.lower()
	idx = 0
	while idx < len(patterns):
		if lower.find(patterns[idx]) >= 0:
			return True
		idx += 1
	return False

def instruction_has_exact_immediate(text, value):
	tokens = re.findall("0x[0-9a-fA-F]+", text)
	idx = 0
	while idx < len(tokens):
		if int(tokens[idx], 16) == value:
			return True
		idx += 1
	return False

def scan_exact_immediate_users(value, label, max_functions, max_hits):
	write("")
	write("#" * 70)
	write("EXACT IMMEDIATE SCAN: %s" % label)
	write("#" * 70)
	functions = {}
	hits = 0
	ridx = 0
	while ridx < len(FIELD_SCAN_RANGES) and hits < max_hits:
		item = FIELD_SCAN_RANGES[ridx]
		inst = listing.getInstructionAt(toAddr(item[0]))
		if inst is None:
			inst = listing.getInstructionAfter(toAddr(item[0]))
		while inst is not None and inst.getAddress().getOffset() < item[1] and hits < max_hits:
			text = inst.toString()
			if instruction_has_exact_immediate(text, value):
				func = fm.getFunctionContaining(inst.getAddress())
				if func is not None:
					entry = func.getEntryPoint().getOffset()
					functions[entry] = True
					write("  0x%08x in %s @ 0x%08x: %s" % (inst.getAddress().getOffset(), func.getName(), entry, text))
					hits += 1
			inst = inst.getNext()
		ridx += 1
	entries = sorted(functions.keys())
	idx = 0
	while idx < len(entries) and idx < max_functions:
		decompile_once(entries[idx], "%s candidate %d" % (label, idx + 1), 60000)
		find_and_print_calls_from(entries[idx], "%s candidate %d" % (label, idx + 1))
		idx += 1
	write("  Candidate functions decompiled: %d of %d; instruction hits: %d" % (idx, len(entries), hits))

def print_instruction_window(addr_int, label, max_instructions):
	write("")
	write("-" * 70)
	write("INSTRUCTION WINDOW: %s @ 0x%08x" % (label, addr_int))
	write("-" * 70)
	inst = listing.getInstructionAt(toAddr(addr_int))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(addr_int - 1))
	count = 0
	while inst is not None and count < max_instructions:
		write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
		refs = inst.getReferencesFrom()
		for ref in refs:
			write("    %s -> 0x%08x" % (ref.getReferenceType(), ref.getToAddress().getOffset()))
		inst = inst.getNext()
		count += 1
	write("  Instructions printed: %d" % count)

def scan_field_users(patterns, label, max_functions, max_hits):
	write("")
	write("#" * 70)
	write("FIELD/TYPE SCAN: %s" % label)
	write("#" * 70)
	functions = {}
	hits = 0
	ridx = 0
	while ridx < len(FIELD_SCAN_RANGES) and hits < max_hits:
		item = FIELD_SCAN_RANGES[ridx]
		inst = listing.getInstructionAt(toAddr(item[0]))
		if inst is None:
			inst = listing.getInstructionAfter(toAddr(item[0]))
		while inst is not None and inst.getAddress().getOffset() < item[1] and hits < max_hits:
			text = inst.toString()
			if instruction_matches(text, patterns):
				func = fm.getFunctionContaining(inst.getAddress())
				if func is not None:
					entry = func.getEntryPoint().getOffset()
					functions[entry] = True
					write("  0x%08x in %s @ 0x%08x: %s" % (inst.getAddress().getOffset(), func.getName(), entry, text))
					hits += 1
			inst = inst.getNext()
		ridx += 1
	entries = sorted(functions.keys())
	idx = 0
	while idx < len(entries) and idx < max_functions:
		decompile_once(entries[idx], "%s candidate %d" % (label, idx + 1), 60000)
		find_and_print_calls_from(entries[idx], "%s candidate %d" % (label, idx + 1))
		idx += 1
	write("  Candidate functions decompiled: %d of %d; instruction hits: %d" % (idx, len(entries), hits))

def audit_known_function(addr_int, label, max_len, caller_limit):
	decompile_once(addr_int, label, max_len)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)
	decompile_callers(addr_int, label, caller_limit, 50000)

write("FNV LOD REPLACEMENT AND VISIBILITY CONTRACT AUDIT")
write("")
write("Questions this output must answer before the LOD handoff is changed:")
write("1. Which cell states and TESObjectCELL fields mean that near references are requested, loaded, attached, or unloading?")
write("2. How does ExtraDistantData connect a real TESObjectREFR to distant 3D, and who owns each reference?")
write("3. At what exact condition does AttachDistant3DTask attach, detach, hide, or preserve distant geometry?")
write("4. Which frame phase updates the camera, cell grid, distant manager, scene roots, culling, and draw lists?")
write("5. Can a frame show both versions or neither version, and which state write creates that overlap or gap?")
write("6. Which squared distances, bounds, category multipliers, fade percentages, timers, and alpha fields drive visibility?")
write("7. How do teleports, worldspace changes, loading screens, disabled refs, missing 3D, and cancelled IO fall back safely?")
write("8. Which operations are main-thread-only, worker-safe, render-thread-visible, refcounted, or lock-protected?")
write("9. Which handoff boundary can be improved without extending stale LOD lifetime or racing scene-graph traversal?")

audit_known_function(0x0086D590, "renderer LOD root construction and child ordering", 90000, 12)
audit_known_function(0x0086E650, "main loop ordering of IO completion, world update, culling, and rendering", 120000, 4)
audit_known_function(0x0094AE40, "PlayerCharacter camera update with skipUpdateLOD argument", 90000, 16)
audit_known_function(0x00452580, "cell load and movement scheduler", 90000, 16)
audit_known_function(0x00528600, "ExteriorCellLoaderTask main loading path", 100000, 16)
audit_known_function(0x00462290, "cell unload execution", 80000, 16)
audit_known_function(0x007160B0, "scene graph cull/update dispatch", 30000, 16)
audit_known_function(0x00548230, "TESObjectCELL reference insertion and VWD count increment", 90000, 16)
audit_known_function(0x0054CA90, "TESObjectCELL reference removal and VWD count decrement", 90000, 16)
audit_known_function(0x005495A0, "TESObjectCELL VWD total-versus-ready count test", 30000, 16)
audit_known_function(0x00551890, "TESObjectCELL update that consumes the VWD ready-count test", 120000, 16)
audit_known_function(0x0054CD20, "TESObjectCELL teardown and VWD count reset", 70000, 16)
audit_known_function(0x0055E1D0, "TESObjectCELL VWD count decrement helper", 30000, 16)
audit_known_function(0x00B791F0, "LandLOD renderer consumer of the post-construction global", 70000, 8)

audit_all_rtti_types()
audit_seed_vtable(0x010A8F90, "BSFadeNode", 48)
audit_nirtti_name("BSFadeNode")
audit_root_consumers()
audit_all_setting_initializers()
audit_discovered_setting_strings(40)

scan_exact_immediate_users(0x13, "ExtraDistantData type 0x13 users", 40, 120)
scan_field_users(["+ 0xa8]", "+0xa8]", "+ 0xaa]", "+0xaa]"], "TESObjectCELL VWD total 0xA8 and ready 0xAA counter users", 80, 240)
print_instruction_window(0x00BC2B20, "undefined BSFadeNodeCuller virtual target", 12)

find_refs_to(0x01082C68, "DistantRefLOD name")
find_refs_to(0x01017700, "fLODBoundRadiusMult setting name")
find_refs_to(0x010177D0, "fLODFadeOutPercent setting name")
find_refs_to(0x01065954, "fLodDistance setting name")
find_refs_to(0x010A91C0, "fLODMultTrees setting name")
find_refs_to(0x01183FB4, "TESObjectCELL RTTI")
find_refs_to(0x011841CC, "TESObjectREFR RTTI")

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/lod_replacement_visibility_contract_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
