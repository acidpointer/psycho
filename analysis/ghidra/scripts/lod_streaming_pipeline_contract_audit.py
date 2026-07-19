# @category Analysis
# @description Prove the FNV distant terrain LOD scheduler, task, IO, publication, cancellation, and eviction contract

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []
decompiled = {}

TASK_RTTI = [
	(0x0119EF18, "BGSDistantObjectBlockLoadTask", 0x0106DC3C),
	(0x0119EF4C, "BGSDistantTreeBlockLoadTask", 0x0106DED0),
	(0x0119F158, "BGSTerrainChunkLoadTask", 0x0106E1DC),
]

STREAM_SETTING_GLOBALS = [
	(0x011D86AC, "bUseNewTerrainSystem"),
	(0x011D869C, "bUseDistantObjectBlocks"),
	(0x011D8680, "bUseDistantTrees"),
	(0x011D86E0, "fSplitDistanceMult"),
	(0x011D8754, "fMorphStartDistanceMult"),
	(0x011D86D4, "fMorphEndDistanceMult"),
	(0x011D877C, "fBlockLoadDistance"),
	(0x011D8724, "fBlockLoadDistanceLow"),
	(0x011D8788, "fTreeLoadDistance"),
	(0x011D8740, "uTerrainTextureFadeTime"),
	(0x011D8760, "bKeepLowDetailTerrain"),
]

SUBSYSTEM_RANGES = [
	(0x00440000, 0x00470000),
	(0x00520000, 0x00590000),
	(0x006E0000, 0x00720000),
	(0x00860000, 0x00880000),
	(0x00900000, 0x00980000),
	(0x00A50000, 0x00A70000),
	(0x00C3C000, 0x00C50000),
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
	callees = collect_callees(addr_int, SUBSYSTEM_RANGES)
	idx = 0
	while idx < len(callees) and idx < max_functions:
		decompile_once(callees[idx], "%s relevant callee %d" % (label, idx + 1), max_len)
		idx += 1
	write("  Relevant callees considered: %d of %d" % (idx, len(callees)))

def audit_task_type(rtti_addr, label, seed_vtable):
	write("")
	write("#" * 70)
	write("TASK TYPE: %s" % label)
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
		methods = print_vtable(vtable, label, 20)
		constructors = collect_ref_functions(vtable, False)
		cidx = 0
		while cidx < len(constructors) and cidx < 12:
			ctor = constructors[cidx]
			decompile_once(ctor, "%s constructor or vtable writer %d" % (label, cidx + 1), 30000)
			find_and_print_calls_from(ctor, "%s constructor or vtable writer %d" % (label, cidx + 1))
			decompile_callers(ctor, "%s producer" % label, 12, 30000)
			cidx += 1
		midx = 0
		while midx < len(methods):
			method = methods[midx]
			decompile_once(method, "%s vtable slot %d" % (label, midx), 50000)
			find_and_print_calls_from(method, "%s vtable slot %d" % (label, midx))
			decompile_relevant_callees(method, "%s vtable slot %d" % (label, midx), 14, 30000)
			midx += 1
		vidx += 1

def audit_all_task_types():
	idx = 0
	while idx < len(TASK_RTTI):
		item = TASK_RTTI[idx]
		audit_task_type(item[0], item[1], item[2])
		idx += 1

def audit_setting_consumers():
	write("")
	write("#" * 70)
	write("DISTANCE, MORPH, FEATURE, AND RETENTION SETTING CONSUMERS")
	write("#" * 70)
	idx = 0
	while idx < len(STREAM_SETTING_GLOBALS):
		item = STREAM_SETTING_GLOBALS[idx]
		find_refs_to(item[0], item[1])
		functions = collect_ref_functions(item[0], False)
		jdx = 0
		while jdx < len(functions) and jdx < 16:
			entry = functions[jdx]
			if entry < 0x00F00000:
				decompile_once(entry, "%s consumer %d" % (item[1], jdx + 1), 50000)
				find_and_print_calls_from(entry, "%s consumer %d" % (item[1], jdx + 1))
			jdx += 1
		idx += 1

def audit_known_function(addr_int, label, max_len, caller_limit):
	decompile_once(addr_int, label, max_len)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)
	decompile_callers(addr_int, label, caller_limit, 40000)
	decompile_relevant_callees(addr_int, label, 20, 40000)

write("FNV LOD STREAMING PIPELINE CONTRACT AUDIT")
write("")
write("Questions this output must answer before an engine improvement is designed:")
write("1. Which main-thread owner converts camera/worldspace movement into terrain, object-block, and tree-block requests?")
write("2. What are the exact level, coordinate, distance, morph, hysteresis, and retention formulas?")
write("3. How are requests deduplicated, prioritized, queued, cancelled, retried, and bounded under rapid movement?")
write("4. Which virtual slots execute on workers, and which completion path returns ownership to the main thread?")
write("5. Which files, textures, models, and child tasks must finish before a block or chunk is publishable?")
write("6. Which fields encode requested, loading, ready, attached, stale, cancelled, and failed states?")
write("7. What refcount, lock, queue, and scene-root rules protect publication and eviction?")
write("8. What happens on missing or malformed LOD data, worldspace change, teleport, unload, and shutdown?")
write("9. Which scheduling and publication boundaries are safe hook surfaces without doing IO on the render thread?")

audit_known_function(0x006FC490, "BGSTerrainManager construction and DLODSettings load", 70000, 12)
audit_known_function(0x006FD210, "BGSTerrainNode construction and split/morph contract", 70000, 12)
audit_known_function(0x005BB390, "worldspace and camera owner that invokes the distant manager", 60000, 8)
audit_known_function(0x006FCA90, "BGSTerrainManager camera-driven update owner", 90000, 8)
audit_known_function(0x006FCDB0, "BGSTerrainManager post-update phase", 30000, 8)
audit_known_function(0x006FEA70, "terrain post-update morph and publication branch", 90000, 8)
audit_known_function(0x006FCE00, "BGSTerrainManager worldspace reset and teardown", 70000, 8)
audit_known_function(0x006FDAA0, "terrain chunk request and retirement branch", 90000, 8)
audit_known_function(0x006FDFC0, "distant object block request and retirement branch", 90000, 8)
audit_known_function(0x006FE330, "distant tree block request and retirement branch", 90000, 8)
audit_known_function(0x006FCEF0, "cell and reference distant-visibility eligibility", 70000, 8)
audit_known_function(0x006F9230, "distant object reference update and attachment", 90000, 8)
audit_known_function(0x006F2290, "distant tree reference update and attachment", 90000, 8)
audit_known_function(0x006FE830, "LOD block distance metric", 30000, 8)
audit_known_function(0x006FF3F0, "terrain texture fade advancement and finalization", 50000, 8)
audit_known_function(0x006F6D10, "distant object block load-task construction candidate", 60000, 12)
audit_known_function(0x006F9360, "distant tree block load-task construction candidate", 60000, 12)
audit_known_function(0x006FB980, "terrain chunk load-task construction candidate", 60000, 12)
audit_known_function(0x006F74F0, "intrusive LOD task pointer publication/release helper", 30000, 4)
audit_known_function(0x00C3DBF0, "main-thread completed IO task processing", 90000, 12)
audit_known_function(0x00C3DFA0, "IO and ModelLoader drain/count wait", 70000, 12)
audit_known_function(0x00C3E1B0, "IO mode transition and queue ownership", 70000, 12)
audit_known_function(0x0044DD60, "IOTask intrusive final release", 30000, 4)

audit_all_task_types()
audit_setting_consumers()

find_refs_to(0x0106E310, "Data\\LODSettings\\%s.DLODSettings path")
find_refs_to(0x0106DBC4, "distant object block diffuse texture path")
find_refs_to(0x0106DBFC, "distant object block normal texture path")
find_refs_to(0x0106E100, "terrain LOD diffuse texture path")
find_refs_to(0x0106E140, "terrain LOD normal texture path")
find_refs_to(0x01202D98, "ModelLoader or IO manager singleton")

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/lod_streaming_pipeline_contract_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
