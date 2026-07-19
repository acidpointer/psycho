# @category Analysis
# @description Resolve TallGrass and SpeedTree render-state vtable methods and alpha coverage ownership

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

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
				name = tgt_func.getName() if tgt_func else "???"
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, name))
				count += 1
	write("  Total: %d calls" % count)

def read_u32(addr_int):
	try:
		return memory.getInt(toAddr(addr_int)) & 0xffffffff
	except Exception as error:
		write("  Failed reading 0x%08x: %s" % (addr_int, error))
		return None

def decompile_direct_callees(addr_int, label, max_functions=32, max_len=12000):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	write("")
	write("=" * 70)
	write("DIRECT CALLEE DECOMPILATIONS: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	if func is None:
		write("  [function not found]")
		return
	targets = []
	seen = set()
	inst_iter = listing.getInstructions(func.getBody(), True)
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if not ref.getReferenceType().isCall():
				continue
			target = ref.getToAddress().getOffset()
			if target in seen:
				continue
			seen.add(target)
			targets.append(target)
	targets.sort()
	count = 0
	for target in targets:
		if count >= max_functions:
			write("  Callee list truncated after %d functions" % count)
			break
		decompile_at(target, "direct callee %d" % (count + 1), max_len)
		count += 1
	write("  Decompiled: %d of %d direct callees" % (count, len(targets)))

def audit_function(addr_int, label, max_len=22000):
	decompile_at(addr_int, label, max_len)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)
	decompile_direct_callees(addr_int, label, 32, 14000)

def audit_vtable_range(base_int, first_index, last_index, label):
	write("")
	write("=" * 70)
	write("VTABLE RENDER-STATE RANGE: %s @ 0x%08x" % (label, base_int))
	write("=" * 70)
	index = first_index
	seen = set()
	while index <= last_index:
		target = read_u32(base_int + index * 4)
		if target is None:
			write("  [%02d] +0x%03x: [unreadable]" % (index, index * 4))
		else:
			func = fm.getFunctionAt(toAddr(target))
			name = func.getName() if func else "???"
			write("  [%02d] +0x%03x: 0x%08x -> %s" % (index, index * 4, target, name))
			if target not in seen:
				seen.add(target)
				decompile_at(target, "%s vtable[%d]" % (label, index), 18000)
				find_and_print_calls_from(target, "%s vtable[%d]" % (label, index))
				decompile_direct_callees(target, "%s vtable[%d]" % (label, index), 24, 12000)
		index += 1

write("FNV ATMOSPHERE ALPHA-COVERAGE STATE FOLLOWUP")
write("")
write("Proven by the first audit:")
write("RenderWorldSceneGraph completes post-depth groups 9 and 1 plus the alpha renderer before returning to OMV.")
write("Native effect 0x22 runs before those final groups and is not a complete world-color boundary.")
write("")
write("Questions:")
write("1. What do TallGrass and SpeedTree virtual slots 75, 76, and 77 set and restore around drawing?")
write("2. Do those methods enable alpha test, alpha-to-coverage, multisample antialiasing, or a sample mask?")
write("3. Which accumulator finalizer calls the pre-depth and post-depth owners for the main world camera?")
write("4. Does the final post-depth alpha path write depth, color, or both, and can a single resolved depth represent its partial coverage?")
write("5. Does the proven contract require coverage-aware atmosphere composition instead of a single-depth full-pixel overwrite?")

audit_vtable_range(0x010B8980, 70, 82, "TallGrassShader")
audit_vtable_range(0x010B9190, 70, 82, "SpeedTreeLeafShader")
audit_vtable_range(0x010BC070, 70, 82, "SpeedTreeBranchShader")

audit_function(0x00BAA570, "TallGrassShader constructor")
audit_function(0x00BB1C10, "SpeedTreeLeafShader constructor")
audit_function(0x00BD4560, "SpeedTreeBranchShader constructor")
audit_function(0x00B66520, "accumulator finalizer variant A")
audit_function(0x00B66570, "accumulator finalizer variant B")
audit_function(0x00B665A0, "accumulator finalizer variant C")
audit_function(0x00B9A120, "single-group geometry draw path")
audit_function(0x00B9A3C0, "special multisample geometry draw path")
audit_function(0x00B9AF60, "sorted alpha geometry draw path")

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_atmosphere_alpha_coverage_state_followup.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("")
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
