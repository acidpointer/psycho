# @category Analysis
# @description Decompile the crash site FUN_00ca363b and its callers to identify the NULL dereference in the IO-thread Havok mesh-loading crash.
#
# Crash context (from .reports/CrashLogger.2026-04-18-11-27-05.log):
#   Thread: IO (BSTaskManagerThread on stack)
#   EIP  = 0x00CA363B
#   Fault = READ at 0x00000004
#   EAX=0 ECX=0 EDX=0 EBX=0 EDI=0 ESI=1
#   EBP  = 0x1A60A3E0 -> hkPackedNiTriStripsData instance
#   Mesh: DATA/meshes/NVDLC03/Architecture/Urban/NVDLC03TransmBldgSquatWreck.NIF
#
# Call chain (top to bottom):
#   0x00CA363B  <- crash (Havok mesh/shape construction)
#   0x00D219B9  <- caller (Havok)
#   mlf Hook_DiskRead+0x20  <- ModLimitFix disk-read hook
#   0x00AA1588              <- FalloutNV, above the mlf hook
#   ucrtbase strlwr_s_l+0xCA <- path-lowercasing wrapper at bottom
#
# Hypotheses we want to confirm or rule out:
#   (a) Zombie reuse: our pool served an allocation, game freed it,
#       pool LIFO-reused the cell, IO thread held a stale pointer and
#       read through offset 4. Matches the documented "immediate-reuse"
#       family on Pool::free (BSTreeNode / JIP / Stewie).
#   (b) Our allocator returned NULL somewhere; IO thread stored NULL
#       without checking; subsequent read dereferences NULL+4.
#   (c) Game bug -- a null-check is missing in Havok code and the
#       trigger is independent of our allocator.
#   (d) ModLimitFix interaction -- the mlf hook returns state that
#       confuses the Havok parser.
#
# What the decomp should tell us:
#   - The exact instruction at 0x00CA363B (which register is NULL).
#   - What that register came from (parameter? field? return value?).
#   - Whether there's a missing null-check (-> (c)) or a dereference
#     that trusts an external pointer (-> (a)/(b)).
#   - The shape-construction sequence in FUN_00D219B9 (the caller) so
#     we can see which allocation or lookup produced the NULL.

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def write(msg):
	output.append(msg)
	print(msg)

def decompile_at(addr_int, label, max_len=12000):
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
		write("  NOTE: Requested 0x%08x is inside %s (entry at 0x%08x, +0x%x)" % (addr_int, func.getName(), faddr, addr_int - faddr))
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		write(code[:max_len])
	else:
		write("  [decompilation failed]")

def disasm_window(addr_int, label, before=32, after=16):
	# Show raw disassembly around the crash site so we can read the
	# exact faulting instruction without relying on the decompiler.
	write("")
	write("-" * 70)
	write("Disassembly window around %s @ 0x%08x (-%d / +%d bytes)" % (label, addr_int, before, after))
	write("-" * 70)
	listing = currentProgram.getListing()
	start = addr_int - before
	end = addr_int + after
	inst_iter = listing.getInstructions(toAddr(start), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		ia = inst.getAddress().getOffset()
		if ia < start:
			continue
		if ia > end:
			break
		marker = "  <-- CRASH" if ia == addr_int else ""
		write("  0x%08x: %s%s" % (ia, inst.toString(), marker))
		count += 1
		if count > 60:
			write("  ... (truncated)")
			break

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
	write("--- Calls FROM %s (entry 0x%08x) ---" % (label, func.getEntryPoint().getOffset()))
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

# --- Main body ---

write("######################################################################")
write("# IO-thread Havok mesh-loading crash at 0x00CA363B")
write("######################################################################")
write("")
write("Goal: identify the NULL pointer dereference in the Havok")
write("mesh/shape construction path hit while IO thread loaded")
write("NVDLC03TransmBldgSquatWreck.NIF.")

# Part 1: the crash site itself. Disassembly + decompile of the whole
# containing function. The faulting instruction plus its immediate
# predecessors tell us which register/operand is NULL and where it
# came from.
write("")
write("######################################################################")
write("# PART 1: crash site 0x00CA363B")
write("######################################################################")

disasm_window(0x00CA363B, "CRASH SITE", before=48, after=24)
decompile_at(0x00CA363B, "Crash site containing function", max_len=14000)
find_refs_to(0x00CA363B, "crash site (mid-function refs)")
find_and_print_calls_from(0x00CA363B, "containing function")

# Part 2: the immediate caller. This is the Havok shape-construction
# or mesh-builder that invokes the crashing function with whatever
# object/pointer is NULL. We want to see how it obtained the pointer
# -- allocator return? cache lookup? field of a parent object?
write("")
write("######################################################################")
write("# PART 2: caller 0x00D219B9 (the Havok step one above the crash)")
write("######################################################################")

disasm_window(0x00D219B9, "CALLER", before=32, after=16)
decompile_at(0x00D219B9, "Caller containing function", max_len=14000)
find_and_print_calls_from(0x00D219B9, "caller containing function")

# Part 3: the stack-frame above mlf. 0x00AA1588 sits in FalloutNV code
# directly above ModLimitFix's disk-read hook. Its role: probably a
# vanilla IO/mesh-load entry. Seeing it lets us confirm whether mlf is
# just a pass-through or is doing something that affects state.
write("")
write("######################################################################")
write("# PART 3: IO dispatch frame 0x00AA1588")
write("######################################################################")

disasm_window(0x00AA1588, "IO DISPATCH", before=32, after=16)
decompile_at(0x00AA1588, "IO-dispatch containing function", max_len=10000)

# Part 4: callers of the crashing function. If the crash site is
# reachable from multiple call paths, the stack-objects on this path
# (hkPackedNiTriStripsData / hkScaledMoppBvTreeShape / bhkMoppBvTreeShape)
# might not be the only scenario -- listing callers gives us
# confidence that this specific mesh-load path is the only reachable
# one or one of several.
write("")
write("######################################################################")
write("# PART 4: all callers of the crashing function")
write("######################################################################")

# We don't know the function entry address yet; derive from the
# containing-function lookup and list its callers via find_refs_to.
# Post-run, reader confirms by cross-referencing with PART 1's
# "Function: ... @ 0x..." header line.
#
# We list refs to addresses across the likely function-entry range by
# scanning a window of addresses backward from the crash site and
# printing refs to each address that is a function entry.
def list_callers_of_containing_function(crash_addr_int):
	func = fm.getFunctionContaining(toAddr(crash_addr_int))
	if func is None:
		write("  [no containing function at 0x%08x]" % crash_addr_int)
		return
	entry = func.getEntryPoint().getOffset()
	write("")
	write("Callers of %s (entry 0x%08x):" % (func.getName(), entry))
	refs = ref_mgr.getReferencesTo(toAddr(entry))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		if not ref.getReferenceType().isCall():
			continue
		src = ref.getFromAddress().getOffset()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		fname = from_func.getName() if from_func else "???"
		fentry = from_func.getEntryPoint().getOffset() if from_func else 0
		write("  0x%08x in %s (entry 0x%08x)" % (src, fname, fentry))
		count += 1
		if count > 40:
			write("  ... (truncated)")
			break
	write("  Total callers: %d" % count)

list_callers_of_containing_function(0x00CA363B)

# Part 5: likely adjacent Havok code we want to cross-reference.
# hkPackedNiTriStripsData is the mesh class on EBP. Its shape
# constructor is hkPackedNiTriStripsShape. A nearby decompile tells
# us whether the crash function is that shape's constructor or
# initialiser, or a helper called from it.
write("")
write("######################################################################")
write("# PART 5: Havok shape-construction neighbourhood cross-reference")
write("######################################################################")
write("")
write("The stack showed hkPackedNiTriStripsData at EBP and")
write("hkPackedNiTriStripsShape, hkScaledMoppBvTreeShape, bhkMoppBvTreeShape,")
write("hkpFixedRigidMotion, hkpRigidBody as other live Havok objects.")
write("If Part 1's containing function is an hkPackedNiTriStripsShape")
write("constructor or initialiser, that confirms the mesh-load path.")

# --- Output ---

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/crash_00CA363B_analysis.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
