# @category Analysis
# @description Prove the static LandLOD VB block creation, chip publication, retirement, failure, and locking leaf contract.

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
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
		if count > 60:
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

def audit_function(addr_int, label, max_len=26000):
	decompile_at(addr_int, label, max_len)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)

def print_instruction_window(addr_int, label, before_count=20, after_count=30):
	write("")
	write("=" * 70)
	write("Instruction window %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	center = listing.getInstructionContaining(toAddr(addr_int))
	if center is None:
		center = listing.getInstructionAt(toAddr(addr_int))
	if center is None:
		write("  [instruction not found]")
		return
	items = []
	current = center
	count = 0
	while current is not None and count < before_count:
		current = listing.getInstructionBefore(current.getAddress())
		if current is not None:
			items.insert(0, current)
		count += 1
	items.append(center)
	current = center
	count = 0
	while current is not None and count < after_count:
		current = listing.getInstructionAfter(current.getAddress())
		if current is not None:
			items.append(current)
		count += 1
	for inst in items:
		marker = ">>" if inst.getAddress().getOffset() == center.getAddress().getOffset() else "  "
		write("%s 0x%08x  %s" % (marker, inst.getAddress().getOffset(), inst.toString()))

write("LOD STATIC VERTEX-BUFFER ALLOCATION FAILURE FINAL AUDIT")
write("Program: %s" % currentProgram.getName())
write("Image base: %s" % currentProgram.getImageBase())
write("")
write("Prior audits prove LandLOD static geometry receives a non-null NiVBChip whose +0x08 VB is null.")
write("This audit resolves only the remaining static VB block allocator and retirement leaf.")

write("")
write("# STATIC VB BLOCK CREATION AND CHIP ACQUISITION")
audit_function(0x00E94B80, "Static NiVBBlock creation and D3D vertex-buffer allocation", 32000)
audit_function(0x00E94650, "Static NiVBBlock chip acquisition and NiVBChip construction", 32000)
audit_function(0x00E94C20, "Static geometry group allocation owner", 22000)
print_instruction_window(0x00E94B80, "Static VB block creation raw entry", 8, 80)
print_instruction_window(0x00E94650, "Static chip acquisition raw entry", 8, 100)

write("")
write("# STATIC CHIP RETIREMENT, BLOCK REUSE, AND DESTRUCTION")
audit_function(0x00E94490, "Static NiVBChip retirement into block", 28000)
audit_function(0x00E946B0, "Static geometry group destructor", 28000)
audit_function(0x00E948F0, "Static geometry group buffer purge or reset", 28000)
audit_function(0x00E94DB0, "Shared geometry group purge or reset", 28000)
audit_function(0x00E94D00, "Shared geometry group adjacent lifecycle owner", 22000)

write("")
write("# UNIVERSAL CREATE-FAILURE COMPARISON")
audit_function(0x00E95230, "Dynamic VB block creation", 30000)
audit_function(0x00E987C0, "Dynamic vertex-buffer allocation helper", 26000)
audit_function(0x00537D60, "Dynamic NiVBChip constructor", 22000)
audit_function(0x00E94E30, "Unshared geometry direct VB allocation raw target", 30000)
print_instruction_window(0x00E94E30, "Unshared direct VB allocation raw entry", 8, 100)

write("")
write("# REQUIRED FIX CONTRACT")
write("The output must establish:")
write("  1. The exact CreateVertexBuffer HRESULT/null handling in the static block creator.")
write("  2. Whether a failed block retains a null D3D VB and remains discoverable in the block map.")
write("  3. Whether chip acquisition copies a null block VB into NiVBChip +0x08 and still returns success.")
write("  4. Whether retirement can clear chip +0x08 concurrently or only detaches the stream slot.")
write("  5. Which synchronization protects static block maps, chip lists, and COM Release.")
write("  6. Whether a post-allocation chip+VB validation at 0x00E8BFA0 is sufficient and retryable.")
write("  7. Whether the weaker Stewie stream-0-only predicate must be restored to the vanilla all-stream contract.")
write("  8. The smallest fix preserving LOD visibility, two workers, and transient allocation retry.")

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/lod_static_vertex_buffer_allocation_failure_final_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
