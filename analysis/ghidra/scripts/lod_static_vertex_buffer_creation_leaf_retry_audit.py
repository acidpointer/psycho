# @category Analysis
# @description Prove the omitted static VB CreateVertexBuffer failure, map publication, chip construction, and retry contract.

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

def audit_function(addr_int, label, max_len=26000):
	decompile_at(addr_int, label, max_len)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)

def print_instruction_window(addr_int, label, before_count=12, after_count=80):
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

write("LOD STATIC VERTEX-BUFFER CREATION LEAF AND RETRY AUDIT")
write("Program: %s" % currentProgram.getName())
write("Image base: %s" % currentProgram.getImageBase())
write("")
write("The prior final audit called 0x00E941A0 but never audited it.")
write("This script closes only that missing CreateVertexBuffer, publication, and retry leaf.")

write("")
write("# DIRECT3D STATIC VERTEX-BUFFER CREATION FAILURE")
audit_function(0x00E941A0, "Static NiVBBlock Direct3D vertex-buffer creator", 32000)
print_instruction_window(0x00E941A0, "Static Direct3D vertex-buffer creator", 12, 100)

write("")
write("# STATIC BLOCK LOOKUP, CREATION, AND MAP PUBLICATION")
audit_function(0x00E941D0, "Static reusable NiVBBlock lookup", 26000)
audit_function(0x00E94580, "Static NiVBBlock selection or creation owner", 32000)
audit_function(0x00E94220, "Static NiVBBlock free-list or map publication", 26000)
audit_function(0x00E94330, "Static NiVBBlock destructor", 26000)
audit_function(0x00A53C30, "Engine pointer-map lookup used by static geometry", 18000)
audit_function(0x00B57EA0, "Engine pointer-map publication used by static geometry", 18000)
print_instruction_window(0x00E94C20, "Static geometry group allocation and map owner", 8, 100)

write("")
write("# CHIP CONSTRUCTION, RETIREMENT, AND NULL-VB PROPAGATION")
audit_function(0x00E98660, "NiVBChip construction from static NiVBBlock", 32000)
audit_function(0x00E94150, "Static NiVBBlock chip retirement accounting", 22000)
audit_function(0x00E94490, "Static NiVBChip retirement owner", 26000)
print_instruction_window(0x00E98660, "NiVBChip construction from block", 10, 100)

write("")
write("# COMMON PUBLICATION AND RETRY BOUNDARY")
audit_function(0x00E8BFA0, "Common release-then-allocate stream wrapper", 22000)
audit_function(0x00E8EEB0, "Vanilla all-stream NiVBChip validity predicate", 18000)
print_instruction_window(0x00E8BFA0, "Common release-then-allocate stream wrapper", 8, 80)

write("")
write("# REQUIRED FIX CONTRACT")
write("The output must establish:")
write("  1. The exact Direct3D CreateVertexBuffer HRESULT and output-pointer handling at 0x00E941A0.")
write("  2. Whether a failed block remains in the static map or free list and can be selected again.")
write("  3. Whether 0x00E98660 copies a null block VB into NiVBChip +0x08 and returns a non-null chip.")
write("  4. Whether any static allocation, map, chip, or COM lifetime operation owns synchronization.")
write("  5. Whether returning false after chip +0x08 validation at 0x00E8BFA0 leaves a retryable state.")
write("  6. Whether retry must retire the just-published invalid chip immediately or on the next attempt.")
write("  7. The smallest safe hook boundary preserving two workers, full LOD visibility, and transient retry.")

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/lod_static_vertex_buffer_creation_leaf_retry_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
