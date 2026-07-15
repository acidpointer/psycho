# @category Analysis
# @description Audit the 2026-07-15 ragdoll penetration raycast crash chain and safe intervention contract

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
ref_mgr = currentProgram.getReferenceManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def write(msg):
	output.append(msg)
	print(msg)

def func_for(addr_int):
	addr = toAddr(addr_int)
	func = fm.getFunctionAt(addr)
	if func is None:
		func = fm.getFunctionContaining(addr)
	return func

def name_for_func(func):
	if func is None:
		return "???"
	return "%s @ 0x%08x" % (func.getName(), func.getEntryPoint().getOffset())

def decompile_at(addr_int, label, max_len=30000):
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
		if len(code) > max_len:
			write("  [decompile truncated at %d chars, total %d]" % (max_len, len(code)))
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

def disasm_window(center_int, before_count, after_count, label):
	write("")
	write("-" * 70)
	write("Disassembly: %s around 0x%08x" % (label, center_int))
	write("-" * 70)
	inst = listing.getInstructionAt(toAddr(center_int))
	if inst is None:
		inst = listing.getInstructionBefore(toAddr(center_int))
	count = 0
	while inst is not None and count < before_count:
		previous = inst.getPrevious()
		if previous is None:
			break
		inst = previous
		count += 1
	index = 0
	limit = before_count + after_count + 1
	while inst is not None and index < limit:
		offset = inst.getAddress().getOffset()
		marker = " << crash" if offset == center_int else ""
		write("  0x%08x: %-62s%s" % (offset, inst.toString(), marker))
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				target = ref.getToAddress().getOffset()
				write("      call -> 0x%08x %s" % (target, name_for_func(func_for(target))))
		inst = inst.getNext()
		index += 1

def audit_frame(addr_int, label, before_count=24, after_count=90):
	decompile_at(addr_int, label)
	disasm_window(addr_int, before_count, after_count, label)
	find_and_print_calls_from(addr_int, label)
	func = func_for(addr_int)
	if func is not None:
		find_refs_to(func.getEntryPoint().getOffset(), label + " entry")

def main():
	write("2026-07-15 RAGDOLL PENETRATION RAYCAST CRASH AUDIT")
	write("=" * 70)
	write("Observed main-thread crash chain:")
	write("  00CF2565 -> 00CA1E1E -> 00D1FCC1 -> 00CA1763 -> 009782DF")
	write("  EBX=hkpAabbPhantom, ECX=EDX=ESI=0 at the fault.")
	write("  Stack includes hkaDetectRagdollPenetration, hkaRagdollInstance,")
	write("  hkpRigidBody, bhkRagdollPenetrationUtil, and hkpAllRayHitCollector.")
	write("")
	write("Questions that must be answered before a patch:")
	write("  1. What exact operand is null at 00CF2565, and who owns it?")
	write("  2. Is the null produced by an empty phantom overlap set, a missing world,")
	write("     a stale collidable, or a ragdoll array/count contract violation?")
	write("  3. Which caller establishes the Havok world/read lock and object lifetime?")
	write("  4. Which narrow frame is a best-effort penetration query whose skip is safe?")
	write("  5. What return value and cleanup does each caller require after a skip?")
	write("  6. Can the actor skeleton or mod identity affect this path, or is it only")
	write("     incidental stack context?")
	audit_frame(0x00cf2565, "Faulting Havok query frame", 36, 130)
	audit_frame(0x00ca1e1e, "Immediate Havok caller", 30, 120)
	audit_frame(0x00d1fcc1, "Ragdoll penetration worker", 30, 130)
	audit_frame(0x00ca1763, "Ragdoll penetration owner", 30, 130)
	audit_frame(0x009782df, "Engine ragdoll update caller", 30, 140)
	audit_frame(0x0086f765, "Main-loop caller after ragdoll update", 20, 70)
	audit_frame(0x0086ee67, "Outer main-loop frame", 20, 70)

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/crash_20260715_ragdoll_penetration_raycast_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
