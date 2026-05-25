# @category Analysis
# @description Audit startup/save loading hot-path candidates from Stewie inlines and FNV loader code

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
		if count > 80:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)

def find_and_print_calls_from(addr_int, label):
	addr = toAddr(addr_int)
	func = fm.getFunctionAt(addr)
	if func is None:
		func = fm.getFunctionContaining(addr)
	write("")
	write("-" * 70)
	write("Calls FROM 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	if func is None:
		write("  [function not found]")
		return
	addr_iter = func.getBody().getAddresses(True)
	count = 0
	while addr_iter.hasNext():
		a = addr_iter.next()
		inst = listing.getInstructionAt(a)
		if inst is None:
			continue
		if not inst.getFlowType().isCall():
			continue
		refs_from = inst.getReferencesFrom()
		for ref in refs_from:
			target = ref.getToAddress().getOffset()
			target_func = fm.getFunctionAt(toAddr(target))
			target_name = target_func.getName() if target_func else "unknown_0x%08x" % target
			write("  CALL 0x%08x -> %s (from 0x%08x)" % (target, target_name, a.getOffset()))
			count += 1
	write("  Total: %d calls" % count)

def disasm_window(center_int, before_count, after_count, label):
	write("")
	write("-" * 70)
	write("Disassembly %s around 0x%08x" % (label, center_int))
	write("-" * 70)
	inst = listing.getInstructionAt(toAddr(center_int))
	if inst is None:
		inst = listing.getInstructionBefore(toAddr(center_int))
	count = 0
	while inst is not None and count < before_count:
		prev = inst.getPrevious()
		if prev is None:
			break
		inst = prev
		count += 1
	idx = 0
	limit = before_count + after_count + 1
	while inst is not None and idx < limit:
		marker = " << TARGET" if inst.getAddress().getOffset() == center_int else ""
		write("  0x%08x: %-38s%s" % (inst.getAddress().getOffset(), inst.toString(), marker))
		inst = inst.getNext()
		idx += 1

def analyze_candidate_group(title, items):
	write("")
	write("=" * 70)
	write(title)
	write("=" * 70)
	for item in items:
		addr_int = item[0]
		label = item[1]
		note = item[2]
		write("")
		write("Candidate: %s" % label)
		write("Reason: %s" % note)
		disasm_window(addr_int, 8, 18, label)
		decompile_at(addr_int, label)
		find_and_print_calls_from(addr_int, label)

def analyze_refs():
	refs = [
		(0x00462d80, "BSFile::ReadBuffer"),
		(0x00aa1750, "BSFile low read helper"),
		(0x00b00650, "BSFile::ReadFile wrapper"),
		(0x00b01800, "ArchiveFile low read helper"),
		(0x0044b8d0, "ModelLoader UpdateReferencesToQueue target"),
		(0x00864820, "BGSLoadGameBuffer::ReadToken target"),
		(0x00846b60, "BGSSaveLoadFormIDMap ctor"),
		(0x00845558, "BGSSaveLoadChangesMap bucket count data")
	]
	for item in refs:
		find_refs_to(item[0], item[1])

def analyze_vtable_slot(addr_int, label, before_slots, after_slots):
	write("")
	write("-" * 70)
	write("VTable/data window %s @ 0x%08x" % (label, addr_int))
	write("-" * 70)
	start = addr_int - before_slots * 4
	total = before_slots + after_slots + 1
	for idx in range(total):
		slot_addr = start + idx * 4
		try:
			target = getInt(toAddr(slot_addr)) & 0xffffffff
		except:
			write("  0x%08x: <read failed>" % slot_addr)
			continue
		marker = " << TARGET" if slot_addr == addr_int else ""
		target_func = fm.getFunctionAt(toAddr(target))
		name = target_func.getName() if target_func else "unknown"
		write("  0x%08x: 0x%08x -> %s%s" % (slot_addr, target, name, marker))

def main():
	write("=" * 70)
	write("LOADING HOT-PATH CANDIDATE AUDIT")
	write("=" * 70)
	write("Goal:")
	write("  Build a concrete candidate list for real loading speedups.")
	write("  Priority is synchronous file/map/list work, because worker-count changes broke completion queue contracts.")
	write("")
	startup_items = [
		(0x00447080, "ModelLoader::LoadFile", "central startup asset scheduling path from earlier audit"),
		(0x00448d7e, "ModelLoader::UpdateReferencesToQueue call site", "Stewie replaces this call with a faster equivalent"),
		(0x0044b8d0, "ModelLoader::UpdateReferencesToQueue target", "candidate pure CPU/lock-map hot path"),
		(0x00afc49c, "ArchiveFile::Read call site A", "Stewie replaces with simpler bound-checked ArchiveFile__Read"),
		(0x00afbf8e, "ArchiveFile::Read call site B", "Stewie replaces with simpler bound-checked ArchiveFile__Read"),
		(0x00b01800, "ArchiveFile low read helper", "target called by Stewie's ArchiveFile__Read wrapper"),
		(0x00b00650, "BSFile::ReadFile wrapper", "Stewie overwrites this wrapper with short direct read/update implementation"),
		(0x00aa1750, "BSFile low read helper", "target called by Stewie's BSFile__ReadFile wrapper"),
		(0x00462d80, "BSFile::ReadBuffer", "used by save-load refID map setup and likely core file buffering")
	]
	save_items = [
		(0x008480c2, "BGSSaveLoadGame::LoadGame refID map setup call", "Stewie dynamically sizes and bulk-loads the refID map"),
		(0x00846b60, "BGSSaveLoadFormIDMap ctor", "bucket-count sensitivity can dominate huge saves"),
		(0x00864820, "BGSLoadGameBuffer::ReadToken target", "Stewie jumps ReadToken wrapper directly here"),
		(0x00864980, "BGSLoadGameBuffer::ReadToken wrapper", "wrapper may be avoidable overhead in save load"),
		(0x0095b9ce, "PlayerCharacter::LoadGame quest list append site", "Stewie avoids tList append n^2 behavior"),
		(0x0066e567, "ActorCause::LoadGame DetectionData call", "Stewie replaces DetectionData load path"),
		(0x008fd98d, "HighProcess::LoadGame DetectionData call A", "Stewie replaces DetectionData load path"),
		(0x008fda31, "HighProcess::LoadGame DetectionData call B", "Stewie replaces DetectionData load path"),
		(0x008487b0, "BGSSaveLoadGame::LoadGame bit-test patch", "Stewie removes avoidable load-time work"),
		(0x008484d3, "TESForm::GetTypeID load call site A", "Stewie inlines form type byte load"),
		(0x00848599, "TESForm::GetTypeID load call site B", "Stewie inlines form type byte load"),
		(0x008488c8, "TESForm::GetTypeID load call site C", "Stewie inlines form type byte load"),
		(0x00848408, "BGSSaveLoadChangesMap::SetChangeFlags load call", "Stewie replaces map operation"),
		(0x00848bb4, "BGSSaveLoadChangesMap::SetChangeFlagsAndUnk04 load call", "Stewie replaces map operation"),
		(0x0084839e, "BGSSaveLoadChangesMap::GetFormChangeFlags load call A", "Stewie replaces map operation"),
		(0x008483b7, "BGSSaveLoadChangesMap::GetFormChangeFlags load call B", "Stewie replaces map operation")
	]
	analyze_candidate_group("STARTUP / ASSET IO CANDIDATES", startup_items)
	analyze_candidate_group("SAVE LOAD CPU/MAP CANDIDATES", save_items)
	analyze_refs()
	analyze_vtable_slot(0x010a4640, "ArchiveFile vtable slot patched by Stewie", 6, 8)
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/loading_hotpath_candidate_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
