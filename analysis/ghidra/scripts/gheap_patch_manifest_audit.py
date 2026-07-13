# @category Analysis
# @description Recover exact vanilla byte and instruction contracts for every allocator hook and patch site

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

def read_bytes(addr_int, count):
	values = []
	index = 0
	while index < count:
		try:
			value = memory.getByte(toAddr(addr_int + index)) & 0xff
			values.append("%02X" % value)
		except:
			values.append("??")
		index += 1
	return " ".join(values)

def print_instruction_contract(addr_int, label, minimum_bytes=16):
	write("")
	write("-" * 70)
	write("PATCH CONTRACT: %s @ 0x%08x" % (label, addr_int))
	write("-" * 70)
	func = fm.getFunctionContaining(toAddr(addr_int))
	if func is None:
		write("  Function: [not found]")
	else:
		write("  Function: %s @ 0x%08x, size %d" % (func.getName(), func.getEntryPoint().getOffset(), func.getBody().getNumAddresses()))
	write("  Context bytes [site-8, site+31]: %s" % read_bytes(addr_int - 8, 40))
	inst = listing.getInstructionAt(toAddr(addr_int))
	if inst is None:
		containing = listing.getInstructionContaining(toAddr(addr_int))
		if containing is None:
			write("  ERROR: site is not in a decoded instruction")
		else:
			write("  ERROR: site is inside instruction at 0x%08x: %s" % (containing.getAddress().getOffset(), containing.toString()))
		return
	covered = 0
	count = 0
	while inst is not None and covered < minimum_bytes:
		length = inst.getLength()
		write("  +0x%02x len=%d bytes=[%s] %s" % (covered, length, read_bytes(inst.getAddress().getOffset(), length), inst.toString()))
		covered += length
		count += 1
		inst = inst.getNext()
	write("  Contract span: %d instructions, %d bytes" % (count, covered))

def print_raw_patch_contract(addr_int, length, replacement, label):
	write("")
	write("-" * 70)
	write("RAW PATCH CONTRACT: %s @ 0x%08x" % (label, addr_int))
	write("-" * 70)
	func = fm.getFunctionContaining(toAddr(addr_int))
	if func is None:
		write("  Function: [not found]")
	else:
		write("  Function: %s @ 0x%08x, size %d" % (func.getName(), func.getEntryPoint().getOffset(), func.getBody().getNumAddresses()))
	write("  Original span (%d bytes): %s" % (length, read_bytes(addr_int, length)))
	write("  Replacement: %s" % replacement)
	write("  Context bytes [site-8, site+%d]: %s" % (length + 15, read_bytes(addr_int - 8, length + 24)))
	inst = listing.getInstructionAt(toAddr(addr_int))
	covered = 0
	while inst is not None and covered < length:
		inst_addr = inst.getAddress().getOffset()
		inst_len = inst.getLength()
		write("  +0x%02x len=%d bytes=[%s] %s" % (inst_addr - addr_int, inst_len, read_bytes(inst_addr, inst_len), inst.toString()))
		covered += inst_len
		inst = inst.getNext()
	if covered != length:
		write("  ERROR: patch length %d does not end on an instruction boundary (decoded %d)" % (length, covered))
	else:
		write("  Patch ends on an instruction boundary")

def audit_inline_targets(items, section):
	write("")
	write("# %s" % section)
	for item in items:
		print_instruction_contract(item[0], item[1], 16)

def audit_raw_targets(items, section):
	write("")
	write("# %s" % section)
	for item in items:
		print_raw_patch_contract(item[0], item[1], item[2], item[3])

def audit_critical_function(addr_int, label, max_len=16000):
	decompile_at(addr_int, label, max_len)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)

def main():
	write("GHEAP COMPLETE PATCH MANIFEST AUDIT")
	write("=" * 70)
	write("This output defines the exact vanilla preflight contract for one atomic")
	write("gheap + CRT + scrap-heap transaction. A mismatch at a required site")
	write("must reject the whole requested allocator mode before runtime allocation")
	write("state or trampolines are created.")
	game_heap = [
		(0x00AA3E40, "GameHeap allocate"),
		(0x00AA4060, "GameHeap free"),
		(0x00AA44C0, "GameHeap msize"),
		(0x00AA4150, "GameHeap realloc path 1"),
		(0x00AA4200, "GameHeap realloc path 2")
	]
	crt = [
		(0x00ECD1C7, "CRT malloc entry 1"),
		(0x00ED0CDF, "CRT malloc entry 2"),
		(0x00EDDD7D, "CRT calloc entry 1"),
		(0x00ED0D24, "CRT calloc entry 2"),
		(0x00ECCF5D, "CRT realloc entry 1"),
		(0x00ED0D70, "CRT realloc entry 2"),
		(0x00EE1700, "CRT recalloc entry 1"),
		(0x00ED0DBE, "CRT recalloc entry 2"),
		(0x00ECD31F, "CRT msize"),
		(0x00ECD291, "CRT free")
	]
	scrap_heap = [
		(0x00AA53F0, "scrap heap init fix"),
		(0x00AA5410, "scrap heap init variable"),
		(0x00AA54A0, "scrap heap allocate"),
		(0x00AA5610, "scrap heap free"),
		(0x00AA5460, "scrap heap purge"),
		(0x00AA42E0, "scrap heap TLS accessor")
	]
	supporting = [
		(0x008705D0, "main-loop maintenance"),
		(0x0086F640, "phase 10 pre"),
		(0x00832AD0, "phase 10 audio update"),
		(0x00833D00, "phase 10 audio worker"),
		(0x004FF1A0, "radio signal scan"),
		(0x00834260, "radio station update"),
		(0x0082FB70, "phase 10 pre tail"),
		(0x0082D7C0, "phase 10 world update"),
		(0x0086F890, "phase 10 mid"),
		(0x00552570, "phase 10 queue drain"),
		(0x0086F670, "phase 10 post"),
		(0x00868850, "per-frame queue drain"),
		(0x008C78C0, "AI thread start"),
		(0x008C7990, "AI thread join"),
		(0x008324E0, "Havok stop/start"),
		(0x00866A90, "OOM stage executor"),
		(0x00A61A60, "texture cache find"),
		(0x00A5FCA0, "NiSourceTexture destructor"),
		(0x00449A50, "model task destructor"),
		(0x00C3E310, "Havok world lock"),
		(0x00C3E340, "Havok world unlock")
	]
	raw_patches = [
		(0x00AA6840, 1, "C3", "RET: SBM stats reset"),
		(0x00866770, 1, "C3", "RET: SBM config table init"),
		(0x00866E00, 1, "C3", "RET: SBM related init"),
		(0x00866D10, 1, "C3", "RET: ScrapHeapManager lazy getter"),
		(0x00AA7030, 1, "C3", "RET: global cleanup"),
		(0x00AA5C80, 1, "C3", "RET: deallocate all arenas"),
		(0x00AA58D0, 1, "C3", "RET: eager ScrapHeapManager constructor"),
		(0x00AA6F90, 1, "C3", "RET: purge unused arenas"),
		(0x00AA7290, 1, "C3", "RET: decrement arena reference"),
		(0x00AA7300, 1, "C3", "RET: release arena by pointer"),
		(0x0086C56F, 5, "90 90 90 90 90", "NOP call: redundant heap init A"),
		(0x00C42EB1, 5, "90 90 90 90 90", "NOP call: redundant heap init B"),
		(0x00EC1701, 5, "90 90 90 90 90", "NOP call: redundant heap init C"),
		(0x00AA3060, 5, "90 90 90 90 90", "NOP call: late singleton allocation"),
		(0x0086EED4, 2, "EB 55", "jump over per-frame SBM arena management"),
		(0x00AA38CA, 30, "30 x 90", "NOP embedded scrap-heap constructor")
	]
	audit_inline_targets(game_heap, "REQUIRED GAME HEAP REDIRECTS")
	audit_inline_targets(crt, "REQUIRED STATIC CRT REDIRECTS")
	audit_inline_targets(scrap_heap, "REQUIRED SCRAP HEAP REDIRECTS")
	audit_inline_targets(supporting, "REQUIRED GHEAP SUPPORTING REDIRECTS")
	audit_raw_targets(raw_patches, "DESTRUCTIVE RAW PATCHES")
	write("")
	write("# MUTABLE DATA PATCH")
	write("HeapSingleton fast-path flag image byte @ 0x011F6361: %s" % read_bytes(0x011F6361, 1))
	write("The constructor writes the runtime value; the image byte is identity evidence only.")
	find_refs_to(0x011F6361, "HeapSingleton + 0x129 fast-path flag")
	write("")
	write("# CRITICAL OWNERSHIP AND FALLBACK FUNCTIONS")
	audit_critical_function(0x00AA3E40, "GameHeap allocate", 18000)
	audit_critical_function(0x00AA4060, "GameHeap free", 18000)
	audit_critical_function(0x00AA44C0, "GameHeap msize", 14000)
	audit_critical_function(0x00AA4150, "GameHeap realloc path 1", 22000)
	audit_critical_function(0x00AA4200, "GameHeap realloc path 2", 22000)
	audit_critical_function(0x00AA3880, "HeapSingleton constructor and embedded scrap heap", 22000)
	audit_critical_function(0x00866E00, "Default File and Static heap construction", 22000)
	audit_critical_function(0x00AA3050, "late singleton initialization gate", 12000)
	write("")
	write("# MAIN EXECUTABLE IMPORT REFERENCES")
	find_refs_to(0x00ECD1C7, "static CRT malloc entry")
	find_refs_to(0x00ECD291, "static CRT free entry")
	find_refs_to(0x00ECCF5D, "static CRT realloc entry")
	find_refs_to(0x00ECD31F, "static CRT msize entry")
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/memory/gheap_patch_manifest_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
