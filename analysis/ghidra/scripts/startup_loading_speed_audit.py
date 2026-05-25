# @category Analysis
# @description Audit cold startup and main-menu loading speed targets

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

def disasm_window(addr_int, label, before=24, after=48):
	start = addr_int - before
	end = addr_int + after
	write("")
	write("-" * 70)
	write("Disassembly %s: 0x%08x - 0x%08x" % (label, start, end))
	write("-" * 70)
	inst = listing.getInstructionAt(toAddr(start))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(start))
	while inst is not None and inst.getAddress().getOffset() <= end:
		a = inst.getAddress().getOffset()
		marker = ""
		if a == addr_int:
			marker = " << TARGET"
		call_info = ""
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				tgt_func = fm.getFunctionAt(toAddr(tgt))
				name = tgt_func.getName() if tgt_func else "???"
				call_info = " -> %s" % name
		write("  0x%08x: %s%s%s" % (a, inst, call_info, marker))
		inst = inst.getNext()

def print_site(addr_int, label):
	decompile_at(addr_int, label, 6000)
	disasm_window(addr_int, label)
	find_refs_to(addr_int, label)

def print_string_refs(patterns, max_matches, max_refs):
	write("")
	write("=" * 70)
	write("STRING ANCHORS")
	write("=" * 70)
	data_iter = listing.getDefinedData(True)
	matches = []
	while data_iter.hasNext():
		data = data_iter.next()
		if data.hasStringValue():
			val = data.getValue()
			if val:
				val_str = str(val)
				low = val_str.lower()
				for pat in patterns:
					if pat.lower() in low:
						matches.append((data.getAddress().getOffset(), val_str, pat))
						break
	write("  Found %d matching strings" % len(matches))
	idx = 0
	for item in matches:
		if idx >= max_matches:
			write("  ... truncated string matches")
			break
		addr_int = item[0]
		val_str = item[1]
		pat = item[2]
		write("")
		write("  0x%08x pattern=%s string=%s" % (addr_int, pat, val_str[:180]))
		refs = ref_mgr.getReferencesTo(toAddr(addr_int))
		ref_count = 0
		while refs.hasNext():
			ref = refs.next()
			from_func = fm.getFunctionContaining(ref.getFromAddress())
			fname = from_func.getName() if from_func else "???"
			faddr = from_func.getEntryPoint().getOffset() if from_func else 0
			write("    %s @ 0x%08x in %s @ 0x%08x" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname, faddr))
			ref_count += 1
			if ref_count >= max_refs:
				write("    ... refs truncated")
				break
		if ref_count == 0:
			write("    [no direct refs]")
		idx += 1

def print_sites():
	write("")
	write("=" * 70)
	write("STEWIE / PSYCHO STARTUP-SPEED PATCH SITES")
	write("=" * 70)
	sites = [
		(0x007D592C, "FasterTitleMenu skip logo alpha wait"),
		(0x0078A093, "FasterTitleMenu current-time hook"),
		(0x0078A133, "FasterTitleMenu music-playing jump"),
		(0x007D590B, "FasterTitleMenu half logo fade duration"),
		(0x007D586E, "Skip loading tiles mouse-button wait"),
		(0x00C3E105, "ModelLoader IO loop Sleep(50) site"),
		(0x00447080, "ModelLoader::LoadFile"),
		(0x00448D7E, "ModelLoader::UpdateReferencesToQueue call site"),
		(0x00AFC58C, "BSA 128KB decompression buffer cap"),
		(0x00AFC537, "BSA inflate init call"),
		(0x00AFC1F4, "BSA inflate call"),
		(0x00AFC49C, "CompressedArchiveFile ArchiveFile::Read call A"),
		(0x00AFBF8E, "CompressedArchiveFile ArchiveFile::Read call B"),
		(0x00B00650, "BSFile::ReadFile candidate"),
		(0x004742AC, "TESFile inflate init"),
		(0x0047434F, "TESFile inflate"),
		(0x00472100, "TESFile compressed/GRUP check inline target"),
		(0x00469800, "TESDataHandler::GetNextID inline target"),
		(0x00404A73, "GameSettingCollection init call site"),
		(0x007D3190, "ContinueGame entry"),
		(0x007D59AE, "Start menu post-load first save hook site"),
		(0x0070C632, "Automatic continue input hook site")
	]
	for item in sites:
		print_site(item[0], item[1])

def main():
	write("STARTUP / MAIN MENU LOADING SPEED AUDIT")
	write("=" * 70)
	write("Goal: identify concrete cold-start loading paths and safe speed targets.")
	write("")
	write("Known source clues:")
	write("  Stewie FasterTitleMenu removes title-logo alpha/fade waits.")
	write("  Stewie Inlines changes ModelLoader IO sleep 50ms -> 10ms.")
	write("  Stewie Inlines also patches ArchiveFile::Read and BSFile::ReadFile.")
	write("  psycho-nvse already replaces TES/BSA zlib paths.")
	patterns = [
		"Fallout -",
		"sArchiveList",
		"SArchiveList",
		"Data\\Menus",
		"main_menu",
		"loading",
		"Loading",
		"FALLOUT.INI",
		"Archive",
		".bsa",
		".esm",
		".esp",
		"Meshes\\Interface\\Loading",
		"Circular Loading",
		"PauseScreen"
	]
	print_string_refs(patterns, 80, 8)
	print_sites()
	write("")
	write("=" * 70)
	write("HOT FUNCTIONS CALL MAP")
	write("=" * 70)
	find_and_print_calls_from(0x00C3DFA0, "ModelLoader IO/update loop")
	find_and_print_calls_from(0x00447080, "ModelLoader::LoadFile")
	find_and_print_calls_from(0x00AFE0B0, "BSFile load buffer")
	find_and_print_calls_from(0x00AFF470, "BSFile read/open related")
	find_and_print_calls_from(0x00AFC000, "CompressedArchiveFile read/decompress area")
	find_and_print_calls_from(0x00472100, "TESFile compressed/GRUP check")
	find_and_print_calls_from(0x00469800, "TESDataHandler::GetNextID")
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/startup_loading_speed_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
