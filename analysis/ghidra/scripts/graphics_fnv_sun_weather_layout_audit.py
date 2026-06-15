# @category Analysis
# @description Audit FNV sky sun weather time and camera layout for OMV environment constants

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x0044FB20: "NewTES",
	0x0045C670: "CurrentCameraGetter_0045C670",
	0x00595EA0: "Sky::GetSunriseBegin",
	0x00595F50: "Sky::GetSunriseEnd",
	0x00595FC0: "Sky::GetSunsetBegin",
	0x00596030: "Sky::GetSunsetEnd",
	0x0063B9B0: "Sky::GetSunriseColorBegin",
	0x0063BA30: "Sky::GetSunsetColorEnd",
	0x006629F0: "CameraOrSceneGetter_006629F0",
	0x00710AB0: "NiCamera/FOV setup candidate",
	0x008706B0: "Main::Render",
	0x00870A00: "Main render world caller A",
	0x00870BD0: "Main render world caller B",
	0x00870AE8: "RenderWorldSceneGraph callsite A",
	0x00870B21: "RenderFirstPerson callsite A",
	0x00870E18: "RenderWorldSceneGraph callsite B",
	0x00870F74: "RenderFirstPerson callsite B",
	0x00873200: "Main::RenderWorldSceneGraph",
	0x00875110: "Main::RenderFirstPerson",
	0x00876125: "pCurrentCamera write before image-space",
	0x00876136: "ProcessImageSpaceShaders callsite",
	0x00B55AC0: "ImageSpaceManager::ProcessImageSpaceShaders",
	0x011DE7B8: "TimeGlobals",
	0x011DEA20: "Sky::singleton",
	0x011F426C: "CameraLocation",
	0x011F474C: "CameraWorldTranslate",
	0x011F917C: "BSShaderManager::pCurrentCamera",
}

FUNCTION_TARGETS = [
	0x0044FB20,
	0x0045C670,
	0x00595EA0,
	0x00595F50,
	0x00595FC0,
	0x00596030,
	0x0063B9B0,
	0x0063BA30,
	0x006629F0,
	0x00710AB0,
	0x008706B0,
	0x00870A00,
	0x00870BD0,
	0x00873200,
	0x00875110,
	0x00B55AC0,
]

GLOBAL_REFS = [
	0x011DEA20,
	0x011DE7B8,
	0x011F917C,
	0x011F426C,
	0x011F474C,
]

DISASM_WINDOWS = [
	0x00870AE8,
	0x00870B21,
	0x00870E18,
	0x00870F74,
	0x00876125,
	0x00876136,
]

def write(msg):
	output.append(msg)
	print(msg)

def label_for(addr_int):
	label = KNOWN.get(addr_int)
	if label is not None:
		return label
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is not None:
		return func.getName()
	func = fm.getFunctionContaining(toAddr(addr_int))
	if func is not None:
		return "%s+0x%x" % (func.getName(), addr_int - func.getEntryPoint().getOffset())
	return "unknown"

def decompile_at(addr_int, label, max_len=18000):
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
		if count > 120:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)

def find_and_print_calls_from(addr_int, label):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	write("")
	write("--- Calls FROM %s (0x%08x) ---" % (label, addr_int))
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, label_for(tgt)))
				count += 1
	write("  Total: %d calls" % count)

def read_bytes(addr_int, count):
	values = []
	i = 0
	while i < count:
		value = memory.getByte(toAddr(addr_int + i)) & 0xff
		values.append("%02X" % value)
		i += 1
	return " ".join(values)

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
		addr_int = inst.getAddress().getOffset()
		marker = " << TARGET" if addr_int == center_int else ""
		extra = ""
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				extra = "%s ; CALL 0x%08x %s" % (extra, tgt, label_for(tgt))
		write("  0x%08x: %-52s%s%s" % (addr_int, inst.toString(), marker, extra))
		inst = inst.getNext()
		idx += 1

def scan_refs_windows(addr_int, label, max_refs):
	write("")
	write("=" * 70)
	write("REFERENCE WINDOWS: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		from_addr = ref.getFromAddress().getOffset()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		fname = from_func.getName() if from_func else "???"
		write("")
		write("Reference %d: 0x%08x in %s" % (count + 1, from_addr, fname))
		disasm_window(from_addr, 10, 24, "reference to %s" % label)
		count += 1
		if count >= max_refs:
			write("  ... reference window scan truncated")
			break
	write("Total reference windows printed: %d" % count)

def print_data_layout_notes():
	write("")
	write("=" * 70)
	write("EXPECTED DATA LAYOUTS TO VERIFY")
	write("=" * 70)
	write("TESReloaded/NewVegasReloaded is trusted prior art, but Psycho needs its own FNV-safe read contract.")
	write("")
	write("Sky:")
	write("  Sky singleton candidate: *(Sky**)0x011DEA20")
	write("  Sky + 0x0C firstClimate candidate")
	write("  Sky + 0x10 firstWeather candidate")
	write("  Sky + 0x14 secondWeather candidate")
	write("  Sky + 0x28 sun candidate")
	write("  Sky + 0x60 sunAmbient candidate")
	write("  Sky + 0x6C sunDirectional candidate")
	write("  Sky + 0xC0 sunFog candidate")
	write("  Sky + 0xF4 weatherPercent candidate")
	write("")
	write("Sun/root node:")
	write("  SkyObject/Sun RootNode candidate is expected near Sun + 0x04 or Sun + 0x08 depending on exact class.")
	write("  NiAVObject local position candidate: RootNode + 0x58")
	write("  NiAVObject world position candidate: RootNode + 0x8C")
	write("  Sun direction must be derived from a proven object transform or proven sky vector, not guessed in HLSL.")
	write("")
	write("Time:")
	write("  TimeGlobals base candidate: 0x011DE7B8")
	write("  TimeGlobals + 0x0C GameHour candidate")
	write("  TimeGlobals + 0x10 GameDaysPassed candidate")
	write("")
	write("Weather:")
	write("  TESReloaded source uses firstWeather/secondWeather blended by weatherPercent.")
	write("  TESWeather fog day/night near/far, sun glare, sun damage, and weather type must be proven before runtime dereference.")
	write("  Fog constants should be read or reconstructed on CPU and passed to shaders, not approximated from depth alone.")
	write("")
	write("Camera:")
	write("  pCurrentCamera candidate: *(NiCamera**)0x011F917C")
	write("  Camera location globals: 0x011F426C and 0x011F474C")
	write("  Camera near/far offsets currently used by Psycho: Camera + 0xEC and Camera + 0xF0")
	write("  View/projection/inverse projection offsets still need a Ghidra-proven contract before sunshafts.")

def audit_globals():
	idx = 0
	while idx < len(GLOBAL_REFS):
		addr = GLOBAL_REFS[idx]
		find_refs_to(addr, label_for(addr))
		scan_refs_windows(addr, label_for(addr), 16)
		idx += 1

def audit_disasm_windows():
	idx = 0
	while idx < len(DISASM_WINDOWS):
		addr = DISASM_WINDOWS[idx]
		write("")
		write("Bytes @ 0x%08x (%s): %s" % (addr, label_for(addr), read_bytes(addr, 16)))
		disasm_window(addr, 16, 42, label_for(addr))
		idx += 1

def audit_functions():
	idx = 0
	while idx < len(FUNCTION_TARGETS):
		addr = FUNCTION_TARGETS[idx]
		decompile_at(addr, label_for(addr))
		find_and_print_calls_from(addr, label_for(addr))
		idx += 1

def print_header():
	write("FNV GRAPHICS SUN WEATHER LAYOUT AUDIT")
	write("")
	write("Questions:")
	write("1. Which exact FNV globals and offsets expose Sky, Sun, Weather, TimeGlobals, and camera state?")
	write("2. Which offsets are valid at scene_pre_image_space, scene_post_image_space, and final_image_space?")
	write("3. Can Psycho fill sun direction, sun color, fog color, fog distance, and weather blend constants without TESReloaded?")
	write("4. Which reads are safe enough for default non-invasive mode, and which require opt-in native graphics mode?")

def main():
	print_header()
	print_data_layout_notes()
	audit_globals()
	audit_disasm_windows()
	audit_functions()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_sun_weather_layout_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("")
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
