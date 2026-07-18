# @category Analysis
# @description Proves the FNV current-epoch underwater classification publication hook contract

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

OUTPATH = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_atmosphere_underwater_epoch_publish_audit.txt"

output = []

FUNCTIONS = [
	(0x004E1BC0, "TESWater RenderReflections owner", 50000),
	(0x004E2120, "Post-classification publication candidate", 16000),
	(0x004E2100, "Non-classified water state path", 16000),
	(0x00872930, "Fallback underwater-mode writer", 16000),
	(0x008727D0, "Main water/reflection owner", 30000),
	(0x00873200, "RenderWorldSceneGraph", 36000),
]

GLOBALS = [
	(0x011C7A58, "TESWater forced render-mode byte"),
	(0x011C7A59, "TESWater computed underwater render-mode byte"),
	(0x011C7A5B, "TESWater one-shot skip byte"),
	(0x01189624, "TESWater render availability byte"),
	(0x011FF104, "Published water shader-mode byte"),
	(0x011FF8C4, "Published underwater camera-mode byte"),
]

WINDOWS = [
	(0x004E1D41, 24, 72, "Camera Z and water-height classification"),
	(0x004E1D66, 20, 28, "Underwater or forced-mode classification write"),
	(0x004E1D7C, 20, 24, "Underwater or forced-mode publication call"),
	(0x004E1D9B, 20, 28, "Above-water classification write"),
	(0x004E1DB1, 20, 24, "Above-water publication call"),
	(0x004E1DBD, 24, 28, "Classification branch join"),
	(0x004E1E1D, 24, 24, "Non-classified shader-mode copy"),
	(0x00872873, 32, 44, "RenderReflections invocation"),
	(0x008728AE, 24, 28, "Fallback publication call"),
	(0x008728C7, 24, 28, "Fallback mode reset"),
	(0x00870A61, 20, 52, "Caller B water-before-world ordering"),
	(0x00870C29, 20, 60, "Caller C water-before-world ordering"),
]

BYTE_SITES = [
	(0x004E2120, 24, "Post-classification publication candidate prologue"),
	(0x004E2100, 24, "Non-classified path prologue"),
	(0x00872930, 24, "Fallback writer prologue"),
]

def write(msg):
	output.append(msg)
	print(msg)

def checkpoint_output():
	fout = open(OUTPATH, "w")
	try:
		fout.write("\n".join(output))
	finally:
		fout.close()

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

def disasm_window(center_int, before_count, after_count, label):
	write("")
	write("-" * 70)
	write("Disassembly %s around 0x%08x" % (label, center_int))
	write("-" * 70)
	inst = listing.getInstructionContaining(toAddr(center_int))
	if inst is None:
		inst = listing.getInstructionBefore(toAddr(center_int))
	if inst is None:
		write("  [instruction not found]")
		return
	count = 0
	while count < before_count:
		previous = inst.getPrevious()
		if previous is None:
			break
		inst = previous
		count += 1
	remaining = before_count + after_count + 1
	while inst is not None and remaining > 0:
		addr_int = inst.getAddress().getOffset()
		max_addr_int = inst.getMaxAddress().getOffset()
		marker = " << TARGET" if addr_int <= center_int <= max_addr_int else ""
		write("  0x%08x: %-64s%s" % (addr_int, inst.toString(), marker))
		inst = inst.getNext()
		remaining -= 1

def dump_bytes(addr_int, byte_count, label):
	write("")
	write("-" * 70)
	write("Bytes %s @ 0x%08x" % (label, addr_int))
	write("-" * 70)
	data = getBytes(toAddr(addr_int), byte_count)
	if data is None:
		write("  [bytes unavailable]")
		return
	parts = []
	index = 0
	while index < len(data):
		parts.append("%02X" % (data[index] & 0xff))
		index += 1
	write("  %s" % " ".join(parts))

def audit_functions():
	index = 0
	while index < len(FUNCTIONS):
		item = FUNCTIONS[index]
		decompile_at(item[0], item[1], item[2])
		find_refs_to(item[0], item[1])
		find_and_print_calls_from(item[0], item[1])
		checkpoint_output()
		if monitor.isCancelled():
			return
		index += 1

def audit_globals():
	index = 0
	while index < len(GLOBALS):
		item = GLOBALS[index]
		find_refs_to(item[0], item[1])
		checkpoint_output()
		if monitor.isCancelled():
			return
		index += 1

def audit_windows():
	index = 0
	while index < len(WINDOWS):
		item = WINDOWS[index]
		disasm_window(item[0], item[1], item[2], item[3])
		checkpoint_output()
		if monitor.isCancelled():
			return
		index += 1

def audit_bytes():
	index = 0
	while index < len(BYTE_SITES):
		item = BYTE_SITES[index]
		dump_bytes(item[0], item[1], item[2])
		checkpoint_output()
		if monitor.isCancelled():
			return
		index += 1

def main():
	write("FNV ATMOSPHERE UNDERWATER EPOCH PUBLICATION AUDIT")
	write("")
	write("Questions:")
	write("1. Is 0x004E2120 a hookable function with a fully proven calling convention and prologue?")
	write("2. Are its only callers the above-water, underwater, and explicit fallback branches shown by current research?")
	write("3. Does every classified path write 0x011C7A59 before calling 0x004E2120?")
	write("4. Do early-return/non-classified paths omit 0x004E2120 so an epoch mismatch safely means unknown?")
	write("5. Does the water/reflection owner always run before RenderWorldSceneGraph on the supported Main paths?")
	write("")
	write("The intended contract is value-copy only: the hook publishes {epoch, known, underwater} and retains no engine pointer.")
	checkpoint_output()
	audit_functions()
	if monitor.isCancelled():
		return
	audit_globals()
	if monitor.isCancelled():
		return
	audit_windows()
	if monitor.isCancelled():
		return
	audit_bytes()
	checkpoint_output()
	print("Output written to %s (%d lines)" % (OUTPATH, len(output)))

try:
	main()
finally:
	checkpoint_output()
	decomp.dispose()
