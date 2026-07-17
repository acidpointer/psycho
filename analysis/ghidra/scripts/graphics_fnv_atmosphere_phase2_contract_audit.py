# @category Analysis
# @description Audit FNV atmosphere Phase 2 HDR composition and underwater-state contracts

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

OUTPATH = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_atmosphere_phase2_contract_audit.txt"

FUNCTIONS = [
	(0x00875FD0, "Main image-space owner"),
	(0x00B55AC0, "ProcessImageSpaceShaders"),
	(0x00B97900, "ImageSpaceManager RenderEndOfFrameEffects"),
	(0x00B97550, "ImageSpaceManager RenderEffect"),
	(0x00B8C830, "Image-space effect dispatch"),
	(0x00BA3F20, "ImageSpaceEffect base Render"),
	(0x00C04570, "ImageSpaceShader constructor"),
	(0x004EC800, "Underwater render-state transaction"),
	(0x00452DC0, "Underwater fog scalar producer"),
	(0x009B88A0, "Underwater scalar source A"),
	(0x00812870, "Underwater scalar source B"),
]

GLOBALS = [
	(0x011F9438, "BSShaderManager current render target"),
	(0x011F91A8, "Rendered texture manager singleton"),
	(0x011F91AC, "ImageSpaceManager singleton"),
	(0x011F9614, "Underwater fog scalar output A"),
	(0x011F9618, "Underwater fog scalar output B"),
]

WINDOWS = [
	(0x00876136, "ProcessImageSpaceShaders callsite"),
	(0x00B979A0, "End-of-frame temporary target selection"),
	(0x00B97A01, "End-of-frame effect dispatch A"),
	(0x00B97A68, "End-of-frame effect dispatch B"),
	(0x00B975C2, "Image-space effect virtual dispatch"),
	(0x004EC8BD, "Underwater camera and fog setup entry"),
	(0x004EC8EE, "Underwater fog scalar publication"),
	(0x004EC91A, "Underwater render transaction setup"),
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

def decompile_at(addr_int, label, max_len=26000):
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
		inst = listing.getInstructionContaining(ref.getFromAddress())
		text = inst.toString() if inst is not None else ""
		write("  %s @ 0x%08x (in %s) %s" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname, text))
		count += 1
		if count >= 120:
			write("  ... (truncated)")
			break
	write("  Total shown: %d refs" % count)

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

def audit_functions():
	index = 0
	while index < len(FUNCTIONS):
		item = FUNCTIONS[index]
		decompile_at(item[0], item[1])
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
		disasm_window(item[0], 24, 48, item[1])
		checkpoint_output()
		if monitor.isCancelled():
			return
		index += 1

def main():
	write("FNV ATMOSPHERE PHASE 2 CONTRACT AUDIT")
	write("")
	write("Questions:")
	write("1. Which native image-space input receives the post-world render target before HDR blend and exposure?")
	write("2. Which image-space paths read or replace the source alpha channel before final output?")
	write("3. Which branch and engine state select the underwater render transaction around 0x004EC800?")
	write("4. Is there a stable value-copy underwater flag that OMV can validate at the post-world boundary?")
	write("")
	write("Static-analysis limit:")
	write("Shader transfer behavior and DXVK surface values still require shader-bytecode review plus runtime telemetry. This script must not be treated as runtime proof.")
	checkpoint_output()
	audit_functions()
	if monitor.isCancelled():
		return
	audit_globals()
	if monitor.isCancelled():
		return
	audit_windows()
	checkpoint_output()
	print("Output written to %s (%d lines)" % (OUTPATH, len(output)))

try:
	main()
finally:
	checkpoint_output()
	decomp.dispose()
