# @category Analysis
# @description Audit FNV graphics hook collision surface and inline-hook safety for Psycho Graphics

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x005BF43C: "ShaderLoader ReloadShaders callsite A",
	0x005C5A39: "ShaderLoader ReloadShaders callsite B",
	0x008706B0: "Main::Render",
	0x00870AE8: "RenderWorldSceneGraph callsite main world path",
	0x00870B21: "RenderFirstPerson callsite main world path",
	0x00870E18: "RenderWorldSceneGraph callsite alternate world path",
	0x00873200: "Main::RenderWorldSceneGraph",
	0x00875110: "Main::RenderFirstPerson",
	0x00875E40: "DepthResolve RenderDepthOfField jump",
	0x00B54090: "ImageSpaceManager::GetDepthTexture",
	0x00B55AC0: "ImageSpaceManager::ProcessImageSpaceShaders",
	0x00B64057: "DepthResolve RegisterObject skip depth groups patch",
	0x00B65C43: "DepthResolve alpha blend skip patch A",
	0x00B65C4C: "DepthResolve alpha blend skip patch B",
	0x00B65C60: "BSShaderAccumulator::RenderPostDepthGroups",
	0x00B65D62: "RenderGeometryGroup group=9 alpha=1 callsite",
	0x00B65DAD: "RenderGeometryGroup group=1 alpha=0 callsite",
	0x00B6657D: "DepthResolve replacement call A",
	0x00B665AC: "DepthResolve replacement call B",
	0x00B639E0: "BSShaderAccumulator::RenderGeometryGroup",
	0x00B97900: "ImageSpaceManager::RenderEndOfFrameEffects",
	0x00BE0FE0: "BSShader::CreateVertexShader",
	0x00BE1750: "BSShader::CreatePixelShader",
}

FUNCTION_TARGETS = [
	0x00873200,
	0x00875110,
	0x00B55AC0,
	0x00B639E0,
	0x00B65C60,
	0x00B97900,
	0x008706B0,
]

PATCH_AND_CALLSITE_TARGETS = [
	0x00870AE8,
	0x00870B21,
	0x00870E18,
	0x00B65D62,
	0x00B65DAD,
	0x00B6657D,
	0x00B665AC,
	0x00B65C43,
	0x00B65C4C,
	0x00B64057,
	0x00B54090,
	0x00875E40,
	0x00B97900,
	0x00BE0FE0,
	0x00BE1750,
	0x005BF43C,
	0x005C5A39,
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

def scan_callers_to(addr_int, label, max_callers):
	write("")
	write("=" * 70)
	write("CALLER SCAN: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		if not ref.getReferenceType().isCall():
			continue
		from_addr = ref.getFromAddress().getOffset()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		fname = from_func.getName() if from_func else "???"
		write("")
		write("Caller %d: 0x%08x in %s" % (count + 1, from_addr, fname))
		disasm_window(from_addr, 10, 24, "caller of %s" % label)
		count += 1
		if count >= max_callers:
			write("  ... caller scan truncated")
			break
	write("Total callers printed: %d" % count)

def instruction_is_bad_for_entry_hook(inst):
	mnemonic = inst.getMnemonicString().lower()
	if mnemonic == "ret" or mnemonic == "retf":
		return True
	if mnemonic == "jmp":
		return True
	if mnemonic.startswith("loop"):
		return True
	return False

def print_inline_hook_probe(addr_int, label):
	write("")
	write("=" * 70)
	write("INLINE HOOK PROLOGUE PROBE: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	write("First 32 bytes: %s" % read_bytes(addr_int, 32))
	inst = listing.getInstructionAt(toAddr(addr_int))
	total = 0
	idx = 0
	unsafe = False
	while inst is not None and total < 5:
		addr = inst.getAddress().getOffset()
		length = inst.getLength()
		bad = instruction_is_bad_for_entry_hook(inst)
		if bad:
			unsafe = True
		write("  steal[%d] 0x%08x len=%d flow=%s text=%s%s" % (idx, addr, length, inst.getFlowType().toString(), inst.toString(), "  [BAD]" if bad else ""))
		total += length
		inst = inst.getNext()
		idx += 1
	write("  stolen_len_for_rel32_jmp=%d" % total)
	if unsafe:
		write("  RESULT: unsafe for simple entry hook; terminating jump/ret/loop in stolen bytes")
	else:
		write("  RESULT: prologue is structurally hookable by a normal 5-byte x86 detour")

def print_callsite_probe(addr_int, label):
	write("")
	write("=" * 70)
	write("PATCH/CALLSITE PROBE: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	write("Bytes @ target: %s" % read_bytes(addr_int, 16))
	inst = listing.getInstructionAt(toAddr(addr_int))
	if inst is None:
		write("  [no instruction starts exactly here]")
		disasm_window(addr_int, 6, 10, label)
		return
	write("  Instruction: %s len=%d flow=%s" % (inst.toString(), inst.getLength(), inst.getFlowType().toString()))
	refs = inst.getReferencesFrom()
	ref_count = 0
	for ref in refs:
		ref_count += 1
		write("  RefFrom: %s -> 0x%08x %s" % (ref.getReferenceType(), ref.getToAddress().getOffset(), label_for(ref.getToAddress().getOffset())))
	if ref_count == 0:
		write("  RefFrom: none")
	disasm_window(addr_int, 8, 18, label)

def audit_function_targets():
	idx = 0
	while idx < len(FUNCTION_TARGETS):
		addr = FUNCTION_TARGETS[idx]
		print_inline_hook_probe(addr, label_for(addr))
		find_refs_to(addr, label_for(addr))
		scan_callers_to(addr, label_for(addr), 12)
		disasm_window(addr, 0, 24, "function entry %s" % label_for(addr))
		idx += 1

def audit_patch_targets():
	idx = 0
	while idx < len(PATCH_AND_CALLSITE_TARGETS):
		addr = PATCH_AND_CALLSITE_TARGETS[idx]
		print_callsite_probe(addr, label_for(addr))
		idx += 1

def audit_decompilation():
	decompile_at(0x008706B0, "Main::Render")
	decompile_at(0x00873200, "Main::RenderWorldSceneGraph")
	decompile_at(0x00875110, "Main::RenderFirstPerson")
	decompile_at(0x00B55AC0, "ImageSpaceManager::ProcessImageSpaceShaders")
	decompile_at(0x00B97900, "ImageSpaceManager::RenderEndOfFrameEffects")
	decompile_at(0x00B65C60, "BSShaderAccumulator::RenderPostDepthGroups")
	find_and_print_calls_from(0x00B55AC0, "ImageSpaceManager::ProcessImageSpaceShaders")
	find_and_print_calls_from(0x00B97900, "ImageSpaceManager::RenderEndOfFrameEffects")
	find_and_print_calls_from(0x00B65C60, "BSShaderAccumulator::RenderPostDepthGroups")

def print_header():
	write("FNV GRAPHICS HOOK COLLISION SURFACE AUDIT")
	write("")
	write("Questions:")
	write("1. Are Psycho's current function-entry hook points structurally hookable in vanilla code?")
	write("2. Which hook points collide with DepthResolve, Shader Loader, or TESReloaded/NewVegasReloaded known addresses?")
	write("3. Which callsites can be used as lower-collision alternatives if function-entry chaining is unsafe?")
	write("")
	write("Static limitation:")
	write("This script cannot see runtime detours from loaded DLLs. It proves vanilla code shape and collision surface only.")

def main():
	print_header()
	audit_function_targets()
	audit_patch_targets()
	audit_decompilation()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_hook_collision_surface_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("")
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
