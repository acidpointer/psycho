# @category Analysis
# @description Resolve FNV ImageSpaceShader vtables and prove native per-pass render-state setup

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

IMAGE_SPACE_SHADER_CONSTRUCTOR = 0x00C04570
IMAGE_SPACE_EFFECT_RENDER = 0x00BA3F20
BS_SHADER_VTABLE = 0x010BC8F8
IMAGE_SPACE_EFFECT_VTABLE = 0x010B0318

def write(msg):
	output.append(msg)
	print(msg)

def decompile_at(addr_int, label, max_len=20000):
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

def read_pointer(addr_int):
	return memory.getInt(toAddr(addr_int)) & 0xffffffff

def print_vtable(base, start_index, end_index, label):
	write("")
	write("=" * 70)
	write("%s @ 0x%08x" % (label, base))
	write("=" * 70)
	index = start_index
	while index <= end_index:
		slot = base + index * 4
		target = read_pointer(slot)
		func = fm.getFunctionAt(toAddr(target))
		name = func.getName() if func else "???"
		write("  [%02d] slot=0x%08x target=0x%08x %s" % (index, slot, target, name))
		index += 1

def audit_vtable_targets(base, start_index, end_index, label):
	index = start_index
	while index <= end_index:
		target = read_pointer(base + index * 4)
		entry_label = "%s[%d]" % (label, index)
		decompile_at(target, entry_label)
		find_and_print_calls_from(target, entry_label)
		find_refs_to(target, entry_label)
		index += 1

def print_header():
	write("FNV IMAGE-SPACE PASS STATE VTABLE FOLLOW-UP")
	write("")
	write("Known ImageSpaceShader layout from the reference headers:")
	write("  BSShader::ReloadShaders is primary vtable entry 72")
	write("  ImageSpaceShader::LoadShaders through Func_84 are entries 79 through 84")
	write("  ImageSpaceShader::PresetStages is primary vtable entry 83")
	write("  ImageSpaceEffect::Render is secondary vtable entry 1")
	write("")
	write("Questions:")
	write("1. What functions occupy the native ImageSpaceShader render and PresetStages slots?")
	write("2. Which D3D/BS render states are applied and restored for every native image-space pass?")
	write("3. Does the native pass explicitly disable alpha test, stencil test, and scissor test?")
	write("4. Which behavior must OMV reproduce when bypassing the native ImageSpaceEffect pipeline?")

def main():
	print_header()
	decompile_at(IMAGE_SPACE_SHADER_CONSTRUCTOR, "ImageSpaceShader constructor")
	find_and_print_calls_from(IMAGE_SPACE_SHADER_CONSTRUCTOR, "ImageSpaceShader constructor")
	decompile_at(IMAGE_SPACE_EFFECT_RENDER, "ImageSpaceEffect base Render")
	find_and_print_calls_from(IMAGE_SPACE_EFFECT_RENDER, "ImageSpaceEffect base Render")
	print_vtable(BS_SHADER_VTABLE, 60, 84, "ImageSpaceShader primary vtable")
	print_vtable(IMAGE_SPACE_EFFECT_VTABLE, 0, 7, "ImageSpaceShader ImageSpaceEffect vtable")
	audit_vtable_targets(BS_SHADER_VTABLE, 72, 84, "ImageSpaceShader primary vtable")
	audit_vtable_targets(IMAGE_SPACE_EFFECT_VTABLE, 0, 7, "ImageSpaceShader ImageSpaceEffect vtable")
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_image_space_pass_state_vtable_followup.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("")
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
