# @category Analysis
# @description Bounded OMV evidence pack for PBR draw ownership plus remaining sun and depth helper contracts

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

DECOMPILE_TIMEOUT_SECONDS = 20
MAX_REFS = 48
MAX_CALLS = 160
MAX_FUNCTION_INSTRUCTIONS = 60000
MAX_CONTRACT_MATCHES = 220

KNOWN = {
	0x0045C670: "native current camera/projector getter",
	0x00559450: "pointer slot dereference helper",
	0x006629F0: "native point transform helper wrapper",
	0x00872F50: "world render target setup and current target writer",
	0x00A29680: "current render target transition helper",
	0x00B68660: "PPLighting six material texture-array writer",
	0x00B6B260: "BSRenderedTexture::GetRenderTargetGroup",
	0x00B6B790: "BSRenderedTexture::StopOffscreen",
	0x00B6B8D0: "BSRenderedTexture::StartOffscreen",
	0x00B73FB0: "PPLighting vertex shader table setup",
	0x00B785E0: "PPLighting pixel shader table setup",
	0x00BA8C50: "pass-entry reused-entry array setter",
	0x00BA8EC0: "pass-entry constructor",
	0x00BA9EE0: "PPLighting pass-entry append/reuse helper",
	0x00BDAF10: "PPLighting material predicate and layer selector",
	0x00BDB4A0: "PPLighting selector setup F0 family",
	0x00BDF790: "PPLighting selector and pass-entry driver F4 family",
	0x00BD4BA0: "current pass shader-interface apply",
	0x00BE0FE0: "BSShader::CreateVertexShader",
	0x00BE1750: "BSShader::CreatePixelShader",
	0x00BE1F90: "BSShader::SetShaders",
	0x00E7DC90: "post-texture sampler helper A",
	0x00E7E940: "post-texture sampler helper B",
	0x00E7EA00: "pass-entry texture record resolver",
	0x00E826D0: "shader-interface field apply dispatcher",
	0x00E88A20: "NiDX9RenderState::SetTexture",
	0x00E89060: "texture stage state tracker getter",
	0x00E90850: "current NiD3DPass writer",
	0x011FDA48: "PPLighting pixel shader group A",
	0x011FDB08: "PPLighting pixel shader group B",
	0x011FDD88: "PPLighting vertex shader group A",
	0x011FDE04: "PPLighting vertex shader group B",
	0x011FDE5C: "PPLighting vertex shader group C",
	0x0126F6C0: "texture record owner global",
	0x0126F6C4: "texture record state global A",
	0x0126F6C8: "texture record state global B",
	0x0126F74C: "current NiD3DPass global",
}

DECOMPILE_TARGETS = [
	(0x0045C670, "native current camera/projector getter", 6000),
	(0x00559450, "pointer slot dereference helper", 6000),
	(0x006629F0, "native point transform helper wrapper", 8000),
	(0x00872F50, "world render target setup and current target writer", 18000),
	(0x00B6B260, "BSRenderedTexture::GetRenderTargetGroup", 10000),
	(0x00B68660, "PPLighting six material texture-array writer", 18000),
	(0x00BA8C50, "pass-entry reused-entry array setter", 14000),
	(0x00BA8EC0, "pass-entry constructor", 16000),
	(0x00BA9EE0, "PPLighting pass-entry append/reuse helper", 20000),
	(0x00BDAF10, "PPLighting material predicate and layer selector", 22000),
	(0x00BD4BA0, "current pass shader-interface apply", 24000),
	(0x00BE1F90, "BSShader::SetShaders", 18000),
	(0x00E7EA00, "pass-entry texture record resolver", 18000),
	(0x00E7DC90, "post-texture sampler helper A", 12000),
	(0x00E7E940, "post-texture sampler helper B", 12000),
	(0x00E826D0, "shader-interface field apply dispatcher", 18000),
	(0x00E88A20, "NiDX9RenderState::SetTexture", 14000),
	(0x00E90850, "current NiD3DPass writer", 16000),
]

CALL_LIST_TARGETS = [
	(0x00872F50, "world render target setup and current target writer"),
	(0x00B68660, "PPLighting six material texture-array writer"),
	(0x00BA9EE0, "PPLighting pass-entry append/reuse helper"),
	(0x00BDAF10, "PPLighting material predicate and layer selector"),
	(0x00BDB4A0, "PPLighting selector setup F0 family"),
	(0x00BDF790, "PPLighting selector and pass-entry driver F4 family"),
	(0x00BD4BA0, "current pass shader-interface apply"),
	(0x00BE1F90, "BSShader::SetShaders"),
	(0x00E7EA00, "pass-entry texture record resolver"),
	(0x00E826D0, "shader-interface field apply dispatcher"),
	(0x00E90850, "current NiD3DPass writer"),
]

REF_TARGETS = [
	(0x00B68660, "PPLighting six material texture-array writer"),
	(0x00BA8C50, "pass-entry reused-entry array setter"),
	(0x00BA8EC0, "pass-entry constructor"),
	(0x00BA9EE0, "PPLighting pass-entry append/reuse helper"),
	(0x00BDAF10, "PPLighting material predicate and layer selector"),
	(0x00BD4BA0, "current pass shader-interface apply"),
	(0x00BE1F90, "BSShader::SetShaders"),
	(0x00E7EA00, "pass-entry texture record resolver"),
	(0x00E88A20, "NiDX9RenderState::SetTexture"),
	(0x011FDA48, "PPLighting pixel shader group A"),
	(0x011FDB08, "PPLighting pixel shader group B"),
	(0x011FDD88, "PPLighting vertex shader group A"),
	(0x011FDE04, "PPLighting vertex shader group B"),
	(0x011FDE5C, "PPLighting vertex shader group C"),
	(0x0126F6C0, "texture record owner global"),
	(0x0126F6C4, "texture record state global A"),
	(0x0126F6C8, "texture record state global B"),
	(0x0126F74C, "current NiD3DPass global"),
]

DISASM_WINDOWS = [
	(0x0045C670, 4, 16, "native current camera/projector getter"),
	(0x00559450, 4, 16, "pointer slot dereference helper"),
	(0x006629F0, 4, 22, "native point transform helper wrapper"),
	(0x00872FDF, 18, 34, "current render target write"),
	(0x00B74000, 24, 24, "vertex shader group A creation"),
	(0x00B740B3, 24, 24, "vertex shader group B creation"),
	(0x00B7419F, 24, 24, "vertex shader group C creation"),
	(0x00B78720, 24, 24, "pixel shader group A creation"),
	(0x00B78907, 24, 24, "pixel shader group B creation"),
	(0x00BDB1C7, 18, 26, "terrain candidate 0x1F2 layer write"),
	(0x00BDB204, 18, 26, "terrain candidate 0x1F3 layer write"),
	(0x00BDB28E, 18, 26, "terrain candidate 0x1F4 layer write"),
	(0x00BDB334, 18, 26, "terrain candidate 0x1F5 layer write"),
	(0x00BD4C35, 18, 30, "current pass shader-interface read A"),
	(0x00BD4C7F, 18, 30, "current pass shader-interface read B"),
	(0x00BE1F90, 12, 50, "BSShader::SetShaders entry and pass reads"),
	(0x00E7EA2D, 20, 28, "pass texture-stage tracker lookup"),
	(0x00E7EAC7, 24, 30, "pass post-texture helper A"),
	(0x00E7EACE, 24, 30, "pass post-texture helper B"),
	(0x00E88A20, 12, 42, "NiDX9RenderState::SetTexture entry"),
	(0x00E90933, 20, 34, "current NiD3DPass write"),
]

WATCH_ADDRESSES = {
	0x00BA8C50: "pass-entry reused-entry array setter",
	0x00BA8EC0: "pass-entry constructor",
	0x00BA9EE0: "pass-entry append/reuse helper",
	0x00BDAF10: "material predicate/layer selector",
	0x00BD4BA0: "current pass shader-interface apply",
	0x00BE1F90: "BSShader::SetShaders",
	0x00E7DC90: "post-texture helper A",
	0x00E7E940: "post-texture helper B",
	0x00E7EA00: "pass-entry texture record resolver",
	0x00E826D0: "shader-interface apply dispatcher",
	0x00E88A20: "NiDX9RenderState::SetTexture",
	0x00E89060: "texture stage state tracker getter",
	0x011FDA48: "pixel shader group A",
	0x011FDB08: "pixel shader group B",
	0x011FDD88: "vertex shader group A",
	0x011FDE04: "vertex shader group B",
	0x011FDE5C: "vertex shader group C",
	0x0126F6C0: "texture record owner",
	0x0126F6C4: "texture record state A",
	0x0126F6C8: "texture record state B",
	0x0126F74C: "current NiD3DPass",
}

OFFSET_NEEDLES = [
	"0xac",
	"0xb0",
	"0xb4",
	"0xb8",
	"0xbc",
	"0xc0",
	"0xc4",
	"0xcc",
	"0x8c4",
]

CONTRACT_SCAN_TARGETS = [
	(0x00B68660, "PPLighting six material texture-array writer"),
	(0x00BA9EE0, "PPLighting pass-entry append/reuse helper"),
	(0x00BDAF10, "PPLighting material predicate and layer selector"),
	(0x00BDB4A0, "PPLighting selector setup F0 family"),
	(0x00BDF790, "PPLighting selector and pass-entry driver F4 family"),
	(0x00BD4BA0, "current pass shader-interface apply"),
	(0x00BE1F90, "BSShader::SetShaders"),
	(0x00E7EA00, "pass-entry texture record resolver"),
	(0x00E7DC90, "post-texture sampler helper A"),
	(0x00E7E940, "post-texture sampler helper B"),
	(0x00E826D0, "shader-interface field apply dispatcher"),
	(0x00E90850, "current NiD3DPass writer"),
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

def get_function_at_or_containing(addr_int):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	return func

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
	result = decomp.decompileFunction(func, DECOMPILE_TIMEOUT_SECONDS, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		write(code[:max_len])
		if len(code) > max_len:
			write("  ... [truncated, total chars=%d]" % len(code))
	else:
		write("  [decompilation failed or timed out after %d seconds]" % DECOMPILE_TIMEOUT_SECONDS)

def find_refs_to(addr_int, label):
	write("")
	write("-" * 70)
	write("References TO 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext() and count < MAX_REFS:
		ref = refs.next()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		fname = from_func.getName() if from_func else "???"
		write("  %s @ 0x%08x (in %s)" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname))
		count += 1
	if refs.hasNext():
		write("  ... [truncated at %d refs]" % MAX_REFS)
	write("  Printed: %d refs" % count)

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
	call_count = 0
	inst_count = 0
	while inst_iter.hasNext() and inst_count < MAX_FUNCTION_INSTRUCTIONS and call_count < MAX_CALLS:
		inst = inst_iter.next()
		inst_count += 1
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				name = label_for(tgt)
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, name))
				call_count += 1
				if call_count >= MAX_CALLS:
					break
	if inst_iter.hasNext():
		write("  ... [bounded scan stopped]")
	write("  Total printed: %d calls from %d instructions" % (call_count, inst_count))

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
	while inst is not None and count < before_count:
		prev = listing.getInstructionBefore(inst.getAddress())
		if prev is None:
			break
		inst = prev
		count += 1
	idx = 0
	limit = before_count + after_count + 1
	while inst is not None and idx < limit:
		addr_int = inst.getAddress().getOffset()
		marker = " << TARGET" if inst.getAddress().equals(toAddr(center_int)) else ""
		extra = ""
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				extra = "%s ; CALL 0x%08x %s" % (extra, tgt, label_for(tgt))
		write("  0x%08x: %-52s%s%s" % (addr_int, inst.toString(), marker, extra))
		inst = listing.getInstructionAfter(inst.getAddress())
		idx += 1

def instruction_matches_offsets(inst):
	text = inst.toString().lower()
	idx = 0
	while idx < len(OFFSET_NEEDLES):
		if OFFSET_NEEDLES[idx] in text:
			return True
		idx += 1
	return False

def watched_reference_text(inst):
	refs = inst.getReferencesFrom()
	parts = []
	for ref in refs:
		target = ref.getToAddress()
		if target is None:
			continue
		target_int = target.getOffset()
		label = WATCH_ADDRESSES.get(target_int)
		if label is not None:
			parts.append("%s -> 0x%08x %s" % (ref.getReferenceType(), target_int, label))
	return "; ".join(parts)

def scan_function_contract(addr_int, label):
	write("")
	write("=" * 70)
	write("ORDERED CONTRACT HITS: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	func = get_function_at_or_containing(addr_int)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	inst_count = 0
	match_count = 0
	while inst_iter.hasNext() and inst_count < MAX_FUNCTION_INSTRUCTIONS and match_count < MAX_CONTRACT_MATCHES:
		inst = inst_iter.next()
		inst_count += 1
		ref_text = watched_reference_text(inst)
		if ref_text != "" or instruction_matches_offsets(inst):
			write("  0x%08x: %-52s %s" % (inst.getAddress().getOffset(), inst.toString(), ref_text))
			match_count += 1
	if inst_iter.hasNext():
		write("  ... [bounded contract scan stopped]")
	write("  Total printed: %d hits from %d instructions" % (match_count, inst_count))

def run_decompile_targets():
	idx = 0
	while idx < len(DECOMPILE_TARGETS):
		if monitor.isCancelled():
			write("Cancelled before remaining decompilations")
			return
		item = DECOMPILE_TARGETS[idx]
		decompile_at(item[0], item[1], item[2])
		idx += 1

def run_call_lists():
	idx = 0
	while idx < len(CALL_LIST_TARGETS):
		if monitor.isCancelled():
			write("Cancelled before remaining call lists")
			return
		item = CALL_LIST_TARGETS[idx]
		find_and_print_calls_from(item[0], item[1])
		idx += 1

def run_refs():
	idx = 0
	while idx < len(REF_TARGETS):
		if monitor.isCancelled():
			write("Cancelled before remaining references")
			return
		item = REF_TARGETS[idx]
		find_refs_to(item[0], item[1])
		idx += 1

def run_disasm_windows():
	idx = 0
	while idx < len(DISASM_WINDOWS):
		if monitor.isCancelled():
			write("Cancelled before remaining disassembly windows")
			return
		item = DISASM_WINDOWS[idx]
		disasm_window(item[0], item[1], item[2], item[3])
		idx += 1

def run_contract_scans():
	idx = 0
	while idx < len(CONTRACT_SCAN_TARGETS):
		if monitor.isCancelled():
			write("Cancelled before remaining contract scans")
			return
		item = CONTRACT_SCAN_TARGETS[idx]
		scan_function_contract(item[0], item[1])
		idx += 1

def write_header():
	write("FNV OMV PBR AND SCENE FOLLOWUP EVIDENCE PACK")
	write("")
	write("This audit is deliberately bounded and non-recursive.")
	write("The large BDF790 selector is scanned linearly but is not decompiled.")
	write("Decompiler timeout per selected function: %d seconds" % DECOMPILE_TIMEOUT_SECONDS)
	write("Reference cap per target: %d" % MAX_REFS)
	write("Call cap per function: %d" % MAX_CALLS)
	write("")
	write("Questions covered:")
	write("1. What do the native sun camera/projector wrapper and pointer helper actually return?")
	write("2. How is the world current render target selected before OMV depth capture?")
	write("3. Which object/material data writes the six PPLighting texture arrays?")
	write("4. When is current NiD3DPass established relative to SetShaders and texture resolution?")
	write("5. Do selector, pass-entry, shader, and texture state belong to the same draw scope?")
	write("6. Which material offsets and resource records feed final texture-stage ownership?")
	write("7. Which terrain selector writes are distinct from general object shader pairs?")
	write("8. Which shader families and creation sites establish the native vertex/pixel ABI?")

def write_output():
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_omv_pbr_and_scene_followup_evidence_pack.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("")
	write("Output written to %s (%d lines)" % (outpath, len(output)))

def main():
	write_header()
	run_disasm_windows()
	run_refs()
	run_contract_scans()
	run_call_lists()
	run_decompile_targets()
	write_output()

def run():
	try:
		main()
	finally:
		decomp.dispose()

run()
