# @category Analysis
# @description Bounded OMV follow-up for native sun coordinates, camera frustum scale, and world/first-person depth ownership

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
MAX_SCAN_INSTRUCTIONS = 5000

KNOWN = {
	0x00452DC0: "native two-float screen vector constructor",
	0x0045C670: "native renderer camera owner getter",
	0x006629F0: "native renderer camera pointer getter",
	0x00870BD0: "main render path and native sun projection owner",
	0x00873200: "Main::RenderWorldSceneGraph",
	0x00875110: "Main::RenderFirstPerson",
	0x00875FD0: "image-space render owner",
	0x00A6FAF0: "NiCamera matrix/frustum update candidate",
	0x00A6FDB0: "native world-to-screen projection",
	0x00B54B10: "shader camera contract uploader",
	0x00B8B1E0: "native sun screen global writer",
	0x00C03410: "native image-space sun screen global reader",
	0x00C52020: "camera depth/projection update owner",
	0x011F917C: "BSShaderManager current camera",
	0x012023F4: "native sun screen X",
	0x012023F8: "native sun screen Y",
}

DECOMPILE_TARGETS = [
	(0x00452DC0, "native two-float screen vector constructor", 8000),
	(0x00A6FAF0, "NiCamera matrix/frustum update candidate", 18000),
	(0x00A6FDB0, "native world-to-screen projection", 14000),
	(0x00B54B10, "shader camera contract uploader", 18000),
	(0x00B8B1E0, "native sun screen global writer", 8000),
	(0x00C03410, "native image-space sun screen global reader", 18000),
	(0x00C52020, "camera depth/projection update owner", 22000),
	(0x00873200, "Main::RenderWorldSceneGraph", 18000),
	(0x00875FD0, "image-space render owner", 22000),
]

REF_TARGETS = [
	(0x00452DC0, "native two-float screen vector constructor"),
	(0x00A6FAF0, "NiCamera matrix/frustum update candidate"),
	(0x00A6FDB0, "native world-to-screen projection"),
	(0x011F917C, "BSShaderManager current camera"),
	(0x012023F4, "native sun screen X"),
	(0x012023F8, "native sun screen Y"),
]

CALL_TARGETS = [
	(0x00870BD0, "main render path and native sun projection owner"),
	(0x00873200, "Main::RenderWorldSceneGraph"),
	(0x00875110, "Main::RenderFirstPerson"),
	(0x00875FD0, "image-space render owner"),
	(0x00A6FAF0, "NiCamera matrix/frustum update candidate"),
	(0x00B54B10, "shader camera contract uploader"),
	(0x00C52020, "camera depth/projection update owner"),
]

DISASM_WINDOWS = [
	(0x00871031, 8, 42, "native sun object virtual getter and world-position load"),
	(0x0087106D, 8, 42, "native sun projector selection and projection call"),
	(0x008710AF, 4, 20, "native sun screen globals write"),
	(0x00873200, 4, 34, "world render entry"),
	(0x00874E2D, 24, 24, "first-person setup frustum replacement"),
	(0x008752F2, 24, 24, "first-person render frustum replacement"),
	(0x00875B4C, 10, 60, "first-person camera/depth transition"),
	(0x00876119, 8, 32, "current camera write before image-space processing"),
	(0x00A6FAF0, 2, 42, "NiCamera frustum copy and effective near calculation"),
	(0x00C52336, 32, 90, "perspective frustum construction and NiCamera update"),
	(0x00C03546, 8, 20, "native image-space consumption of sun screen globals"),
]

CAMERA_SCAN_TARGETS = [
	(0x00A6FAF0, "NiCamera matrix/frustum update candidate"),
	(0x00A6FDB0, "native world-to-screen projection"),
	(0x00B54B10, "shader camera contract uploader"),
	(0x00C52020, "camera depth/projection update owner"),
	(0x00873200, "Main::RenderWorldSceneGraph"),
	(0x00875110, "Main::RenderFirstPerson"),
	(0x00875FD0, "image-space render owner"),
]

CAMERA_NEEDLES = [
	"0xd4",
	"0xd8",
	"0xdc",
	"0xe0",
	"0xe4",
	"0xe8",
	"0xec",
	"0xf0",
	"0xfc",
	"0x100",
	"0x104",
	"0x108",
	"0x10c",
	"0x110",
	"0x17",
]

def write(msg):
	output.append(msg)
	print(msg)

def get_function_at_or_containing(addr_int):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	return func

def label_for(addr_int):
	label = KNOWN.get(addr_int)
	if label is not None:
		return label
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is not None:
		return func.getName()
	return "unknown"

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
	while refs.hasNext():
		ref = refs.next()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		fname = from_func.getName() if from_func else "???"
		write("  %s @ 0x%08x (in %s)" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname))
		count += 1
		if count >= MAX_REFS:
			write("  ... [truncated at %d refs]" % MAX_REFS)
			break
	write("  Printed: %d refs" % count)

def find_and_print_calls_from(addr_int, label):
	func = get_function_at_or_containing(addr_int)
	write("")
	write("--- Calls FROM %s (0x%08x) ---" % (label, addr_int))
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext() and count < MAX_CALLS:
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, label_for(tgt)))
				count += 1
				if count >= MAX_CALLS:
					break
	if count >= MAX_CALLS:
		write("  ... [truncated at %d calls]" % MAX_CALLS)
	write("  Printed: %d calls" % count)

def disassemble_window(center_int, before_count, after_count, label):
	center = toAddr(center_int)
	inst = listing.getInstructionContaining(center)
	write("")
	write("-" * 70)
	write("Disassembly %s around 0x%08x" % (label, center_int))
	write("-" * 70)
	if inst is None:
		write("  [instruction not found]")
		return
	start = inst
	steps = 0
	while steps < before_count:
		previous = start.getPrevious()
		if previous is None:
			break
		start = previous
		steps += 1
	current = start
	printed = 0
	limit = before_count + after_count + 1
	while current is not None and printed < limit:
		address = current.getAddress().getOffset()
		marker = " << TARGET" if address == inst.getAddress().getOffset() else ""
		write("  0x%08x: %-52s%s" % (address, current.toString(), marker))
		current = current.getNext()
		printed += 1

def scan_camera_operands(addr_int, label):
	func = get_function_at_or_containing(addr_int)
	write("")
	write("=" * 70)
	write("CAMERA/DEPTH OPERAND SCAN: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	matches = 0
	while inst_iter.hasNext() and count < MAX_SCAN_INSTRUCTIONS:
		inst = inst_iter.next()
		text = inst.toString().lower()
		matched = False
		for needle in CAMERA_NEEDLES:
			if needle in text:
				matched = True
				break
		if matched:
			write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
			matches += 1
		count += 1
	write("  Matched: %d instructions (scanned %d)" % (matches, count))

def run_decompile_targets():
	for item in DECOMPILE_TARGETS:
		decompile_at(item[0], item[1], item[2])

def run_ref_targets():
	for item in REF_TARGETS:
		find_refs_to(item[0], item[1])

def run_call_targets():
	for item in CALL_TARGETS:
		find_and_print_calls_from(item[0], item[1])

def run_disasm_windows():
	for item in DISASM_WINDOWS:
		disassemble_window(item[0], item[1], item[2], item[3])

def run_camera_scans():
	for item in CAMERA_SCAN_TARGETS:
		scan_camera_operands(item[0], item[1])

write("FNV OMV RUNTIME ARTIFACTS FOLLOW-UP EVIDENCE PACK")
write("")
write("This audit is bounded and non-recursive. No caller graph recursion is performed.")
write("Decompiler timeout per selected function: %d seconds" % DECOMPILE_TIMEOUT_SECONDS)
write("Reference cap per target: %d" % MAX_REFS)
write("Call cap per function: %d" % MAX_CALLS)
write("")
write("Questions covered:")
write("1. What exact coordinate pair does vanilla publish and consume for image-space sun effects?")
write("2. Are NiCamera frustum fields slopes or near-plane extents requiring division by near Z?")
write("3. Which camera is current at world, first-person, and image-space boundaries?")
write("4. Which native paths mutate projection/depth state around OMV depth resolves?")

run_ref_targets()
run_disasm_windows()
run_decompile_targets()
run_call_targets()
run_camera_scans()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_omv_runtime_artifacts_followup_evidence_pack.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("")
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
