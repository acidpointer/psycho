# @category Analysis
# @description Trace QueuedTexture -> NiSourceTexture -> NiPixelData access path
#
# Crash: 0x00ED2C9E MOVDQA [EDI],XMM0 with EDI=0
# Return addr: 0x00AA22A2 (BSFile::Read or similar)
# NiPixelData refcount=0, NiSourceTexture refcount=0
# BSTaskManagerThread loading "test15.dds"
#
# Need to verify:
# 1. How does QueuedTexture reference NiSourceTexture? (NiPointer or raw?)
# 2. What does BSTaskManagerThread read from NiSourceTexture during task?
# 3. What exactly is at 0x00AA22A2 and what leads to the memcpy crash?
# 4. Does NiPixelData destructor zero its buffer pointer?
# 5. Is there a NULL check that vanilla relies on?

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)
listing = currentProgram.getListing()

output = []

def write(msg):
	output.append(msg)
	print(msg)

def decompile_at(addr_int, label, max_len=6000):
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
	entry = func.getEntryPoint().getOffset()
	sz = func.getBody().getNumAddresses()
	write("  Function: %s, Size: %d bytes" % (func.getName(), sz))
	write("  Entry: 0x%08x" % entry)
	result = decomp.decompileFunction(func, 60, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		write(code[:max_len])
	else:
		write("  [decompilation failed]")

def disasm_range(start_int, count=25):
	inst = listing.getInstructionAt(toAddr(start_int))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(start_int - 1))
	for i in range(count):
		if inst is None:
			break
		write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
		inst = inst.getNext()

def find_calls_from(addr_int, label):
	addr = toAddr(addr_int)
	func = fm.getFunctionAt(addr)
	if func is None:
		func = fm.getFunctionContaining(addr)
	write("")
	write("--- Calls FROM %s (0x%08x) ---" % (label, addr_int))
	if func is None:
		write("  [function not found]")
		return
	body = func.getBody()
	addr_iter = body.getAddresses(True)
	count = 0
	while addr_iter.hasNext():
		a = addr_iter.next()
		inst = listing.getInstructionAt(a)
		if inst is None:
			continue
		if not inst.getFlowType().isCall():
			continue
		refs_from = inst.getReferencesFrom()
		for r in refs_from:
			target = r.getToAddress().getOffset()
			target_func = fm.getFunctionAt(toAddr(target))
			target_name = target_func.getName() if target_func else "unknown_0x%08x" % target
			write("  CALL 0x%08x -> %s (from 0x%08x)" % (target, target_name, a.getOffset()))
			count += 1
	write("  Total: %d calls" % count)

def find_xrefs_to(addr_int, label, limit=15):
	addr = toAddr(addr_int)
	refs = getReferencesTo(addr)
	write("")
	write("--- XRefs to %s (0x%08x) ---" % (label, addr_int))
	count = 0
	for ref in refs:
		from_addr = ref.getFromAddress()
		func = fm.getFunctionContaining(from_addr)
		fname = func.getName() if func else "???"
		write("  %s @ 0x%s (in %s)" % (ref.getReferenceType(), from_addr, fname))
		count += 1
		if count >= limit:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)


write("=" * 70)
write("QueuedTexture -> NiSourceTexture -> NiPixelData LIFECYCLE")
write("=" * 70)

# SECTION 1: QueuedTexture constructor - how is NiSourceTexture stored?
write("")
write("# SECTION 1: QueuedTexture constructor (FUN_0043bd10)")
write("# vtable assigned at 0x0043bd5d. What fields are set?")
decompile_at(0x0043BD10, "QueuedTexture_ctor")

# SECTION 2: FUN_0043be60 - another QueuedTexture init
write("")
write("# SECTION 2: FUN_0043be60 - QueuedTexture init 2")
decompile_at(0x0043BE60, "QueuedTexture_init2")

# SECTION 3: FUN_0043bef0 - QueuedTexture init 3
write("")
write("# SECTION 3: FUN_0043bef0 - QueuedTexture init 3")
decompile_at(0x0043BEF0, "QueuedTexture_init3")

# SECTION 4: QueuedTexture task body - what does BSTaskManagerThread do?
# FUN_0043c050 (vtable+0x20 = entry [8])
write("")
write("# SECTION 4: FUN_0043c050 - QueuedTexture task body (full)")
decompile_at(0x0043C050, "QueuedTexture_TaskBody")
find_calls_from(0x0043C050, "QueuedTexture_TaskBody")

# SECTION 5: FUN_0055b980 - what does this return?
# Called first in task body: iVar2 = FUN_0055b980((int)param_1)
write("")
write("# SECTION 5: FUN_0055b980 - get NiSourceTexture from QueuedTexture?")
decompile_at(0x0055B980, "GetNiSourceTexture")

# SECTION 6: FUN_00448ed0 - called with DAT_011c3b3c
# cVar1 = FUN_00448ed0(DAT_011c3b3c, uVar3, (int)pvVar5)
write("")
write("# SECTION 6: FUN_00448ed0 - texture load dispatch")
decompile_at(0x00448ED0, "TextureLoadDispatch")

# SECTION 7: FUN_0043c100 and FUN_0043c0d0 - post-processing
write("")
write("# SECTION 7: FUN_0043c100 - post-load handler")
decompile_at(0x0043C100, "PostLoad_0043c100")

write("")
write("# SECTION 7b: FUN_0043c0d0 - secondary handler")
decompile_at(0x0043C0D0, "PostLoad_0043c0d0")

# SECTION 8: 0x00AA22A2 crash caller - what function is this?
write("")
write("# SECTION 8: 0x00AA22A2 - crash return address (BSFile::Read area)")
decompile_at(0x00AA22A2, "CrashCaller_AA22A2")
find_calls_from(0x00AA22A2, "CrashCaller_AA22A2")

# SECTION 9: NiPixelData destructor - does it zero its buffer?
write("")
write("# SECTION 9: NiPixelData destructor (vtable 0x0109DBB4)")
write("# vtable[1] is the destructor")
dtor_addr = getInt(toAddr(0x0109DBB4 + 4)) & 0xFFFFFFFF
write("  NiPixelData vtable[1] = 0x%08x" % dtor_addr)
decompile_at(dtor_addr, "NiPixelData_dtor")

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/queuedtexture_nisource_lifecycle.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
