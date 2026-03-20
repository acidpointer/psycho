# @category Analysis
# @description Research hooking AFTER AI thread join for cell unloading.
# Current hook at FUN_008705d0 runs BEFORE AI join.
# AI join at FUN_008c7990 (0x0086ee4e).
# Can we add a second hook AFTER the join for safe cell unloading?
#
# Options:
# A) Hook FUN_008c7990 itself — wrap with our cell unload after original
# B) Hook FUN_0086f6a0 (post-AI, called at 0x0086ee62)
# C) Check DAT_011dfa19 flag (set to 0 by join, 1 by dispatch)

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def write(msg):
	output.append(msg)
	print(msg)

def decompile_at(addr_int, label, max_len=10000):
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
	write("  Function: %s, Size: %d bytes" % (func.getName(), func.getBody().getNumAddresses()))
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		write(code[:max_len])
	else:
		write("  [decompilation failed]")

def find_xrefs_to(addr_int, label, limit=20):
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
write("POST-AI-JOIN HOOK POSITION RESEARCH")
write("=" * 70)
write("")
write("Frame: ...RENDER -> OUR_HOOK(008705d0) -> AI_JOIN(008c7990) -> POST_AI(0086f6a0)")
write("")
write("Can we do cell unloading AFTER AI join?")

# SECTION 1: FUN_008c7990 hookability
write("")
write("#" * 70)
write("# SECTION 1: FUN_008c7990 — can we hook it?")
write("# 72 bytes, fastcall. How many callers? Only per-frame or also elsewhere?")
write("#" * 70)

decompile_at(0x008C7990, "AIThreadJoin_008c7990")
find_xrefs_to(0x008C7990, "AIThreadJoin_008c7990")

# SECTION 2: FUN_0086f6a0 — post-AI cleanup, hookable?
write("")
write("#" * 70)
write("# SECTION 2: FUN_0086f6a0 — post-AI, called at 0x0086ee62")
write("# Is it safe for cell unloading + SceneGraphInvalidate?")
write("#" * 70)

decompile_at(0x0086F6A0, "PostAI_0086f6a0")
find_xrefs_to(0x0086F6A0, "PostAI_0086f6a0")

# SECTION 3: DAT_011dfa19 — AI active flag lifecycle
write("")
write("#" * 70)
write("# SECTION 3: DAT_011dfa19 — when is it set/cleared?")
write("# FUN_008c7990 clears it. Who sets it?")
write("#" * 70)

find_xrefs_to(0x011DFA19, "DAT_011dfa19")

# SECTION 4: What runs between AI join and post-AI?
write("")
write("#" * 70)
write("# SECTION 4: Disassembly 0x0086ee4e to 0x0086ee70")
write("# What happens between AI join and FUN_0086f6a0 call?")
write("#" * 70)

listing = currentProgram.getListing()
write("")
write("--- Disasm 0x0086ee40 to 0x0086ee80 ---")
addr = toAddr(0x0086ee40)
end_addr = toAddr(0x0086ee80)
while addr.compareTo(end_addr) < 0:
	inst = listing.getInstructionAt(addr)
	if inst is not None:
		mnemonic = inst.getMnemonicString()
		ops = ""
		for i in range(inst.getNumOperands()):
			if i > 0:
				ops = ops + ", "
			ops = ops + inst.getDefaultOperandRepresentation(i)
		write("  0x%s  %s %s" % (addr, mnemonic, ops))
		addr = addr.add(inst.getLength())
	else:
		addr = addr.add(1)

# SECTION 5: FUN_008ca300 — single-thread alternative to AI join
write("")
write("#" * 70)
write("# SECTION 5: FUN_008ca300 — called when processor count == 1")
write("# (instead of AI dispatch+join)")
write("#" * 70)

decompile_at(0x008CA300, "SingleThread_008ca300")

# SECTION 6: The conditional around AI dispatch and join
write("")
write("#" * 70)
write("# SECTION 6: Full conditional block around AI dispatch/join")
write("# bVar1 controls whether AI is dispatched")
write("#" * 70)

write("")
write("--- Disasm 0x0086ec50 to 0x0086eca0 (AI dispatch block) ---")
addr = toAddr(0x0086ec50)
end_addr = toAddr(0x0086eca0)
while addr.compareTo(end_addr) < 0:
	inst = listing.getInstructionAt(addr)
	if inst is not None:
		mnemonic = inst.getMnemonicString()
		ops = ""
		for i in range(inst.getNumOperands()):
			if i > 0:
				ops = ops + ", "
			ops = ops + inst.getDefaultOperandRepresentation(i)
		write("  0x%s  %s %s" % (addr, mnemonic, ops))
		addr = addr.add(inst.getLength())
	else:
		addr = addr.add(1)

# SECTION 7: FUN_00870610 — called right after FUN_0086f6a0
write("")
write("#" * 70)
write("# SECTION 7: FUN_00870610 — called at 0x0086ee6a, after PostAI")
write("# Could this be a better hook point?")
write("#" * 70)

decompile_at(0x00870610, "PostPostAI_00870610")
find_xrefs_to(0x00870610, "PostPostAI_00870610")

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/post_ai_join_hook.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
print("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
