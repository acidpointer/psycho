# @category Analysis
# @description Verify exact signatures of all 8 hooked functions. Wrong calling convention = stack corruption.

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def write(msg):
	output.append(msg)
	print(msg)

def verify_func(addr_int, label, expected_conv, expected_params):
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
	conv = func.getCallingConventionName()
	sig = func.getSignature()
	params = func.getParameters()
	param_count = len(params)
	write("  Convention: %s (expected: %s) %s" % (conv, expected_conv, "OK" if conv == expected_conv else "MISMATCH!"))
	write("  Param count: %d (expected: %d) %s" % (param_count, expected_params, "OK" if param_count == expected_params else "MISMATCH!"))
	write("  Signature: %s" % sig)
	write("  Parameters:")
	for p in params:
		write("    %s: %s (storage: %s)" % (p.getName(), p.getDataType(), p.getVariableStorage()))
	# Show first bytes for prologue verification
	listing = currentProgram.getListing()
	write("  First 20 bytes (disassembly):")
	inst = listing.getInstructionAt(toAddr(faddr))
	byte_count = 0
	while inst is not None and byte_count < 20:
		iaddr = inst.getAddress().getOffset()
		ilen = inst.getLength()
		write("    0x%08x: %-6s %s" % (iaddr, inst.getMnemonicString(), str(inst)))
		byte_count += ilen
		inst = inst.getNext()
	# Decompile
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		write(code[:3000])
	else:
		write("  [decompilation failed]")


write("=" * 70)
write("HOOK SIGNATURE VERIFICATION")
write("Wrong calling convention or param count = stack corruption")
write("=" * 70)

write("")
write("#" * 70)
write("# HAVOK HOOKS (3 functions)")
write("#" * 70)

# FUN_00c94bd0: hkpWorld::addEntity
# Our hook: thiscall(this, i32, i32, i32) = 3 stack params
verify_func(0x00c94bd0, "hkpWorld_addEntity", "__thiscall", 4)

# FUN_00c40b70: bhkCollisionObject destructor
# Our hook: thiscall(this, u8) = 1 stack param
verify_func(0x00c40b70, "bhkCollisionObject_dtor", "__thiscall", 2)

# FUN_00cbf860: cached raycast
# Our hook: thiscall(this, ptr, ptr, i32, u32, u32) = 5 stack params
verify_func(0x00cbf860, "havok_raycast", "__thiscall", 6)

write("")
write("#" * 70)
write("# ACTOR SYNC HOOKS (5 functions)")
write("#" * 70)

# FUN_0096e870: actor downgrade
# Our hook: thiscall(this, ptr) = 1 stack param
verify_func(0x0096e870, "actor_downgrade", "__thiscall", 2)

# FUN_009784c0: process mgr update
# Our hook: fastcall(i32) = 0 stack params (ECX only)
verify_func(0x009784c0, "process_mgr_update", "__fastcall", 1)

# FUN_0096c330: AI Process 1
# Our hook: fastcall(i32) = 0 stack params
verify_func(0x0096c330, "ai_process1", "__fastcall", 1)

# FUN_0096cb50: AI Process 2
# Our hook: fastcall(i32) = 0 stack params
verify_func(0x0096cb50, "ai_process2", "__fastcall", 1)

# FUN_00453550: cell mgmt update
# Our hook: thiscall(this, f32) = 1 stack param
verify_func(0x00453550, "cell_mgmt_update", "__thiscall", 2)


outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/verify_havok_hook_sigs.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
