# @category Analysis
# @description Research texture cache hash table node layout for proper NULL-tolerant traversal

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
	entry = func.getEntryPoint().getOffset()
	sz = func.getBody().getNumAddresses()
	write("  Function: %s, Size: %d bytes" % (func.getName(), sz))
	write("  Entry: 0x%08x" % entry)
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		write(code[:max_len])
	else:
		write("  [decompilation failed]")

def disasm_range(start_int, count=30):
	listing = currentProgram.getListing()
	inst = listing.getInstructionAfter(toAddr(start_int - 1))
	for i in range(count):
		if inst is None:
			break
		write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
		inst = inst.getNext()


write("=" * 70)
write("HASH TABLE NODE LAYOUT — for proper NULL-tolerant find")
write("=" * 70)

# SECTION 1: FUN_00a61a60 full disasm — the find function we need to rewrite
write("")
write("#" * 70)
write("# SECTION 1: FUN_00a61a60 — full disasm (103 bytes)")
write("# Node layout: entry[0] = value_ptr, entry[1] = next_ptr")
write("# Value object: value[0] = ?, value[1] = key")
write("#" * 70)

decompile_at(0x00A61A60, "HashTableFind_Original")

write("")
write("Full disasm:")
disasm_range(0x00A61A60, 35)

# SECTION 2: Hash table ADD function — understand node structure
# FUN_00a62090 has WRITE to DAT_011f4468
write("")
write("#" * 70)
write("# SECTION 2: Hash table add/modify function — FUN_00a62090")
write("# How are nodes created? What's the node struct?")
write("#" * 70)

decompile_at(0x00A62090, "HashTable_AddOrModify")

# SECTION 3: The iterator function — FUN_00a619b0
# This traverses the hash table correctly — shows node layout
write("")
write("#" * 70)
write("# SECTION 3: Iterator FUN_00a619b0 — correct traversal pattern")
write("#" * 70)

decompile_at(0x00A619B0, "HashTable_Iterator")

# SECTION 4: Hash table node allocation — who creates nodes?
# FUN_00a61920 might be the insert/find-in-bucket function
write("")
write("#" * 70)
write("# SECTION 4: FUN_00a61920 — bucket operations")
write("#" * 70)

decompile_at(0x00A61920, "HashTable_BucketOp")

# SECTION 5: What exactly does value[0] contain?
# The crash reads *value → gets node_data_ptr → reads node_data_ptr[1] as key
# What is node_data_ptr? Is it the NiSourceTexture itself or a wrapper?
write("")
write("#" * 70)
write("# SECTION 5: FUN_00a61c50 and FUN_00a61cd0 — other hash table ops")
write("# These READ DAT_011f4468 — what do they do with entries?")
write("#" * 70)

decompile_at(0x00A61C50, "HashTable_Op1")
decompile_at(0x00A61CD0, "HashTable_Op2")

# SECTION 6: FUN_00a61f30 and FUN_00a61fb0 — more hash table readers
write("")
write("#" * 70)
write("# SECTION 6: More hash table operations")
write("#" * 70)

decompile_at(0x00A61F30, "HashTable_Op3")
decompile_at(0x00A61FB0, "HashTable_Op4")

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/hashtable_node_layout.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
