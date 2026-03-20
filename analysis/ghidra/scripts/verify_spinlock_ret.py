# @category Analysis
# @description Check if SpinLock_Acquire uses RET or RET N (stack cleanup)

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()

output = []

def write(msg):
	output.append(msg)
	print(msg)

write("=" * 70)
write("SpinLock_Acquire RET instruction check")
write("=" * 70)

# Disassemble FUN_0040fbf0 completely (149 bytes)
write("")
write("Full disassembly of FUN_0040fbf0 (SpinLock_Acquire):")
inst = listing.getInstructionAt(toAddr(0x0040fbf0))
count = 0
while inst is not None and count < 80:
	off = inst.getAddress().getOffset()
	if off >= 0x0040fc90:
		break
	mnem = inst.getMnemonicString()
	write("  0x%08x: %s" % (off, inst.toString()))
	if mnem == "RET":
		write("  ^^^ RET found! Check if it has an operand (RET N = stack cleanup)")
		ops = inst.getNumOperands()
		if ops > 0:
			write("  RET operand: %s" % inst.getDefaultOperandRepresentation(0))
		else:
			write("  RET with no operand (no stack cleanup)")
	count += 1
	inst = inst.getNext()

# Also check all call sites of FUN_0040fbf0 for PUSH before CALL pattern
write("")
write("=" * 70)
write("Call sites of FUN_0040fbf0 — check for PUSH before CALL")
write("=" * 70)

refs = getReferencesTo(toAddr(0x0040fbf0))
for ref in refs:
	if not ref.getReferenceType().isCall():
		continue
	call_addr = ref.getFromAddress()
	func = fm.getFunctionContaining(call_addr)
	fname = func.getName() if func else "???"
	write("")
	write("--- Call at 0x%08x in %s ---" % (call_addr.getOffset(), fname))
	# Show 5 instructions before the CALL
	addr = toAddr(call_addr.getOffset() - 20)
	inst = listing.getInstructionAfter(addr)
	while inst is not None and inst.getAddress().getOffset() <= call_addr.getOffset() + 4:
		marker = " <<< CALL" if inst.getAddress().getOffset() == call_addr.getOffset() else ""
		write("  0x%08x: %s%s" % (inst.getAddress().getOffset(), inst.toString(), marker))
		inst = inst.getNext()

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/verify_spinlock_ret.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Wrote %d lines to %s" % (len(output), outpath))
