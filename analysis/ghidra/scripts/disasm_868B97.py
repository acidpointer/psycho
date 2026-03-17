# @category Analysis
# @description Disassemble around 0x00868B97

listing = currentProgram.getListing()
output = []

starts = [0x00868B80, 0x00868B85, 0x00868B88, 0x00868B90, 0x00868B94, 0x00868B95, 0x00868B96, 0x00868B97]
for s in starts:
	inst = listing.getInstructionAt(toAddr(s))
	if inst is not None:
		output.append("  0x%08x: %s" % (s, inst.toString()))

output.append("")
output.append("--- Sequential from 0x00868B80 ---")

addr = toAddr(0x00868B80)
count = 0
while count < 30:
	inst = listing.getInstructionAt(addr)
	if inst is not None:
		output.append("  0x%08x: %s" % (addr.getOffset(), inst.toString()))
		nxt = inst.getNext()
		if nxt is None:
			break
		addr = nxt.getAddress()
		count = count + 1
	else:
		addr = addr.add(1)
		count = count + 1

def dump_bytes(base, length):
	result = ""
	for i in range(length):
		b = getByte(toAddr(base + i)) & 0xFF
		result = result + "%02X " % b
	return result

output.append("")
output.append("--- Raw bytes 0x00868B90 ---")
output.append(dump_bytes(0x00868B90, 16))

output.append("")
output.append("--- Raw bytes 0x00868B97 ---")
output.append(dump_bytes(0x00868B97, 16))

text = "\n".join(output)
fout = open("/tmp/disasm_868B97.txt", "w")
fout.write(text)
fout.close()
print(text)
