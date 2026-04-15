# @category Analysis
# @description Find every call site to FUN_00aa3e40 (game heap alloc),
# walk back up to 10 instructions looking for a literal size operand,
# and list all callers that ask for >= 1 MB. Decompile the top callers
# so we can identify the 5.6 MB worker-thread alloc that froze the game.

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

ALLOC_ADDR = 0x00aa3e40

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
	faddr = func.getEntryPoint().getOffset()
	write(
		"  Function: %s @ 0x%08x, Size: %d bytes"
		% (func.getName(), faddr, func.getBody().getNumAddresses())
	)
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		write(code[:max_len])
	else:
		write("  [decompilation failed]")


def parse_imm_token(token):
	if token is None:
		return None
	t = token.strip()
	if len(t) == 0:
		return None
	if t[0] == "-":
		return None
	# Ghidra operand repr for hex literals uses "0x..." form.
	if t.startswith("0x") or t.startswith("0X"):
		try:
			return int(t[2:], 16)
		except ValueError:
			return None
	# Some pure decimal literals.
	try:
		return int(t, 10)
	except ValueError:
		pass
	# Last-resort hex parse for bare hex like "12h" or ABCD.
	try:
		return int(t, 16)
	except ValueError:
		return None


def extract_literal_size_before(call_addr):
	inst = listing.getInstructionBefore(toAddr(call_addr))
	steps = 0
	while inst is not None and steps < 12:
		mnem = inst.getMnemonicString()
		if mnem == "CALL":
			return None
		if mnem == "PUSH":
			op = inst.getDefaultOperandRepresentation(0)
			val = parse_imm_token(op)
			if val is not None and val > 0:
				return val
		if mnem == "MOV":
			op0 = inst.getDefaultOperandRepresentation(0)
			op1 = inst.getDefaultOperandRepresentation(1)
			if op0 is not None and op0.find("ESP") >= 0:
				val = parse_imm_token(op1)
				if val is not None and val > 0:
					return val
		inst = inst.getPrevious()
		steps += 1
	return None


def scan_callsites():
	write("")
	write("-" * 70)
	write("Scanning call sites to FUN_00aa3e40")
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(ALLOC_ADDR))
	total = 0
	literal = 0
	symbolic = 0
	result = {}
	result["addrs"] = []
	result["sizes"] = []
	result["entries"] = []
	result["names"] = []
	while refs.hasNext():
		ref = refs.next()
		if not ref.getReferenceType().isCall():
			continue
		total += 1
		call_addr = ref.getFromAddress().getOffset()
		size = extract_literal_size_before(call_addr)
		func = fm.getFunctionContaining(ref.getFromAddress())
		if func is None:
			entry = 0
			name = "(no func)"
		else:
			entry = func.getEntryPoint().getOffset()
			name = func.getName()
		result["addrs"].append(call_addr)
		result["sizes"].append(size)
		result["entries"].append(entry)
		result["names"].append(name)
		if size is None:
			symbolic += 1
		else:
			literal += 1
	write("  Total alloc call sites : %d" % total)
	write("  With literal size      : %d" % literal)
	write("  With symbolic size     : %d" % symbolic)
	return result


def print_histogram(sizes):
	bands_lo = [0, 256, 4096, 65536, 262144, 1048576, 4194304, 16777216]
	bands_hi = [256, 4096, 65536, 262144, 1048576, 4194304, 16777216, 0x7fffffff]
	bands_lbl = [
		"0..256B",
		"256B..4K",
		"4K..64K",
		"64K..256K",
		"256K..1M",
		"1M..4M",
		"4M..16M",
		">=16M",
	]
	buckets = [0, 0, 0, 0, 0, 0, 0, 0]
	unknown = 0
	i = 0
	while i < len(sizes):
		s = sizes[i]
		if s is None:
			unknown += 1
		else:
			j = 0
			while j < len(bands_lo):
				if s >= bands_lo[j] and s < bands_hi[j]:
					buckets[j] += 1
					break
				j += 1
		i += 1
	write("")
	write("-" * 70)
	write("Literal size distribution")
	write("-" * 70)
	k = 0
	while k < len(bands_lbl):
		write("  %-12s : %d" % (bands_lbl[k], buckets[k]))
		k += 1
	write("  %-12s : %d" % ("non-literal", unknown))


def print_large_allocs(sites, min_size):
	write("")
	write("-" * 70)
	write("Literal allocations >= %d bytes" % min_size)
	write("-" * 70)
	addrs = sites["addrs"]
	sizes = sites["sizes"]
	entries = sites["entries"]
	names = sites["names"]
	large = {}
	large["addrs"] = []
	large["sizes"] = []
	large["entries"] = []
	large["names"] = []
	i = 0
	while i < len(addrs):
		s = sizes[i]
		if s is not None and s >= min_size:
			large["addrs"].append(addrs[i])
			large["sizes"].append(s)
			large["entries"].append(entries[i])
			large["names"].append(names[i])
		i += 1
	# Sort by size desc via index permutation (selection sort, small N).
	order = []
	k = 0
	while k < len(large["sizes"]):
		order.append(k)
		k += 1
	n = len(order)
	a = 0
	while a < n:
		b = a + 1
		while b < n:
			if large["sizes"][order[b]] > large["sizes"][order[a]]:
				tmp = order[a]
				order[a] = order[b]
				order[b] = tmp
			b += 1
		a += 1
	for idx in order:
		write(
			"  call 0x%08x  size=%d (%.2f MB)  caller 0x%08x %s"
			% (
				large["addrs"][idx],
				large["sizes"][idx],
				large["sizes"][idx] / 1048576.0,
				large["entries"][idx],
				large["names"][idx],
			)
		)
	write("  Total large callsites: %d" % len(order))
	large["order"] = order
	return large


def decompile_unique_large_callers(large, limit=10):
	write("")
	write("=" * 70)
	write("TOP LARGE-ALLOC CALLERS")
	write("=" * 70)
	entries = large["entries"]
	order = large["order"]
	seen = {}
	shown = 0
	for idx in order:
		if shown >= limit:
			break
		ent = entries[idx]
		if ent == 0:
			continue
		if ent in seen:
			continue
		seen[ent] = 1
		decompile_at(ent, "large_alloc_caller_0x%08x" % ent)
		shown += 1


def print_symbolic_size_callers(sites):
	write("")
	write("=" * 70)
	write("SYMBOLIC-SIZE alloc call sites (no literal push)")
	write("=" * 70)
	addrs = sites["addrs"]
	sizes = sites["sizes"]
	entries = sites["entries"]
	names = sites["names"]
	seen = {}
	i = 0
	while i < len(addrs):
		if sizes[i] is None:
			ent = entries[i]
			if ent not in seen:
				seen[ent] = names[i]
				write("  caller 0x%08x %s  call @ 0x%08x" % (ent, names[i], addrs[i]))
		i += 1
	write("  Total unique symbolic-size callers: %d" % len(seen))


# ======================================================================
# MAIN BODY
# ======================================================================

write("LARGE-ALLOC CALLER TRACE")
write("Goal: identify the 5.6 MB worker-thread allocation that froze the game")
write("=" * 70)

sites = scan_callsites()
print_histogram(sites["sizes"])

print_large_allocs(sites, 1 * 1024 * 1024)
large = print_large_allocs(sites, 4 * 1024 * 1024)
decompile_unique_large_callers(large, limit=10)

print_symbolic_size_callers(sites)

# ---------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/trace_large_alloc_callers.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("")
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
