from . import find
from parse import *
from pwn import *
import sys

def main():
	# get list of symbols
	log.info('Enter one symbol per line. Blank line to finish. Format <name addr>:')

	symbols = {}
	while True:
		line = raw_input(" [?] ").strip()
		if (len(line) == 0):
			break
		name, addr = parse("{} {}", line)
		symbols[name] = int(addr[2:], 16) if (addr.startswith("0x")) else int(addr, 10)

	if (len(symbols.items()) == 0):
		log.failure('No symbols entered!')
		return

	# many outputs or first output?
	log.info("")
	many = (pwnlib.ui.options('Matches to return', ['first', 'all'], 0) == 1)
	log.info('You chose: %s' % ('all' if many else 'first'))

	# architectures to check
	log.info("")
	arches = ['any', 'amd64', 'i386', 'arm', 'aarch64', 'mips', 'ia64']
	arch = arches[pwnlib.ui.options('Which arch', arches, 1)]
	log.info('You chose: %s' % arch)

	# identify
	try:
		results = find(symbols, many, arch)
	except:
		log.failure(sys.exc_info()[1])
		return

	# show results
	if (results is None):
		return
	if (not many):
		results = [results]
	for libc, filepath in results:
		log.success("libc candidate: %s" % filepath)
		binshs = list(libc.search("/bin/sh"))
		if (len(binshs) > 0):
			log.indented("/bin/sh should be at offset 0x%08x" % binshs[0])

if __name__ == "__main__":
	try:
		while True:
			main()
	except KeyboardInterrupt:
		log.info("Bye!")