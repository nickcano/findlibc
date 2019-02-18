import os
import glob
from pwn import *

libcs = []
initialized = False
def internal_initialize():
	global libcs, initialized
	if initialized:
		return

	def contains_any(haystack, needles):
		for needle in needles:
			if needle in haystack:
				return True
		return False

	initialized = True
	p = log.progress('Initializing')
	for r, ds, fs in os.walk(os.path.dirname(__file__) + "/libcs"):
		if contains_any(r, ["sparc", "powerpc", "ia64", "hppa", "lpia"]):
			# filter out formats that make pwntools ELF() choke.
			# this works because the current submodule with libcs
			# has these in the directory name. if that changes,
			# this will begin to spam
			continue
		for filename in fs:
			if (filename.endswith(".so") or filename.endswith(".so.6")):
				filepath = os.path.join(r, filename)
				p.status(filepath)
				with context.local(log_level='CRITICAL'):
					# wrap in CRITICAL log level to quite noise
					try:
						libc = ELF(filepath)
						libcs.append((libc, filepath))
					except:
						pass

	p.success('initialized %d potential libcs' % len(libcs))

def find(symbols, many=False, arch='amd64'):
	global libcs
	internal_initialize()

	symtype = type(symbols)
	if (symtype is not type({})):
		raise TypeError("Expected dictionary, got %s" % symtype)

	if len(symbols.items()) < 2:
		raise TypeError("Need at least 2 symbols")

	arch = arch.lower()
	anyarch = (arch == 'any')

	results = []
	p = log.progress('Searching')
	for libc, filepath in libcs:
		if (anyarch or libc.get_machine_arch() == arch):
			p.status(filepath)
			with context.local(log_level='CRITICAL'):
				# wrap in CRITICAL log level to quite noise
				match = True
				symiter = iter(symbols.items())

				# choose the first symbol as a reference point
				bname, baddr = next(symiter)
				# get the reference point's address within the current libc
				libc_baddr = libc.symbols[bname]

				# check the reamining symbols against the reference point
				for name, addr in symiter:
					# by first calculating an offset relative to the reference point within
					# the context of the given addresses
					offset = addr - baddr
					# then an offset relative to the reference point within the context
					# of the current libc
					libc_offset = libc.symbols[name] - libc_baddr
					# then checking if the offsets are equal
					#   (meaning, the functions have a constant offset
					#    in both contexts, implying a potentially matching
					#    libc)
					if (offset != libc_offset):
						match = False
						break

				# if the check passed (meaning all functions had same offset),
				# add this libc to our result set:
				if match:
					results.append((libc, filepath))
					if (not many):
						# user can select to get one result or many results
						break

	if (len(results) == 0):
		p.failure('match not found')
		return None
	elif many:
		p.success('%d matches found' % len(results))
		return results
	else:
		p.success('match found')
		return results[0]