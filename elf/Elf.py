
import os
import struct

class elf:

	CLASS = {1 :'ELF32', 2 :'ELF64'}

	DATA = {1: 'LE', 2: 'BE'}

	VERSION = {0:'NONE', 1:'CURRENT'}

	TYPE = {
			0	:'NONE', 
			1	:'REL', 
			2	:'EXEC', 
			3	:'DYN', 
			4	:'CORE', 
			0xff00 :'LOPROC', 
			0xffff :'HIPROC'
			}

	MACHINE = {
			0 :'NONE', 
			1 :'M32', 
			2 :'SPARC', 
			3 :'386', 
			4 :'68K', 
			5 :'88K', 
			7 :'860', 
			8 :'MIPS',
			40 :'ARM',
			62 :'X86_64'
			}

	def __init__(self, fp):

		self.filename = fp.name
		fp.seek(0)
		st = fp.read()

		self.e_ident = struct.unpack('16s', st[:16])[0]

		(magic, eclass, data, version) = struct.unpack('4sBBB', self.e_ident[:7])

		if magic != '\x7fELF':
				raise SyntaxError, 'Not an elf file'

		if version != 1:
				raise SyntaxError, 'Invalid version'

		try:
			self.ei_class = self.CLASS[eclass]
			self.ei_data = self.DATA[data]

		except KeyError:
			raise SyntaxError, 'Invalid field'

		self.endformat = {'LE':'<', 'BE': '>'}[self.ei_data]
		self.addrformat = {'ELF32':'I', 'ELF64':'Q'}[self.ei_class] 

		self.formatstr = self.endformat + 'HHI'+ self.addrformat * 3 + 'IHHHHHH'

		(etype, machine, version, self.entry, self.phoff, self.shoff, self.flags, 
		self.ehsize, self.phentsize, self.phnum, self.shentsize, self.shnum, 
		self.shstrndx ) = struct.unpack(self.formatstr, st[16:struct.calcsize(self.formatstr)+16])

		try:
			self.elftype = self.TYPE[etype]
			self.machine = self.MACHINE[machine]
			self.version = self.VERSION[version]

		except KeyError:
			raise SyntaxError("Invalid field")

		importstr = "import arch_%s as arch" % (self.machine)
		try:
			exec(importstr)
		except ImportError:
			print "Arch %s not supported, using defaults\n" % (self.machine)
			import arch_NONE as arch

		self.arch = arch
		self.shdrs = []
		self.phdrs = []
		self.sections = []
		self.debug_sections = []

		# read section headers
		if self.shnum != 0:

				fp.seek(self.shoff)
				st = fp.read(self.shentsize * self.shnum)
				for i in range(0, len(st), self.shentsize):

						sh = shdr(st[i:i+self.shentsize], self)
						self.shdrs.append(sh)

						SECTION_TYPES = {
							'SYMTAB': symbol_section,
							'DYNSYM': symbol_section,
							'DYNAMIC': dynamic_section,
							'REL': rel_section,
							'RELA': rela_section,
							'NOTE': note_section,
							'HASH': hash_section,
							'GNU_VERSYM': gnu_versym_section,
							'GNU_VERNEED':gnu_verneed_section,
							'GNU_HASH': gnu_hash_section
							}

						# read sections
						fp.seek(sh.offset)
						data = fp.read(sh.size)

						try:
							sec = SECTION_TYPES[sh.shtype](data, self, sh)
						except KeyError:
							sec = section(data, self, sh)

						self.sections.append(sec)
						sh.section = sec
	
				shstrtab = self.sections[self.shstrndx].data
				for sh in self.shdrs:
						sh.name = shstrtab[sh.sh_name:].split('\0')[0]
						sh.linksec = self.sections[sh.link]

						if '.debug_' in sh.name :
							self.debug_sections.append(sh)

		# read program headers
		if self.phnum != 0:
				fp.seek(self.phoff)
				st = fp.read(self.phentsize * self.phnum)
				for i in range(0, len(st), self.phentsize):
						p = phdr(st[i:i+self.phentsize], self)
						self.phdrs.append(p)

		fp.close()

		if self.debug_sections != []:
			import dwarf
			debug_info = dwarf.dwarf(self.debug_sections)
	
		for s in self.sections:
			s.process()

	def save(self):

		# Write the elf header

		st = self.e_ident	
		st += struct.pack(self.formatstr, 
						rlookup(self.TYPE, self.elftype), 
						rlookup(self.MACHINE, self.machine), 
						rlookup(self.VERSION, self.version), 
						self.entry, self.phoff, self.shoff, 
						self.flags, self.ehsize, self.phentsize, 
						self.phnum, self.shentsize, self.shnum, 
						self.shstrndx ) 

		# Write all sections

		for s in self.shdrs:
			if s.offset != 0:
				gap = s.offset - len(st)
			else:
				gap = 0

			if gap < 0:
				st = st[:len(st) + gap]
			else:	
				st += '\x00' * gap

			st += s.section.data

		# Write program headers

		sphdrs = ''
		for phdr in self.phdrs:
			sphdrs += phdr.save()

		if len(st) < self.phoff:
			st += '\x00' * (self.phoff - len(st))

		st = st[:self.phoff] + sphdrs + st[self.phoff + len(sphdrs):]

		# Write section headers

		sshdrs = ''
		for shdr in self.shdrs:
			sshdrs += shdr.save()

		if len(st) < self.shoff:
			st += '\x00' * (self.shoff - len(st))

		st = st[:self.shoff] + sshdrs + st[self.shoff + len(sshdrs):]

		return st

class shdr:

	SHTYPE = {
		0: 'NULL',
		1: 'PROGBITS',
		2: 'SYMTAB',
		3: 'STRTAB',
		4: 'RELA',
		5: 'HASH',
		6: 'DYNAMIC',
		7: 'NOTE',
		8: 'NOBITS',
		9: 'REL',
		10: 'SHLIB',
		11: 'DYNSYM',
		14: 'INIT_ARRAY',
		15: 'FINI_ARRAY',

		0x6ffffff5: 'GNU_ATTRIB',
		0x6ffffff6: 'GNU_HASH',
		0x6ffffffd: 'GNU_VERDEF',
		0x6ffffffe: 'GNU_VERNEED',
		0x6fffffff: 'GNU_VERSYM',

		0x70000000:	'LOPROC',
		0x7fffffff:	'HIPROC',

		0x80000000:	'LOUSER',
		0xffffffff:	'HIUSER' 
		}

	SHFLAGS = {0:'W', 1:'A', 2:'X', 4:'M', 5:'S', 28:'p'}

	def __init__(self, st, header):

		self.header = header
		self.formatstr = header.endformat+'II'+header.addrformat*4+'II'+header.addrformat*2

		(self.sh_name, shtype, flags, self.addr, self.offset, self.size,
		self.link, self.info, self.addralign, self.entsize) = struct.unpack(self.formatstr, st)

		try:
			self.shtype = self.SHTYPE[shtype]
		except KeyError:
			try:
				self.shtype = header.arch.TYPE[shtype]
			except KeyError:
				raise SyntaxError, "Unknown Section header type %x" % (shtype)

		self.flags = []
		for i in range(0, 32):
			if ( flags & (1<<i) ) and i in self.SHFLAGS:
				self.flags.append(self.SHFLAGS[i])

		self.name = ''
		self.section = ''
		self.linksection = ''

	def save(self):

		flags = 0
		if 'W' in self.flags:
				flags += 1
		if 'A' in self.flags:
				flags += 2
		if 'X' in self.flags:
				flags += 4
		if 'M' in self.flags:
				flags += 0x10
		if 'S' in self.flags:
				flags += 0x20
		if 'p' in self.flags:
				flags += 0x10000000

		try:
			shtype = rlookup(self.SHTYPE, self.shtype)
		except IndexError:
			try:
				shtype = rlookup(self.header.arch.TYPE, self.shtype)
			except IndexError:
				raise SyntaxError, 'Unknown Section header type '+self.shtype 

		st = struct.pack(self.formatstr, self.sh_name, shtype, 
						flags, self.addr, self.offset, self.size, self.link, 
						self.info, self.addralign, self.entsize ) 

		return st

class phdr:

	PHTYPE= {
			0 : 'NULL', 
			1 : 'LOAD',
			2 : 'DYNAMIC',
			3 : 'INTERP',
			4 : 'NOTE',
			5 : 'SHLIB',
			6 : 'PHDR',
			7 : 'TLS',
	
			0x6474e550 : 'GNU_EH_FRAME',
			0x6474e551 : 'GNU_STACK',
			0x6474e552 : 'GNU_RELRO',

			0x70000000 : 'LOPROC',
			0x7fffffff : 'HIPROC' 
			}

	def __init__(self, st, header):

		self.formatstr = header.endformat + 'II' + header.addrformat*6
		self.header = header

		if self.header.ei_class == 'ELF32':
			(phtype, self.offset, self.vaddr, self.paddr, self.filesz,
			self.memsz, flags, self.align ) = struct.unpack(self.formatstr, st)
		else:
			(phtype, flags, self.offset, self.vaddr, self.paddr, self.filesz,
			self.memsz, self.align ) = struct.unpack(self.formatstr, st)

		try:
			self.phtype = self.PHTYPE[phtype]
		except KeyError:
			try:
				self.phtype = header.arch.TYPE[phtype]
			except KeyError:
				raise SyntaxError, "Unknown Program header type %x" %(phtype)
		
		self.flags = []
		if(flags & 1):
				self.flags.append('E')
		if(flags & 2):
				self.flags.append('W')
		if(flags & 4):
				self.flags.append('R')

	def save(self):

		flags = 0
		if 'E' in self.flags:
				flags += 1
		if 'W' in self.flags:
				flags += 2
		if 'R' in self.flags:
				flags += 4

		try:
			phtype = rlookup(self.PHTYPE, self.phtype)
		except IndexError:
			try:
				phtype = rlookup(self.header.arch.TYPE, self.phtype)
			except IndexError:
				raise SyntaxError, 'Program Header type not recognised'

		if self.header.ei_class == 'ELF32':
			st = struct.pack( self.formatstr, phtype, self.offset, self.vaddr, 
					self.paddr, self.filesz, self.memsz, flags, self.align)
		else:
				st = struct.pack( self.formatstr, phtype, flags, self.offset, 
					self.vaddr, self.paddr, self.filesz, self.memsz, self.align)
	
		return st

class section:
	def __init__(self, st, header, shdr):

		self.data = st
		self.shdr = shdr
		self.header = header

		self.processed = 0 

	def process(self):
		self.processed = 1 
		return

class symbol_section(section):

	def __init__(self, st, header, shdr):
		section.__init__(self, st, header, shdr)
		self.symbols = []

	def process(self):

		if self.processed == 1:
			return

		strtab = self.shdr.linksec.data
		symbol_size = (16,24)[self.header.ei_class == 'ELF64']

		for off in range(0, len(self.data), symbol_size):
			sym = symbol(self.data[off:off+symbol_size], self.header)
			sym.name = strtab[sym.st_name:].split('\0')[0]
			self.symbols.append(sym)

		self.processed = 1 

class symbol:

	BINDING = {
			0	:'LOCAL', 
			1	:'GLOBAL', 
			2	:'WEAK', 
			13 :'LOPROC', 
			15 :'HIPROC', 
			}

	SYMTYPE = {
			0	:'NOTYPE', 
			1	:'OBJECT', 
			2	:'FUNC', 
			3	:'SECTION', 
			4	:'FILE', 
			6	:'TLS',
			13 :'LOPROC', 
			15 :'HIPROC',
			}

	VISIBILITY = {
			0 :'DEFAULT',
			2 :'HIDDEN'
			}

	def __init__(self, st, header):
		if header.ei_class == 'ELF32':
				(self.st_name, self.value, self.size, info, other, self.shndx
				) = struct.unpack( header.endformat+'IIIBBH', st)
		else:
				(self.st_name, info, other, self.shndx, self.value, self.size
				) = struct.unpack( header.endformat+'IBBHQQ', st)

		self.symtype = self.SYMTYPE[info & 0xf]
		self.binding = self.BINDING[info >> 4]
		self.visibility = self.VISIBILITY[other]
		self.name = ''

class dynamic_section(section):

	def __init__(self, st, header, shdr):
		section.__init__(self, st, header, shdr)
		self.dynents = []

	def process(self):

		if self.processed == 1:
			return

		strtab = self.shdr.linksec.data
		dynent_size = (8,16)[self.header.ei_class == 'ELF64']

		for off in range(0, len(self.data), dynent_size):
			ent = dynent(self.data[off:off+dynent_size], self.header)

			if ent.tag == 'NEEDED':
				ent.st = strtab[ent.value:].split('\0')[0]

			self.dynents.append(ent)
			if ent.tag == 'NULL':
				break

		self.processed = 1 

class dynent:

	TAG = {
		0 : 'NULL',
		1 : 'NEEDED', 
		2 : 'PLTRELSZ',
		3	: 'PLTGOT',
		4 : 'HASH',
		5 : 'STRTAB', 
		6 : 'SYMTAB',
		7 : 'RELA',
		8 : 'RELASZ',
		9 : 'RELAENT',
		10 : 'STRSZ',
		11 : 'SYMENT',
		12 : 'INIT',
		13 : 'FINI',
		14 : 'SONAME',
		15 : 'RPATH',
		16 : 'SYMBOLIC',

		17 : 'REL',
		18 : 'RELSZ',
		19 : 'RELENT',
		20 : 'PLTREL',
		21 : 'DEBUG',
		22 : 'TEXTREL',
		23 : 'JMPREL',

		25 : 'INIT_ARRAY',
		26 : 'FINI_ARRAY',
		27 : 'INIT_ARRAYSZ',
		28 : 'FINI_ARRAYSZ',

		0x6ffffef5 : 'GNU_HASH',

		0x6ffffff0 : 'GNU_VERSYM',
		0x6ffffffe : 'GNU_VERNEED',
		0x6fffffff : 'GNU_VERNUM',

		0x70000000 : 'LOPROC',
		0x7fffffff : 'HIPROC'
		}

	def __init__(self, st, header):
		(tag, value) = struct.unpack(header.endformat + header.addrformat *2, st)
		try:
			self.tag = self.TAG[tag]
		except KeyError:
			try:
				self.tag = header.arch.TAG[tag]
			except KeyError:
				raise SyntaxError, "Unknown dynamic tag: 0x%x\n" % (tag)
			
		self.value = value
		self.st = ''

class rel_section(section):

	def __init__(self, st, header, shdr):
		section.__init__(self, st, header, shdr)
		self.relents = []

	def process(self):

		if self.processed == 1:
			return

		dynsym = self.shdr.linksec
		dynsym.process()

		relent_size = (8,16)[self.header.ei_class == 'ELF64']
		for off in range(0, len(self.data), relent_size):
			ent = relent(self.data[off:off+relent_size], self.header)
			ent.sym = dynsym.symbols[ent.symndx].name

			self.relents.append(ent)

		self.processed = 1

class relent:

	def __init__(self, st, header):

		(self.offset, self.info) = struct.unpack(header.endformat + header.addrformat *2, st)

		self.reltype = header.arch.INFO[self.info & 0xff]
		self.symndx = self.info >> 8
		self.sym = ''

class rela_section(section):

	def __init__(self, st, header, shdr):
		section.__init__(self, st, header, shdr)
		self.relaents = []

	def process(self):

		if self.processed == 1:
			return

		dynsym = self.shdr.linksec
		dynsym.process()

		relent_size = (12,24)[self.header.ei_class == 'ELF64']

		for off in range(0, len(self.data), relent_size):

			ent = relaent(self.data[off:off+relent_size], self.header)
			ent.sym = dynsym.symbols[ent.symndx].name

			self.relaents.append(ent)

		self.processed = 1

class relaent:

	def __init__(self, st, header):

		(self.offset, self.info, self.addend) = struct.unpack(header.endformat + header.addrformat * 3, st)

		self.relatype = header.arch.INFO[self.info & 0xff]
		self.symndx = self.info >> (8,32)[header.ei_class == 'ELF64']
		self.sym = ''

class gnu_versym_section(section):

	def __init__(self, st, header, shdr):
		section.__init__(self, st, header, shdr)
		self.versyments = []

	def process(self):

		if self.processed == 1:
			return

		for off in range(0, len(self.data), 2):

			ent = struct.unpack(self.header.endformat+'H', self.data[off:off+2])[0]
			self.versyments.append(ent)

		self.processed = 0 

class gnu_verneed_section(section):

	def __init__(self, st, header, shdr):

		section.__init__(self, st, header, shdr)
		self.vns = []

	def process(self):

		if self.processed == 1:
			return

		off = 0
		st = self.data
		dynstr = self.shdr.linksec.data

		while(off < len(st)):

			vn = verneedent(st[off:off+16], self.header)
			vn.filename = dynstr[vn.file:].split('\0')[0]
			off += 16

			for i in range(0,vn.cnt):

				vna = verneedauxent(self.data[off:off+16], self.header)
				vna.libname = dynstr[vna.name:].split('\0')[0]
				vn.vnas.append(vna)
				off += 16

			self.vns.append(vn)

		self.processed = 1 

class verneedent:

	def __init__(self, st, header):

		(self.version, self.cnt, self.file, self.aux, self.next) = struct.unpack(header.endformat+'HHIII', st)

		self.filename = ''
		self.vnas = []

class verneedauxent:

	def __init__(self, st, header):

		(self.hash, self.flags, self.other, self.name, self.next) = struct.unpack(header.endformat+'IHHII', st)

		self.libname = ''

class note_section(section):

	def __init__(self, st, header, shdr):

		section.__init__(self, st, header, shdr)

		(self.namesz, self.descsz, self.notetype) = struct.unpack(header.endformat+'III', st[:12])
		
		if self.notetype == 1:
			(self.name, x, v0,v1,v2) = struct.unpack(header.endformat+'4sIIII', st[12:])
			self.kversion = "%d.%d.%d" % (v0,v1,v2)
		else:
			self.name = 'Unknown'
			self.kversion = 'Unknown'

class hash_section(section):

	def __init__(self, st, header, shdr):

		section.__init__(self, st, header, shdr)

		self.buckets = []
		self.chains = []

		(self.nbuckets, self.nchains) = struct.unpack(header.endformat +'II', st[:8])

		st = st[8:]

		for i in range(0, self.nbuckets * 4, 4):
			self.buckets.append(struct.unpack(header.endformat+'I', st[i:i+4]))

		st = st[self.nbuckets * 4:]

		for i in range(0, self.nchains * 4, 4):
			self.chains.append(struct.unpack(header.endformat+'I', st[i:i+4]))

class gnu_hash_section(section):

	def __init__(self, st, header, shdr):

		section.__init__(self, st, header, shdr)

		self.maskwords= []
		self.buckets = []

		(self.nbuckets, self.symndx, self.nmaskwords, self.shift2) = \
						struct.unpack(header.endformat + 'IIII', st[:16])

		st = st[16:]
		for i in range(0, self.nmaskwords * 4, 4):
			self.maskwords.append(struct.unpack(header.endformat+'I', st[i:i+4])[0])

		st = st[self.nmaskwords * 4:]
		for i in range(0, self.nbuckets * 4, 4):
			self.buckets.append(struct.unpack(header.endformat+'I', st[i:i+4])[0])


from types import StringType
import __builtin__

def rlookup(dict, val):
	return [k for k,v in dict.items() if v == val][0]

def open(fp):

		"Open an elf file and examine header"

		if isinstance(fp, StringType):
				fp = __builtin__.open(fp, 'rb')

		return elf(fp)

def save(elf, file):

		fp = __builtin__.open(file, 'wb')
		fp.write(elf.save())
		fp.close()
		os.chmod(file, 0755)

