import struct

class dwarf:
		def __init__(self, debug_sections):

				DEBUG_SECTIONS = {
					'.debug_aranges' : debug_aranges,
					'.debug_ranges' : debug_ranges,
					'.debug_pubnames': debug_pubnames,
					'.debug_info': debug_info,
					'.debug_abbrev': debug_abbrev,
					'.debug_line': debug_line,
					'.debug_str': debug_str,
					'.debug_frame': debug_frame,
					'.debug_loc': debug_loc,
				}

				for ds in debug_sections:
					try:
						info = DEBUG_SECTIONS[ds.name](ds)
					except KeyError:
						print 'unsupported section', ds.name

##################### aranges ####################

class debug_aranges:

		def __init__(self, shdr):

				self.data = data = shdr.section.data
				aranges = []

				while len(data):
						size = struct.unpack('<I', data[:4])[0]
						ar = arange(data[:size + 4])
						aranges.append(ar)
						data = data[size+4:]
						#print ar.__dict__

class arange:
		def __init__(self, data):
				(self.length, self.version, self.offset, self.ptr_size, self.seg_size) \
				= struct.unpack('<IHIBB', data[:12])

##################### pubnames ####################

class debug_pubnames:

		def __init__(self, shdr):

				self.data = data = shdr.section.data
				pubnames = []

				while len(data):
						size = struct.unpack('<I', data[:4])[0]
						pn = pubname(data[:size + 4])
						pubnames.append(pn)
						data = data[size+4:]
						#print pn.__dict__

class pubname:
		def __init__(self, data):
				(self.length, self.version, self.debug_info_offset, self.debug_info_length) \
				= struct.unpack('<IHII', data[:14])


##################### info ####################

class debug_info:

		def __init__(self, shdr):

				self.data = data = shdr.section.data
				compilation_units = []

				while len(data):
						size = struct.unpack('<I', data[:4])[0]
						cu = compilation_unit(data[:size + 4])
						compilation_units.append(cu)
						data = data[size+4:]
						#print cu.__dict__

class compilation_unit:
		def __init__(self, data):
				(self.length, self.version, self.debug_abbrev_offset, self.address_size) \
				= struct.unpack('<IHIB', data[:11])


##################### abbrev ####################

class debug_abbrev:

		def __init__(self, shdr):
				self.data = shdr.section.data

##################### line ####################

class debug_line:

		def __init__(self, shdr):
				self.data = shdr.section.data

##################### str ####################

class debug_str:

		def __init__(self, shdr):
				self.data = shdr.section.data

##################### ranges ####################

class debug_ranges:

		def __init__(self, shdr):
				self.data = shdr.section.data

class debug_frame:

		def __init__(self, shdr):
				self.data = shdr.section.data

class debug_loc:

		def __init__(self, shdr):
				self.data = shdr.section.data

