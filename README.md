PyElf
=====

PyElf is a elf file decoder and encoder written completely in Python.
If you need a tool to access or modify section data from
an Elf file, you can use this module.

The module has been tested with x86, x86_64, MIPS and ARM executables.
This covers both 32 bit and 64 bit executables, in both Little-endian
and Big-endian formats.

Can be used as a platform independent library to write tools like elf2hex
and elf2bin.

TODO:
=====

- Decoding .interp section
- Decoding of debug sections ( Dwarf 2 and Dwarf 3 formats )

