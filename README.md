PyElf
=====

PyElf is an ELF file decoder and encoder written in Python. It helps
in accessing and modifying sections of an elf file. 

PyElf has been tested with x86, x86_64, MIPS and ARM executables.
This covers both 32 bit and 64 bit executables, in both Little-endian
and Big-endian formats.

TODO:
-----

* Decoding of debug sections ( Dwarf 2 and Dwarf 3 formats )
* Better support and testing for writing back modified ELF files
