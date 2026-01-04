# SHA-512-ARM-64-bit-assembly
Implementation of the FIPS 180-4 SHA-512 algorithm in ARM 64-bit assembly language.

https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

For better readability of the source code:

Aliases are used for all registers -> see file 'aliases'

Macros encapsulate frequently recurring commands and boilerplate for function declaration, functions for preprocessing (padding), sha-functions, message parsing, and hash computation -> see file 'macro.sx'

C-interface for the public function in sha512.sx -> sha512.h

Unit tests: see sha512tests.c and sha512tests.h

Developed on a RaspberryPi 4 (Broadcom BCM2711, Quad core Cortex-A72 (ARM v8) 64-bit SoC @ 1.5GHz) with Raspberry Pi OS
