#! /usr/bin/env python3
# Alexandre Joannou, 2018

import argparse
import os.path as op
from elftools.elf.elffile import ELFFile

################################
# Parse command line arguments #
################################

parser = argparse.ArgumentParser(description='Reads an elf file and exports it to another memory format')

parser.add_argument('elf', type=str, metavar='ELF', help="the elf file to re-export")
parser.add_argument('-o', '--output', type=str, metavar='OUTPUT',
                    help="the output file to export to")

subcmds = parser.add_subparsers(dest='subcmd',metavar='sub-command',help="Individual sub-command help available by invoking it with -h or --help.")
subcmds.required = True

# hex
hexcmd = subcmds.add_parser('hex', help="generate a HEX file")
hexcmd.add_argument('-s', '--only-section', nargs='+', default=None,
                    help="List the elf sections to include in the HEX output (default all)")

args = parser.parse_args()

###########
# helpers #
###########

def bundle(iterable, n):
  return zip(*[iter(iterable)]*n)

def dump_hex(some_bytes, some_width):
  dump = ""
  word = ""
  i = 0
  for b in some_bytes:
    word = "{:02X}{:s}".format(b,word)
    i += 1
    if i == some_width:
      dump += "{:s}\n".format(word)
      word = ""
      i = 0
  if i != 0:
    dump += "{:s}{:s}\n".format("00"*(some_width-i), word)
  return dump

##################
# write hex file #
##################

def elf_to_hex(elf, only_sec, outfile, byte_width):
  if only_sec:
    sections = [x for x in elf.iter_sections() if x.name in only_sec]
  else:
    sections = list(elf.iter_sections())
  sections = sorted(sections, key = lambda x: x.header["sh_addr"])
  list(map(lambda x: print(x.name), sections))
  last_section = sections[-1]
  data_bytes = bytearray(last_section.header["sh_addr"] + last_section.header["sh_size"])
  for addr, sz, data in [(s.header["sh_addr"],s.header["sh_size"],s.data()) for s in sections]:
    data_bytes[addr:addr+sz] = data # XXX check data sz compared to section sz
  outfile.write(dump_hex(data_bytes, byte_width))

#################
# main function #
#################

def main():
  if args.output == None:
    args.output, _ = op.splitext(args.elf)
    args.output = op.basename(args.output)+"."+args.subcmd
  print("args.output: {:s}".format(args.output))
  with open(args.elf,"rb") as in_f:
    elf = ELFFile(in_f)
    with open(args.output,"w") as out_f:
      if (args.subcmd == "hex"):
        elf_to_hex(elf, args.only_section, out_f, 4)
    exit(0)

if __name__ == "__main__":
    main()
