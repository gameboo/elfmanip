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
  sections = {}
  sec_lst = elf.iter_sections()
  if only_sec:
    sec_lst = [x for x in elf.iter_sections() if x.name in only_sec]
  for section in sec_lst:
    if (len(section.data()) != 0):
      print("{:s} -- {:d} byte(s)".format(section.name, len(section.data())))
      hd = section.header
      sections[(hd['sh_addr'], hd['sh_size'])] = section.data() # XXX check addralign
  print(sorted(sections))
  lastaddr, lastsz = max(sections.keys())
  data_bytes = bytearray(lastaddr + lastsz)
  for (addr, sz), data in sorted(sections.items()):
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
