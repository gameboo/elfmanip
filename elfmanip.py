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
hexcmd.add_argument('-f', '--force-skip', action="store_true",
                    help="In case a section overlaos with an earlier section, force skipping.")

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

def input_y_n(prompt):
  s = input(prompt)
  return s.lower() in ["", "y", "ye", "yes"]

##################
# write hex file #
##################

def elf_to_hex(elf, only_sec, outfile, byte_width):
  if only_sec:
    sections = [x for x in elf.iter_sections() if x.name in only_sec]
  else:
    sections = list(elf.iter_sections())
  #sections = sorted(sections, key = lambda x: x.header["sh_addr"])
  last_section = sections[-1]
  data_bytes = bytearray(last_section.header["sh_addr"] + last_section.header["sh_size"])
  last_top = 0
  for section in sections:
  #for addr, sz, data in [(s.header["sh_addr"],s.header["sh_size"],s.data()) for s in sections]:
    skip = False
    addr = section.header["sh_addr"]
    if addr < last_top:
      if args.force_skip:
        skip = True
      else:
        skip = input_y_n("{:s} overlaps with previous sections. Skip {:s} (Y/n) ? ".format(*[section.name]*2))
    if not skip:
      last_top = addr + section.header["sh_size"] # XXX check data sz compared to section sz
      data_bytes[addr : last_top] = section.data()
      print("{:s} section written (0x{:0X} to 0x{:0X})".format(section.name, addr, last_top))
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
