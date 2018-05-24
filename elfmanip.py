#! /usr/bin/env python3
# Alexandre Joannou, 2018

import argparse
import os.path as op
from elftools.elf.elffile import ELFFile

################################
# Parse command line arguments #
################################

def auto_int (x):
    return int(x,0)

parser = argparse.ArgumentParser(description='Reads an elf file and exports it to another memory format.')

parser.add_argument('elf', type=str, metavar='ELF',
                    help="The elf file to re-export.")
parser.add_argument('-o', '--output', type=str, metavar='OUTPUT',
                    help="The OUTPUT file to export to. When unspecified, it is derived from the ELF input.")
parser.add_argument('--only-section', nargs='+', default=None, metavar='SECTION',
                    help="List the elf SECTIONs to use when generating the output (default all).")

subcmds = parser.add_subparsers(dest='subcmd',metavar='sub-command',help="Individual sub-command help available by invoking it with -h or --help.")
subcmds.required = True

# hex
hexcmd = subcmds.add_parser('hex',
                    help="Generate a HEX file.")
hexcmd.add_argument('-f', '--force-skip', action="store_true",
                    help="In case a section overlaps with an earlier section, force skipping.")
hexcmd.add_argument('-w', '--word-size', type=auto_int, default=4, metavar="BYTE_WIDTH",
                    help="The size in bytes of a memory word.")

# mif
mifcmd = subcmds.add_parser('mif',
                    help="Generate a MIF file.")
mifcmd.add_argument('-f', '--force-skip', action="store_true",
                    help="In case a section overlaps with an earlier section, force skipping.")
mifcmd.add_argument('-w', '--word-size', type=auto_int, default=4, metavar="BYTE_WIDTH",
                    help="The size in bytes of a memory word.")
#binary (BIN), hexadecimal (HEX), octal (OCT), signed decimal (DEC), unsigned decimal (UNS)
radices = ['BIN', 'HEX', 'OCT', 'DEC', 'UNS']
mifcmd.add_argument('-a', '--address-radix', choices=radices, default='HEX', metavar='RADIX',
                    help="RADIX used to display the addresses, one of {{{:s}}}, (default: HEX)".format(", ".join(radices)))
mifcmd.add_argument('-d', '--data-radix', choices=radices, default='HEX', metavar='RADIX',
                    help="RADIX used to display the data, one of {{{:s}}}, (default: HEX)".format(", ".join(radices)))

args = parser.parse_args()

###########
# helpers #
###########

def bundle(iterable, n):
  return zip(*[iter(iterable)]*n)

def rad_to_fmt(rad):
  return {
    'BIN': "b",
    'HEX': "X",
    'OCT': "o",
    'DEC': "d",
    'UNS': "d"
  }.get(rad, "x")

def field_width(width, rad):
  tmp = int.from_bytes(bytearray(b'\xff') * width, 'little')
  return len("{:{rd}}".format(tmp, rd=rad_to_fmt(rad)))

def group_bytes(some_bytes, group_size):
  for i in range(0, len(some_bytes), group_size):
    tmp = some_bytes[i:i+group_size]
    if len(tmp) == group_size:
      yield tmp
    else:
      val = bytearray(group_size)
      val[0:len(tmp)] = tmp
      yield val

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

#########################
# sections to bytearray #
#########################

def elf_sections_to_bytearray(sections, force_skip=False):
  last_section = sorted(sections, key = lambda x: x.header["sh_addr"])[-1]
  size = last_section.header["sh_addr"] + last_section.header["sh_size"]
  data_bytes = bytearray(size)
  #print(size)
  last_top = 0
  for section in sections:
    skip = False
    addr = section.header["sh_addr"]
    if addr < last_top:
      if force_skip:
        skip = True
      else:
        skip = input_y_n("{:s} overlaps with previous sections. Skip {:s} (Y/n) ? ".format(*[section.name]*2))
    if not skip:
      last_top = addr + section.header["sh_size"] # XXX check data sz compared to section sz
      data_bytes[addr : last_top] = section.data()
      print("{:s} section written (0x{:0X} to 0x{:0X})".format(section.name, addr, last_top))
  return data_bytes

##################
# write hex file #
##################

def elf_sections_to_hex(sections, outfile, byte_width, force_skip=False):
  outfile.write(dump_hex(elf_sections_to_bytearray(sections, force_skip), byte_width))

##################
# write mif file #
##################

def elf_sections_to_mif(sections, outfile, byte_width, addr_rad, data_rad, force_skip=False):
  data_bytes = elf_sections_to_bytearray(sections, force_skip)
  nb_words = int(len(data_bytes)/byte_width)
  outfile.write("DEPTH = {:d};\n".format(nb_words))
  outfile.write("WIDTH = {:d};\n".format(byte_width*8))
  outfile.write("ADDRESS_RADIX = {:s};\n".format(addr_rad))
  outfile.write("DATA_RADIX = {:s};\n".format(data_rad))
  outfile.write("CONTENT\n")
  outfile.write("BEGIN\n")
  addr = 0
  max_aw = len("{:{rad}}".format(len(data_bytes),rad=rad_to_fmt(addr_rad)))
  max_dw = field_width(byte_width, data_rad)
  for word in group_bytes(data_bytes, byte_width):
    data = int.from_bytes(word, byteorder='little', signed=(True if data_rad == 'DEC' else False))
    outfile.write("{:0{aw}{rad_a}}: {:0{dw}{rad_d}};\n".format(addr, data, aw=max_aw, rad_a=rad_to_fmt(addr_rad), dw=max_dw, rad_d=rad_to_fmt(data_rad)))
    addr += 1
  outfile.write("END;")

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
    if args.only_section:
      sections = [x for x in elf.iter_sections() if x.name in args.only_section]
    else:
      sections = list(elf.iter_sections())
    with open(args.output,"w") as out_f:
      if (args.subcmd == "hex"):
        elf_sections_to_hex(sections, out_f, args.word_size, force_skip=args.force_skip)
      if (args.subcmd == "mif"):
        elf_sections_to_mif(sections, out_f, args.word_size, args.address_radix, args.data_radix, force_skip=args.force_skip)
    exit(0)

if __name__ == "__main__":
    main()
