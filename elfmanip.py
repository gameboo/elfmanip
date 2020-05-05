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

def auto_pos_int (x):
  val = int(x,0)
  if val <= 0:
      raise argparse.ArgumentTypeError("argument must be a positive int. Got {:d}.".format(val))
  return val

parser = argparse.ArgumentParser(description='Reads an elf file and exports it to another memory format.')

parser.add_argument('elf', type=str, metavar='ELF',
                    help="The elf file to re-export.")
parser.add_argument('-o', '--output', type=str, metavar='OUTPUT',
                    help="The OUTPUT file to export to. When unspecified, it is derived from the ELF input.")
parser.add_argument('--only-section', nargs='+', default=None, metavar='SECTION',
        help="Filters the list the elf SECTIONs to include only the specified ones. Note: this filter is applied before the --exclude-section filter.")
parser.add_argument('--exclude-section', nargs='+', default=None, metavar='SECTION',
        help="Filters the list the elf SECTIONs to exclude the specified ones. Note: this filter is applied after the --only-section filter.")
parser.add_argument('-s', '--start-at', type=auto_pos_int, default=0, metavar='START_ADDR',
        help="The address at which to start considering the content of the elf file")
parser.add_argument('-e', '--end-at', type=auto_pos_int, default=None, metavar='END_ADDR',
        help="The address at which to stop considering the content of the elf file")
parser.add_argument('-f', '--force-skip', action="store_true",
                    help="In case a section overlaps with an earlier section, force skipping.")
parser.add_argument('-v', '--verbose', action='count', default=0,
        help="Increase verbosity level by adding more \"v\".")

subcmds = parser.add_subparsers(dest='subcmd',metavar='sub-command',help="Individual sub-command help available by invoking it with -h or --help.")
subcmds.required = True

# info
infocmd = subcmds.add_parser('info',
                    help="Print ELF file info.")
infocmd.add_argument('--list-sections', action="store_true",
                    help="Print a list of the available ELF sections in the file.")

# hex
hexcmd = subcmds.add_parser('to-hex',
                    help="Generate a HEX file.")
hexcmd.add_argument('-w', '--word-size', type=auto_pos_int, default=4, metavar="BYTE_WIDTH",
                    help="The size in bytes of a memory word.")

# mif
mifcmd = subcmds.add_parser('to-mif',
                    help="Generate a MIF file.")
mifcmd.add_argument('-w', '--word-size', type=auto_pos_int, default=4, metavar="BYTE_WIDTH",
                    help="The size in bytes of a memory word.")
mifcmd.add_argument('-g', '--group-same', action="store_true",
                    help="Group successive same values of padding in one line.")
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

def verboseprint(lvl,msg):
  if args.verbose >= lvl:
    print(msg)

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

#def bundle(iterable, n):
#  return zip(*[iter(iterable)]*n)

def group_bytes_padded(some_bytes, group_size):
  for i in range(0, len(some_bytes), group_size):
    tmp = some_bytes[i:i+group_size]
    if len(tmp) == group_size:
      yield tmp
    else:
      val = bytearray(group_size)
      val[0:len(tmp)] = tmp
      yield val

def group_bytes(some_bytes, group_size):
  for i in range(0, len(some_bytes), group_size):
    yield some_bytes[i:i+group_size]

def dump_hex(some_bytes):
  dump = ""
  for b in some_bytes:
    dump = "{:02X}{:s}".format(b,dump)
  return dump

def dump_hex_padded(some_bytes, some_width):
  dump = ""
  i = 0
  for b in some_bytes:
    dump = "{:02X}{:s}".format(b,dump)
    i += 1
  if i < some_width:
      dump = "{:s}{:s}".format("00"*(some_width-i),dump)
  return dump

def input_y_n(prompt):
  s = input(prompt)
  return s.lower() in ["", "y", "ye", "yes"]

##########################
# elf sections filtering #
##########################

def filter_elf_sections(sections, only=None, exclude=None, force_skip=False):
  filtered = list(sections)
  if only:
    filtered = [x for x in filtered if str(x.name) in only]
  if exclude:
    filtered = [x for x in filtered if str(x.name) not in exclude]
  last_top = 0
  for s in filtered:
    skip = False
    addr = s.header["sh_addr"]
    top = addr + s.header["sh_size"] # XXX check data sz compared to section sz
    if addr < last_top:
      if force_skip:
        skip = True
      else:
        skip = input_y_n("{:s} overlaps with previous sections. Skip {:s} (Y/n) ? ".format(*[str(s.name)]*2))
    if not skip:
      last_top = top
    else:
      filtered = [x for x in filtered if str(x.name) != str(s.name)]
  return filtered

##################
# write hex file #
##################

def elf_sections_to_hex(sections, outfile, byte_width, start_addr, end_addr):
  verboseprint(1,"Creating HEX file")
  ssections = sorted(sections, key = lambda x: x.header["sh_addr"])
  last_addr = start_addr
  remaining = bytearray(0)

  for s in ssections:
    base = s.header["sh_addr"]
    top  = base + s.header["sh_size"]
    # skip empty sections
    if s.header["sh_size"] == 0:
      continue
    # skip too low
    if top < start_addr:
      continue
    # break too high
    if end_addr:
      if end_addr < base:
        break
    # sections with content...
    padding = remaining # fold in unaligned bytes from previous section
    offset = 0
    if base > last_addr: # fill gap with zeroes
      padding += bytearray(base - last_addr)
    else:
      offset = last_addr - base
    remaining = bytearray(0) # reset remaining bytes
    for g in group_bytes(padding + s.data()[offset:], byte_width):
      if len(g) == byte_width:
        outfile.write("{:s}\n".format(dump_hex(g)))
      else:
        remaining = g
    # prepare next step
    last_addr = top

  # remaining bytes to write ...
  if len(remaining) != 0:
    outfile.write(dump_hex_padded(remaining, byte_width))

##################
# write mif file #
##################

def elf_sections_to_mif(sections, outfile, word_byte_width, addr_rad, data_rad, group_same=False):
  verboseprint(1,"Creating MIF file")
  ssections = sorted(sections, key = lambda x: x.header["sh_addr"])
  last_addr = ssections[-1].header["sh_addr"] + ssections[-1].header["sh_size"]
  nb_words = int(last_addr/word_byte_width)
  outfile.write("DEPTH = {:d};\n".format(nb_words))
  outfile.write("WIDTH = {:d};\n".format(word_byte_width*8))
  outfile.write("ADDRESS_RADIX = {:s};\n".format(addr_rad))
  outfile.write("DATA_RADIX = {:s};\n".format(data_rad))
  outfile.write("CONTENT\n")
  outfile.write("BEGIN\n")
  max_aw = len("{:{rad}}".format(nb_words,rad=rad_to_fmt(addr_rad)))
  max_dw = field_width(word_byte_width, data_rad)
  word_addr = 0
  for s in ssections:
    if int(s.header["sh_addr"]/word_byte_width) > word_addr: # fill gap with zeroes
      if group_same:
        outfile.write("[{:0{aw}{rad_a}}..{:0{aw}{rad_a}}]: {:0{dw}{rad_d}};\n".format(word_addr, (s.header["sh_addr"]/word_byte_width)-1, 0, aw=max_aw, rad_a=rad_to_fmt(addr_rad), dw=max_dw, rad_d=rad_to_fmt(data_rad)))
      else:
        for wa in range(word_addr, int(s.header["sh_addr"]/word_byte_width)):
          outfile.write("{:0{aw}{rad_a}}: {:0{dw}{rad_d}};\n".format(wa, 0, aw=max_aw, rad_a=rad_to_fmt(addr_rad), dw=max_dw, rad_d=rad_to_fmt(data_rad)))
      word_addr = int(s.header["sh_addr"]/word_byte_width)
    for word in group_bytes_padded(s.data(), word_byte_width):
      data = int.from_bytes(word, byteorder='little', signed=(True if data_rad == 'DEC' else False))
      outfile.write("{:0{aw}{rad_a}}: {:0{dw}{rad_d}};\n".format(word_addr, data, aw=max_aw, rad_a=rad_to_fmt(addr_rad), dw=max_dw, rad_d=rad_to_fmt(data_rad)))
      word_addr += 1
  outfile.write("END;")

#################
# main function #
#################

def main():
  if args.output == None:
    args.output, _ = op.splitext(args.elf)
    args.output = op.basename(args.output)+"."+args.subcmd
  with open(args.elf,"rb") as in_f:
    elf = ELFFile(in_f)
    if (args.subcmd == "info"):
      print("-------- {:s} --------".format(args.elf))
      print("-- HEADER --")
      print("EI_CLASS: {:s}".format(elf.header.e_ident.EI_CLASS))
      print("EI_DATA: {:s}".format(elf.header.e_ident.EI_DATA))
      print("EI_OSABI: {:s}".format(elf.header.e_ident.EI_OSABI))
      print("e_type: {:s}".format(elf.header.e_type))
      print("e_machine: {:s}".format(elf.header.e_machine))
      print("e_entry: 0x{:016x}".format(elf.header.e_entry))
      if args.list_sections:
        print("-- SECTIONS --")
        for sec in elf.iter_sections():
          rpt = "Null section \"{:s}\"".format(sec.name)
          if not sec.is_null():
            rpt = "Section {:20s} -- start: 0x{:016x}  size: {:8d} bytes".format(sec.name, sec.header.sh_addr, sec.data_size)
          print(rpt)
    else:
      sections = filter_elf_sections(elf.iter_sections(), args.only_section, args.exclude_section, args.force_skip)
      with open(args.output,"w") as out_f:
        verboseprint(1,"Opened {:s} for output".format(args.output))
        if (args.subcmd == "to-hex"):
          elf_sections_to_hex(sections, out_f, args.word_size, args.start_at, args.end_at)
        if (args.subcmd == "to-mif"):
          elf_sections_to_mif(sections, out_f, args.word_size, args.address_radix, args.data_radix, args.group_same)
    exit(0)

if __name__ == "__main__":
    main()
