# elfmanip
Just fiddle with elf files to turn them into memory image.

## install dependencies
In order to run [elfmanip.py](elfmanip.py) you need `python3` and the `python3` packages listed in [requirements.txt](requirements.txt) to be installed.
Assuming a Ubuntu distribution, this can be done by running the following commands:
```
$ sudo apt install python3 python3-pip
$ pip3 install -r requirements.txt
```

## using elfmanip
[elfmanip.py](elfmanip.py) can generate a "hex" image or a "mif" image from and "elf" image. The help message displayed by invoking the script with th `--help` flag provides more details:
```
$ ./elfmanip.py --help
usage: elfmanip.py [-h] [-o OUTPUT] [--only-section SECTION [SECTION ...]]
                   [--exclude-section SECTION [SECTION ...]] [-s START_ADDR] [-i IMG_SZ] [-f] [-v]
                   ELF sub-command ...

Reads an elf file and exports it to another memory format.

positional arguments:
  ELF                   The elf file to re-export.
  sub-command           Individual sub-command help available by invoking it with -h or --help.
    info                Print ELF file info.
    to-hex              Generate a HEX file.
    to-mif              Generate a MIF file.

optional arguments:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        The OUTPUT file to export to. When unspecified, it is derived from the ELF
                        input.
  --only-section SECTION [SECTION ...]
                        Filters the list the elf SECTIONs to include only the specified ones. Note:
                        this filter is applied before the --exclude-section filter.
  --exclude-section SECTION [SECTION ...]
                        Filters the list the elf SECTIONs to exclude the specified ones. Note: this
                        filter is applied after the --only-section filter.
  -s START_ADDR, --start-addr START_ADDR
                        The address at which to start considering the content of the elf file
  -i IMG_SZ, --image-size IMG_SZ
                        The size (in bytes) of the image to generate
  -f, --force-skip      In case a section overlaps with an earlier section, force skipping.
  -v, --verbose         Increase verbosity level by adding more "v".
```

Further per sub-command help is available when using the `--help` flag after the sub-commad.
