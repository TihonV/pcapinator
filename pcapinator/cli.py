import argparse
import logging
from os import R_OK, access
from pathlib import Path
from typing import Any, Generic, List, Text, TypeVar

from pcapinator.consts import PROGNAME

__all__ = (
    'get_cli_args',
)

HEADER = "-" * 20 + " PCAPinator " + "-" * 20

T = TypeVar('T')

logger = logging.getLogger(__name__)


def get_existing_path(val: Text):
    prospective_path = Path(val).resolve()

    if all([access(prospective_path, R_OK), prospective_path.exists()]):
        return prospective_path

    raise argparse.ArgumentTypeError(
        "ReadablePath:{0} is not a readable path".format(prospective_path)
    )


def get_readable_file_or_dir_path(val: Text) -> Path:
    prospective_path = get_existing_path(val)

    if any([prospective_path.is_file(), prospective_path.is_dir()]):
        return prospective_path

    raise argparse.ArgumentTypeError(
        "FileOrDir:{0} is not a readable object".format(prospective_path)
    )


def get_writable_path(val: Text) -> Path:
    prospective_path = Path(val).resolve()

    if access(prospective_path, R_OK) and prospective_path.parent.exists():
        return prospective_path

    raise argparse.ArgumentTypeError(
        "WritablePath:{0} haven't parent directory or not acceptable for write".format(
            prospective_path
        )
    )


class _Args(Generic[T]):
    infile: List[Path]
    kismetdb: bool
    outfile: Path
    verbose: int
    split: bool
    split_count: int
    split_output: Path
    wshark_dir: Path
    handshakes: bool
    wifi_csv: bool
    hashcat: bool
    dnssimple: bool
    pcapfix: bool
    pcapfd: Path
    minsplitsz: Any
    tshark_query: Text
    tshark_fields: Any
    existing_tsv: bool
    validate_tsv: bool


def _init_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROGNAME,
        description=HEADER,
        usage='use "%(prog)s --help" for more information',
        epilog='PCAPinator - Tool for crazy PCAP analysis',
    )
    parser.add_argument(
        "infile",
        nargs='+',
        help="Input PCAP file or directory",
        type=get_readable_file_or_dir_path,
    )
    parser.add_argument(
        "--kismetdb",
        action="store_true",
        help="Extract PCAP files from Kismet DB"
    )
    # parser.add_argument("-r", "--recursive", action="store_true", dest="recursive",
    #                     help="Recursively search for PCAP files")
    parser.add_argument(
        "--out",
        action="store",
        type=get_writable_path,
        dest="outfile",
        help="Output file"
    )
    parser.add_argument(
        "-v",
        "--verbosity",
        action="count",
        default=0,
        help="defaults — no verbosity; \"-v\" — basic; \"-vv\" — performance counters; "
             "\"-vvv\" — extended"
    )
    parser.add_argument(
        "--split",
        action="store_true",
        dest="split",
        help="Split the PCAP into pieces based on CPU count"
    )
    parser.add_argument(
        "--split_count",
        action="store",
        type=int,
        dest="split_count",
        help="Set the number of pieces the PCAP will be split into"
    )
    parser.add_argument(
        "--split_output",
        action="store",
        type=get_writable_path,
        dest="split_output",
        help="Directory location of the newly split files"
    )
    parser.add_argument(
        "--wshark_dir",
        action="store",
        type=get_readable_file_or_dir_path,
        help="Define the location of the wireshark directory"
    )
    parser.add_argument(
        "--handshakes",
        action="store_true",
        help="Get WPA/WPA2 handshakes"
    )
    parser.add_argument(
        "--wifi_csv",
        action="store_true",
        help="Build CSV files with default tables"
    )
    parser.add_argument(
        "--hashcat",
        action="store_true",
        help="Output to Hashcat format"
    )
    parser.add_argument(
        "--dnsSimple",
        action="store_true",
        dest="dnssimple",
        help="Create a CSV of dns data only"
    )
    parser.add_argument(
        "--pcapfix",
        action="store_true",
        help="Fixes Borked PCAP files, only works in *nix"
    )
    parser.add_argument(
        "--pcapfix_dir",
        action="store",
        type=get_writable_path,
        dest="pcapfd",
        help="Set the PCAPFix directory where broken files will go"
    )
    parser.add_argument(
        "--min_split",
        action="store",
        dest="minsplitsz",
        default=209715200,
        help="Min Split Size in bytes, default 200 MB"
    )
    parser.add_argument(
        "--query",
        action="store",
        dest="tshark_query",
        help="A custom query that you want to run on a dataset, use with --fields"
    )
    parser.add_argument(
        "--fields",
        action="store",
        dest="tshark_fields",
        help="The fields list you would like to use with your query, use with --query"
    )
    parser.add_argument(
        "--unique_existing_tsv",
        action="store_true",
        dest="existing_tsv",
        help="Get unique data from an existing TSV file"
    )
    parser.add_argument(
        "--validate_wifi_tsv",
        action="store_true",
        dest="validate_tsv",
        help="Validate and fix a tsv file you are making"
    )

    return parser


# noinspection PyTypeChecker
def get_cli_args() -> _Args:
    return _init_parser().parse_args()
