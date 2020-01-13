import argparse
import logging
from os import R_OK, W_OK, access
from pathlib import Path
from typing import Any, Generic, List, Text, TypeVar

from pcapinator.consts import PROGNAME, WSHARK_DEFAULT_DIR

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

    if access(prospective_path.parent, W_OK) and prospective_path.parent.exists():
        return prospective_path

    raise argparse.ArgumentTypeError(
        "NotWritablePath:{0} haven't parent directory or not acceptable for write".format(
            prospective_path
        )
    )


SIZE_UNITS = {"B": 1, "KB": 2 ** 10, "MB": 2 ** 20, "GB": 2 ** 30, "TB": 2 ** 40}


def parse_size(size):
    number = ''.join(
        filter(
            str.isdigit, size
        )
    )
    unit = size[len(number):]
    return int(number) * SIZE_UNITS[unit.upper()]


class _Args(Generic[T]):
    infile: List[Path]
    kismetdb: bool
    outfile: Path
    verbose: int
    split_count: int
    split_output: Path
    override_wshark: Path
    handshakes_out: Path
    wifi_tsv: Path
    override_hccapx_tool: Path
    dns_simple: bool
    pcap_fix_dir: Path
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
        "-w",
        "--workers",
        action="store",
        dest="workers",
        help="max CPU workers count"
    )
    parser.add_argument(
        "--split-data-by-parts",
        action="store",
        type=int,
        default=0,
        dest="split_count",
        help="Set the number of pieces the PCAP will be split into"
    )
    parser.add_argument(
        "--temp-directory",
        action="store",
        type=get_writable_path,
        dest="split_output",
        help="Directory location of storing temporary files"
    )
    parser.add_argument(
        "--override-wshark",
        action="store",
        default=WSHARK_DEFAULT_DIR,
        type=get_readable_file_or_dir_path,
        help="Define the location of the `./wireshark/bin` directory"
    )
    parser.add_argument(
        "--handshakes-out",
        action="store",
        type=get_writable_path,
        help="output folder for WPA/WPA2 handshakes"
    )
    parser.add_argument(
        "--wifi-tsv",
        action="store",
        type=get_readable_file_or_dir_path,
        help="build TSV files with default tables"
    )
    parser.add_argument(
        "--override-hccapx-tool",
        action="store",
        type=get_readable_file_or_dir_path,
        help="override to hccapx utility"
    )
    parser.add_argument(
        "--dns-simple",
        action="store_true",
        dest="dns_simple",
        help="make TSV only with dns data"
    )
    parser.add_argument(
        "--pcap-fix-dir",
        action="store",
        type=get_writable_path,
        dest="pcap_fix_dir",
        help="save autofixed pcap-files into specific directory"
    )
    parser.add_argument(
        "--chunk-size",
        action="store",
        dest="chunk_size",
        type=parse_size,
        default=parse_size('200MB'),
        help="Min Split Size in bytes, default 200 MB"
    )
    parser.add_argument(
        "--tshark-query",
        action="store",
        dest="tshark_query",
        help="passing field list to tshark with `--query`"
    )
    parser.add_argument(
        "--tshark-fields",
        action="store",
        dest="tshark_fields",
        help="passing field list to tshark with `--fields`"
    )
    parser.add_argument(
        "--unique-tsv-out",
        action="store",
        dest="existing_tsv",
        help="Calculate & save unique SSID from a dumps"
    )
    parser.add_argument(
        "--validate-wifi-tsv",
        action="store_true",
        dest="validate_tsv",
        help="apply fixture to a broken SSID in tsv file"
    )
    parser.add_argument(
        "-v",
        dest="verbose",
        action="count",
        default=0,
        help="defaults — no verbosity; \"-v\" — basic; \"-vv\" — performance counters; "
             "\"-vvv\" — extended"
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 1.0"
    )

    return parser


# noinspection PyTypeChecker
def get_cli_args() -> _Args:
    return _init_parser().parse_args()
