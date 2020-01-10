import logging
import struct
import subprocess
from functools import partial, update_wrapper, wraps
from itertools import chain
from pathlib import Path
from time import perf_counter
from typing import List, Iterator, Text, Generator
from uuid import uuid4

import pandas as pd

from pcapinator.consts import CHUNKSZ

global DEBUG_LEVEL


perf_logger = logging.getLogger('perf')
util_logger = logging.getLogger('util')


def add_perf_counter(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        _start = perf_counter()
        result = func(*args, **kwargs)
        _end = perf_counter()
        logging.debug('"{}" duration {}'.format(repr(func), _end - _start))
        return result

    return wrapper if DEBUG_LEVEL > 1 else func


@add_perf_counter
def gen_path4files(
        input_list: List[Path],
        file_mask: Text = '*'
) -> Generator[Path, None, None]:
    """
    Provides generator with recursive path finder
    :param input_list: paths for files or dirs
    :param file_mask: glob mask for filtering
    :return: generator with Path-objects
    """
    files_in_dir = map(
        partial(Path.rglob, '**/{}'.format(file_mask)),
        filter(Path.is_dir, input_list)
    )
    files = filter(Path.is_file, input_list)
    all_of_them = chain(files, files_in_dir)

    yield from all_of_them


def fix_broken_ssid_line(s: Text) -> Text:
    """
    Function for applying automatic fix for broken tsv lines
    :param s: broken string

    :return fixed string

    TODO: Add the ability to call this function from the command line, test for functionality
    """

    def _find_nth(haystack, needle, n):
        parts = haystack.split(needle, n)
        if len(parts) <= n:
            return -1
        return len(haystack) - len(parts[-1]) - len(needle)

    st_pos: int = _find_nth(s, '\t', 8)
    en_pos: int = _find_nth(s, '\t', 9)

    broken_ssid = s[st_pos + 1:en_pos]
    pos: int = _find_nth(broken_ssid, '"', 2)
    new_ssid: Text = broken_ssid[:pos] + broken_ssid[pos + 1:]
    fixed_line = s[:st_pos + 1] + new_ssid + s[en_pos:]
    return fixed_line


@add_perf_counter
def autofix_tsv_ssid(p: Path) -> Path:
    """
    Function for applying automatic fixture for TSV file
    :return: fixed TSV file
    """
    fixed_file = Path('fixed-{}'.format(p.name))
    with fixed_file.open('w+') as nf:
        with p.open() as f:
            for line_idx, line in enumerate(f):
                quotecnt = line.count('"')
                tabcnt = line.count('\t')
                if quotecnt % 2 or tabcnt != 16:
                    util_logger.debug(
                        "Broken Line: {} (quotecnt: {}, tabcnt: {})".format(
                            line_idx, quotecnt, tabcnt
                        )
                    )
                    util_logger.debug("** FULL LINE: {}".format(line))
                    if tabcnt == 16:
                        # try to fix it
                        nf.write(fix_broken_ssid_line(line))
                else:
                    nf.write(line)
    return fixed_file


# It's wrapper over Pandas TSV parser with predefined args and perf_counter
pd_chunked_reader = update_wrapper(
    add_perf_counter,
    partial(
        pd.read_csv,
        sep='\t',
        lineterminator='\n',
        names=['time', 'time_epoch', 'sa', 'ta', 'ta_resolved',
               'ra', 'da', 'bssid', 'ssid', 'manufacturer',
               'device_name', 'model_name', 'model_number',
               'uuid_e', 'fc_type_subtype', 'frame_len', 'signal'],
        dtype={'device_name': 'object', 'manufacturer': 'object',
               'model_name': 'object', 'model_number': 'object',
               'uuid_e': 'object', 'fc_type_subtype': 'Int64'}
    )
)


@add_perf_counter
def make_unique_ssid_for_tsv(
        file: Iterator[Path],
        chunksize=CHUNKSZ
) -> Path:
    """
    Function for creating small temporary TSV pieces with unique values
    :return: TSV with uq-data
    """
    result = pd.DataFrame()
    result_file = Path('unique-{}.tsv'.format(uuid4()))

    dub_filter = {
        'subset': ['ssid']
    }

    result_drop_dups = update_wrapper(add_perf_counter, result.drop_duplicates)

    for idx, chunk in enumerate(pd_chunked_reader(file, chunksize=chunksize)):
        drop_dups = update_wrapper(add_perf_counter, chunk.drop_duplicates)
        result.append(drop_dups(**dub_filter))
        result = result_drop_dups(**dub_filter)
        logging.debug("Complete counting on {} chunk".format(idx))

    writer = update_wrapper(add_perf_counter, result.to_csv)
    writer(str(result_file), sep='\t', index=False)
    return result_file


def write_pcap_header(f, dlt):
    hdr = struct.pack(
        'IHHiIII',
        0xa1b2c3d4,  # magic
        2, 4,  # version
        0,  # offset
        0,  # sigfigs
        8192,  # max packet len
        dlt  # packet type
    )

    f.write(hdr)


def write_pcap_packet(f, timeval_s, timeval_us, packet_bytes):
    pkt = struct.pack(
        'IIII',
        timeval_s,
        timeval_us,
        len(packet_bytes),
        len(packet_bytes)
    )
    f.write(pkt)
    f.write(packet_bytes)


@add_perf_counter
def convert2hccapx(*args, out_dir: Path, executable: Path, files: Iterator[Path] = None):
    @add_perf_counter
    def _call_converter(file: Path):
        _cmd = '"{}" "{}" "{}.hccapx"'.format(
            executable,
            file.resolve(),
            out_dir.joinpath(file.name)
        )
        util_logger.debug('Run {}'.format(_cmd))

        subprocess.check_output(_cmd, shell=True)

    for file in chain(args, files):
        _call_converter(file)
        util_logger.info('{} was been converted to hccapx'.format(file.name))
    else:
        util_logger.error('No target provided for hccapx-converter')


@add_perf_counter
def merge_csv(out_dir: Path):
    util_logger.debug('outdir: {}'.format(out_dir))
    first_file, *tsv_files, last_file = filter(
        lambda p: ('split' in p.name and p.name[-4:].lower() == '.tsv'),
        out_dir.iterdir()
    )

    # split_Kismet-20170726-10-21-17-1-fixed_00000_20170711010628.tsv
    # split_Kismet-20170725-09-35-21-1_00001_20170711010800.tsv
    # subprocess.call ('"{}" -F pcap -c {} "{}" {}split_{}.pcap'.format(EDITCAP, chunk_size, inpcap, outdir, filename), shell=True)
    # What's happening to them: -17-30-1-fixed-808-06-37-49-1.pcap.tsv

    util_logger.debug("tsv_files: {}".format(tsv_files))
    # Check to see if it has a split time

    start_time = first_file.name.split('.')[0][-14:]
    stop_time = last_file.name.split('.')[0][-14:]

    out_file = Path('{}-{}.pcap.tsv'.format(start_time, stop_time))

    with out_file.open('wb') as fout:
        for f in tsv_files:
            with f.open('rb') as fin:
                # skip first line
                _ = fin.readline()

                fout.write(fin.read())

    return out_file
