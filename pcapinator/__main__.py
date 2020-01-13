#!/usr/bin/env python3
"""
PCAPinator
By: Mike Spicer (@d4rkm4tter)

"""
import logging
import sys
from itertools import chain
from pathlib import Path
from typing import Iterator

from pcapinator import captools, utils
from pcapinator.cli import get_cli_args
from pcapinator.consts import get_wshark_executables

TOOLS = {}


def _configure_logger(verbosity: int = 0) -> logging.Logger:
    logs_severity = logging.INFO

    if verbosity == 1:
        logs_severity = 18
    if verbosity == 2:
        logs_severity = 14
    if verbosity >= 3:
        logs_severity = logging.DEBUG

    logging.basicConfig(level=logs_severity)
    return logging.getLogger(__name__)


@utils.add_perf_counter
def main():
    args = get_cli_args()
    logger = _configure_logger(args.verbose)

    # Find wireshark tools by the path
    TOOLS.update(get_wshark_executables(args.override_wshark))

    logger.debug('Running with args: {}'.format(args.__dict__))
    logger.info('Opening files: {}'.format(args.infile))

    pcap_files = tuple()

    if args.existing_tsv:
        tsv_files = utils.gen_path4files('*.tsv', args.infile)

        if args.validate_tsv:
            tsv_files: Iterator[Path] = map(
                utils.autofix_tsv_ssid,
                tsv_files
            )

        utils.make_unique_ssid_for_tsv(tsv_files)

    elif args.kismetdb:
        kismet_files = utils.gen_path4files('*.kismet', args.infile)
        pcap_files = tuple(captools.process_kismet_log(kismet_files))

    else:
        pcap_files = tuple(
            chain(
                utils.gen_path4files('*.pcap', args.infile),
                utils.gen_path4files('*.pcapdump', args.infile),
            )
        )

    _executable_ext = ''

    _is_win_32 = sys.platform == 'win32'

    if _is_win_32:
        _executable_ext = '.exe'
        logger.debug("Running under windows!")

    logger.debug("input list {}".format(pcap_files))
    logger.debug('PCAP {}'.format(list(pcap_files)))

    if _is_win_32 and args.pcap_fix_dir:
        logger.critical(
            "Windows isn't supported for PCAPFIX, time to install Cygwin/WSL or use Linux."
        )
        exit(2)
    elif args.pcap_fix_dir:
        logger.debug('Try to applying pcap fixtures {}'.format(args.infile))
        captools.pcap_fix(pcap_files, args.pcap_fix_dir, TOOLS['tshark'])

    if args.split_count:
        if args.split_output.is_dir():
            args.split_output.mkdir()
        captools.split_pcap(
            args.infile,
            args.split_output,
            args.split_count
        )

    if any([args.handshakes_out, args.override_hccapx_tool]):
        if not args.override_hccapx_tool:
            logger.error("hccapx converter doesn't provided.")
            exit(1)

        captools.process_handshakes(
            map(Path, pcap_files),
            args.handshakes_out
        )
        utils.convert2hccapx(executable=args.override_hccapx_tool)

    if args.wifi_tsv:
        pass

    if args.dns_simple:
        pass

    if args.pcap_fix_dir:
        captools.pcap_fix(
            chain(utils.gen_path4files('*.pcap'), utils.gen_path4files('*.pcapdump')),
            args.pcap_fix_dir,
            TOOLS['tshark']
        )

    if args.tshark_query and args.tshark_fields:
        pass


if __name__ == '__main__':
    main()
