import concurrent.futures
import logging
import os
import shutil
import subprocess
from functools import partial
from itertools import chain
from pathlib import Path
from typing import Any, Callable, Iterator, List, Text, Union

from pcapinator.utils import add_perf_counter, merge_csv, make_unique_ssid_for_tsv

logger = logging.getLogger(__name__)


@add_perf_counter
def process_handshakes(
        pcapfiles: Iterator[Path],
        split_output: Path
):
    def _create_tshark_task(pid: int, f: Path) -> Callable:
        # -2 means that tshark will perform a two-pass
        # analysis causing buffered output until the entire
        # first pass is done. Prevents errors.

        tshark_args = '-R "(wlan.fc.type_subtype == 0x08 || ' \
                      'wlan.fc.type_subtype == 0x05 || eapol)" ' \
                      '-2 -F pcap -w hs_{}'.format(f.name)

        return partial(tsharking, str(f), tshark_args, '', '', pid)

    with concurrent.futures.ProcessPoolExecutor() as executor:
        executor.map(_create_tshark_task, enumerate(pcapfiles))
        executor.shutdown()

    merge_pcap_dumps()
    # clean_handshakes()
    clean_splits(split_output)


@add_perf_counter
def merge_pcap_dumps(executable):
    """
    Calling "mergecap -F pcap -w hs.pcap hs*.pcap"

    :param executable: mergecap executable path
    """
    logger.debug(
        'CMD# "{}" -F pcap -w handshakes.pcap hs*.pcap'.format(executable)
    )
    try:
        subprocess.check_output(
            '"{}" -F pcap -w handshakes.pcap hs*.pcap'.format(executable), shell=True
        )
    except subprocess.CalledProcessError as exc:
        logger.error("some error happened with mergecap", exc_info=exc)
        raise


@add_perf_counter
def clean_splits(dir_path: Path):
    """
    Recursive remove all pcap files whole directory
    :param dir_path: target path
    """
    logger.debug('clean_dir: {}'.format(dir_path))
    for f in chain.from_iterable(
            map(
                lambda file_type: dir_path.rglob('**/*.{}'.format(file_type)),
                ['pcap', 'pcapdump']
            )
    ):
        f.unlink()


@add_perf_counter
def pcap_fix(files: Iterator[Path], fix_dir: Path, executable: Path):
    """Method for apply pcapfix to file list"""

    @add_perf_counter
    def _apply_pcap_fixtures(pid, paths) -> None:
        _orig, _fixed = paths
        _cmd = '"{}" -o "{}" "{}"'.format(
            executable.absolute(), _fixed.absolute(), _orig
        )
        logger.debug('thread "{}" execute \"{}\"'.format(pid, _cmd))
        subprocess.check_output(_cmd, shell=True)

    logger.debug("PCAPFIXDIR: {}".format(fix_dir))

    if not fix_dir.exists():
        fix_dir.mkdir()

    fixed_files_list = tuple(
        map(
            fix_dir.joinpath,
            map(Path.name.fget, files)
        )
    )
    logger.debug("FIXED LIST: {}".format(fixed_files_list))

    with concurrent.futures.ThreadPoolExecutor() as executor:
        executor.map(_apply_pcap_fixtures, enumerate(zip(files, fixed_files_list)))
        executor.shutdown()

    for orig, fixed in zip(files, fixed_files_list):
        if orig.exists():
            logger.info('overwrite "{}" with fixtures'.format(fixed_files_list))
            fixed.rename(orig.absolute())


@add_perf_counter
def split_pcap(
        in_pcap: Path,
        out_dir: Path,
        split_executable: Path,
        capinfo_executable: Path,
        split_cnt: int = os.cpu_count()
):
    logger.debug('CMD# "{}" -c -M -T -m "{}"'.format(split_executable, in_pcap))
    packet_count = 0

    @add_perf_counter
    def _apply_split(file: Path):
        _cmd = '"{}" -K -c -M -T -m "{}"'.format(capinfo_executable, in_pcap)
        logger.debug('Run {}'.format(_cmd))
        try:
            subprocess.check_output(_cmd, shell=True)
        except subprocess.CalledProcessError as exc:
            logger.critical(
                'Something went wrong with pcap: {}'.format(exc.stdout),
                exc_info=exc
            )

    try:
        packet_count = int(
            subprocess.check_output(
                '"{}" -K -c -M -T -m "{}"'.format(capinfo_executable, in_pcap),
                shell=True
            ).split(b',')[-1]
        )
    except subprocess.CalledProcessError as e:
        logger.error('Error occured, run fixpcap first: %s' % (str(e.output)))
        return
    except TypeError:
        logger.critical('Unexpected output from capinfos')
        return

    chunk_size = packet_count // split_cnt + 1

    logger.info('Packet Count: {}'.format(packet_count))
    logger.info('Chunk Size: {}'.format(chunk_size))

    if in_pcap.stat().st_size <= split_cnt:
        logger.debug('*Copying, not splitting, too small*')
        logger.debug('CMD# cp {} {}.split'.format(in_pcap, out_dir.joinpath(in_pcap.name)))
        # noinspection PyTypeChecker
        shutil.copyfile(in_pcap, out_dir.joinpath("{}.split".format(in_pcap.name)))
    else:
        _apply_split()


@add_perf_counter
def tsharking(
        in_pcap: Path, params: Text, output: Text,
        proc_id: Any, tshark_executable: Path, out_dir: Path = Path.cwd()
):
    p: Union[subprocess.Popen, List] = list()

    if all([in_pcap.exists(), output]):
        _cmd = '{} -r "{}" {}'.format(tshark_executable, in_pcap, params)
        logger.debug("Run {}".format(_cmd))
        p = subprocess.Popen(
            _cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True
        )
    elif not output:
        logger.error(
            'Not sure why you are here, basically you called this function with an '
            'output directory but no output file.'
        )
        return

    elif out_dir.is_dir():
        out_file = out_dir.joinpath(output).resolve()
        _cmd = '{} -r "{}" {} >> "{}"'.format(
            tshark_executable, in_pcap, params, out_file
        )
        logger.debug('Run {}'.format(_cmd))

        p = subprocess.Popen(
            _cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True
        )

    out, err = p.communicate()

    logging.debug("ProcID {} stdout: {}".format(proc_id, out))
    logging.debug("ProcID {} stderr: {}".format(proc_id, err))

    return out, err


@add_perf_counter
def process_custom_query(pcap_files, query, fields, split_output):
    @add_perf_counter
    def _apply_command(pid: int, file: Path):
        tshark_args = '-T fields {} -E separator=/t ' \
                      '-E quote=d -E occurrence=f "{}"'.format(fields, query)
        *_tshark_outargs, _ = file.name
        out_file = Path(''.join(_tshark_outargs) + '.tsv')

        return tsharking(file, tshark_args, out_file, pid)

    with concurrent.futures.ProcessPoolExecutor() as executor:
        executor.map(_apply_command, enumerate(pcap_files))
        executor.shutdown()

    if len(pcap_files) > 1:
        merge_pcap_dumps()
        clean_splits(split_output)


@add_perf_counter
def process_dns_simple(pcap_files):
    @add_perf_counter
    def _apply_command(pid: int, file: Path):
        tshark_args = '-T fields -e dns.qry.name -e dns.resp.name -e dns.a -e dns.aaaa ' \
                      '-e dns.cname -e wlan.sa -e wlan.ta -e wlan.da -e wlan.ra ' \
                      '-e dns.srv.proto -E separator=/t -E quote=d -E occurrence=f ' \
                      '"dns || mdns"'
        *_tshark_outargs, _ = file.name
        out_file = Path(''.join(_tshark_outargs) + '.tsv')

        return tsharking(file, tshark_args, out_file, pid)

    with concurrent.futures.ProcessPoolExecutor() as executor:
        executor.map(_apply_command, enumerate(pcap_files))
        executor.shutdown()

    if len(pcap_files) > 1:
        tsvfile = merge_csv()
        clean_splits()

        make_unique_ssid_for_tsv(tsvfile)


# TODO: Build a dossier about a mac address
# What is interesting now about a mac address?
# What networks are they probing? What other sites are they visiting?

# TODO: Process and return a list of everything encrypted and what encryption type
# IE: wlan.rsn.akms.type == psk

# TODO: Get a list of all the SSID's and unique it

# TODO: Build summary endpoint and conversation reports for IP, TCP, UDP
# tshark -r input.cap.pcapng -q -z conv,ip > output.txt
# tshark -r input.cap.pcapng -q -z endpoint,ip > output.txt
# Gotta parse the output reports and send to Graphistry


@add_perf_counter
def process_csv(files: Iterator[Path], split_output: Path):
    _files = tuple(files)

    @add_perf_counter
    def _process_csv(pid: int, file: Path):
        tshark_args = '-T fields -e frame.time -e frame.time_epoch -e wlan.sa -e wlan.ta ' \
                      '-e wlan.ta_resolved -e wlan.ra -e wlan.da -e wlan.bssid -e wlan.ssid ' \
                      '-e wps.manufacturer -e wps.device_name -e wps.model_name ' \
                      '-e wps.model_number -e wps.uuid_e -e wlan.fc.type_subtype -e frame.len ' \
                      '-e wlan_radio.signal_dbm -E separator=/t -E quote=d -E occurrence=f'
        return tsharking(file, tshark_args, file.name, pid, split_output)

    with concurrent.futures.ProcessPoolExecutor() as executor:
        executor.map(_process_csv, _files)
        executor.shutdown()

    if _files:
        merge_csv(split_output)
        clean_splits(split_output)
