import logging
import multiprocessing as mp
import sqlite3
from contextlib import closing
from multiprocessing.pool import ThreadPool
from pathlib import Path
from typing import Any, List

from pcapinator.utils import (
    add_perf_counter,
    write_pcap_header,
    write_pcap_packet
)

logger = logging.getLogger(__name__)


@add_perf_counter
def kismet_log2pcap(kismetdb: Path, pid: Any) -> Path:
    with closing(sqlite3.connect(str(kismetdb))) as db:
        logger.debug("Id: {} sqlite3 DB opened: {}".format(pid, kismetdb))
        # noinspection SqlNoDataSourceInspection
        sql = "SELECT ts_sec, ts_usec, dlt, packet FROM packets WHERE dlt > 0"
        outfile = Path(kismetdb.name + '.pcap')
        npackets = 0

        with db.cursor() as conn:
            with outfile.open('wb') as file:
                for idx, row in enumerate(conn.execute(sql)):
                    ts_sec, ts_usec, dlt, packet = row

                    if npackets % 1000 == 0:
                        logger.debug("Id: {} Converted {} packets...".format(pid, npackets))

                    logger.debug(
                        "Id: {} Assuming dlt {} for all packets".format(pid, row[2])
                    )
                    logger.debug("Logging to {}".format(outfile))

                    if not idx:
                        write_pcap_header(file, dlt)
                    write_pcap_packet(file, ts_sec, ts_usec, packet)

                    npackets += 1
            logger.info("Id: {} Done! Converted {} packets.".format(pid, npackets))

        return outfile


@add_perf_counter
def process_kismet_log(kismetdbs) -> List[Any]:
    if len(kismetdbs) < mp.cpu_count():
        pool = ThreadPool(len(kismetdbs))
    else:
        pool = ThreadPool(mp.cpu_count())

    results = []

    for pid, f in enumerate(kismetdbs):
        # tsharking(inpcap, params, output, outext, procid)
        ("ID: {} Processing: {}".format(pid, f))
        results.append(pool.apply_async(kismet_log2pcap, (f, pid)))

    pool.close()
    pool.join()

    return results
