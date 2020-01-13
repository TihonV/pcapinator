import sys
from pathlib import Path

__all__ = [
    'PROGNAME',
    'WSHARK_DEFAULT_DIR',
    'get_wshark_executables',
    'PERF',
    'VERBOSE',
]


def add_extension(filename):
    if sys.platform == 'win32':
        return '{}.exe'.format(filename)
    return filename


def get_wshark_executables(app_dir):
    return {
        'tshark': app_dir / add_extension('tshark'),
        'editcap': app_dir / add_extension('editcap'),
        'capinfos': app_dir / add_extension('capinfos'),
        'mergecap': app_dir / add_extension('mergecap'),
    }


PROGNAME = 'pcapinator'
WSHARK_DEFAULT_DIR = Path(
    'C:/Program Files/Wireshark'
    if sys.platform == 'win32'
    else '/usr/bin/'
)
PERF = 15
VERBOSE = 18
