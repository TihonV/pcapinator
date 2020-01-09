from functools import wraps
from time import perf_counter
import logging


global DEBUG_LEVEL

perf_logger = logging.getLogger('perf')
perf_logger.setLevel(logging.DEBUG)


def add_perf_counter(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        _start = perf_counter()
        result = func(*args, **kwargs)
        _end = perf_counter()
        logging.debug('"{}" duration {}'.format(repr(func), _end - _start))
        return result

    return wrapper if DEBUG_LEVEL > 1 else func

