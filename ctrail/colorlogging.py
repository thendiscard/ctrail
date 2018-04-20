

import os
import sys

from logging import basicConfig as logging_basicConfig, \
    addLevelName as logging_addLevelName, \
    getLogger as logging_getLogger, \
    log as logging_log, \
    DEBUG   as logging_level_DEBUG, \
    INFO    as logging_level_INFO,  \
    WARN    as logging_level_WARN,  \
    ERROR   as logging_level_ERROR, \
    debug   as logging_debug,   \
    info    as logging_info,    \
    warn    as logging_warn,    \
    error   as logging_error

from multiprocessing import current_process


#
# 256 color terminal color test:
#
# print("FG | BG")
# for i in range(256):
#    # foreground color | background color
#    print("\033[48;5;0m\033[38;5;{0}m #{0} \033[0m | "
#            "\033[48;5;{0}m\033[38;5;15m #{0} \033[0m".format(i))
#
LOGGING_LEVELS = {
    'ERROR' : {
        'level' : logging_level_ERROR,
        'name'  : 'ERROR',
        'xterm' : '31m',
        '256color': '38;5;196m',
    },
    'NORMAL' : {
        'level' : 35,
        'name'  : '',
        'xterm' : '37m',
        '256color': '38;5;255m',
    },
    'WARNING' : {
        'level' : logging_level_WARN,
        'name'  : 'WARN',
        'xterm' : '33m',
        '256color': '38;5;227m',
    },
    'INFO' : {
        'level' : logging_level_INFO,
        'name'  : 'INFO',
        'xterm' : '36m',
        '256color': '38;5;45m',
    },
    'DEBUG' : {
        'level' : logging_level_DEBUG,
        'name'  : 'DEBUG',
        'xterm' : '35m',
        '256color': '38;5;135m',
    },
}


#
# We allow the log level to be specified on the command-line or in the
# config by name (string/keyword), but we need to convert these to the
# numeric value:
#
LOGGING_LEVELS_MAP = {
    'NORMAL'    : LOGGING_LEVELS['NORMAL']['level'],
    'ERROR'     : logging_level_ERROR,
    'WARN'      : logging_level_WARN,
    'INFO'      : logging_level_INFO,
    'DEBUG'     : logging_level_DEBUG,
    'normal'    : LOGGING_LEVELS['NORMAL']['level'],
    'error'     : logging_level_ERROR,
    'warn'      : logging_level_WARN,
    'info'      : logging_level_INFO,
    'debug'     : logging_level_DEBUG
}


def log(msg: str):
    """Convenience wrapper function for calling logging.log with our 'NORMAL' level"""

    logging_log(LOGGING_LEVELS['NORMAL']['level'], msg)


def info(msg: str):

    logging_info(msg)


def warn(msg: str):

    logging_warn(msg)


def error(msg: str):

    logging_error(msg)


def debug(msg: str):

    logging_debug(msg)


def color_logging_setup():
    #
    # Set logging to INFO by default (log everything except DEBUG).
    #
    # Also try to add colors to the logging output if the logging output goes
    # to a capable device (not a file and a terminal supporting colors).
    #
    # Actually adding the ANSI escape codes in the logging level name is pretty
    # much an ugly hack but it is the easiest way (less changes).
    #
    # An elegant way of doing this is described here:
    #  http://stackoverflow.com/questions/384076/how-can-i-color-python-logging-output
    #
    proc_name = current_process().name
    proc_pid = os.getpid()
    proc_info = f" {proc_name}/{proc_pid}:" if proc_name != 'MainProcess' else ''
    fmt_str = f"%(asctime)s %(levelname)s:{proc_info} %(message)s"
    out_dev_istty = getattr(sys.stdout, 'isatty', None)

    if ((out_dev_istty is not None) and (out_dev_istty())):
        if ('256color' in os.environ['TERM']):
            for lvl in LOGGING_LEVELS.keys():
                logging_addLevelName(LOGGING_LEVELS[lvl]['level'],
                                     "\033[{0}{1}".format(
                                         LOGGING_LEVELS[lvl]['256color'],
                                         LOGGING_LEVELS[lvl]['name']))
            fmt_str = f"\033[38;5;250m%(asctime)s\033[0m %(levelname)s:" \
                      f"{proc_info} %(message)s\033[0m"
        elif ('xterm' in os.environ['TERM']):
            for lvl in LOGGING_LEVELS.keys():
                logging_addLevelName(LOGGING_LEVELS[lvl]['level'],
                                     "\033[{0}{1}".format(
                                         LOGGING_LEVELS[lvl]['xterm'],
                                         LOGGING_LEVELS[lvl]['name']))
            fmt_str = f"\033[37m%(asctime)s\033[0m %(levelname)s:" \
                      f"{proc_info} %(message)s\033[0m"
        else:
            logging_addLevelName(LOGGING_LEVELS['NORMAL']['level'],
                                 LOGGING_LEVELS['NORMAL']['name'])

    logging_basicConfig(format=fmt_str, level=logging_level_INFO,
                        stream=sys.stdout)
    logger = logging_getLogger()

    return logger
