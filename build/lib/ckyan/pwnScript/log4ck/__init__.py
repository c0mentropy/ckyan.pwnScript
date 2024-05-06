from pwn import log


class Colors:
    def __init__(self):
        self.error = "31"
        self.success = "32"
        self.warning = "33"
        self.debug = "34"


log_colors = Colors()


def debug(message: str, *args, **kwargs):
    try:
        message = "\033[" + log_colors.debug + "m" + message + "\033[0m"
        log.debug(message, *args, **kwargs)
    except Exception as ex:
        print(str(ex))


def info(message: str, *args, **kwargs):
    try:
        log.info(message, *args, **kwargs)
    except Exception as ex:
        print(str(ex))


def success(message: str, *args, **kwargs):
    try:
        message = "\033[" + log_colors.success + "m" + message + "\033[0m"
        log.success(message, *args, **kwargs)
    except Exception as ex:
        print(str(ex))


def warning(message: str, *args, **kwargs):
    try:
        message = "\033[" + log_colors.warning + "m" + message + "\033[0m"
        log.warning(message, *args, **kwargs)
    except Exception as ex:
        print(str(ex))


def warning_once(message: str, *args, **kwargs):
    try:
        message = "\033[" + log_colors.warning + "m" + message + "\033[0m"
        log.warning_once(message, *args, **kwargs)
    except Exception as ex:
        print(str(ex))


def warn(message: str, *args, **kwargs):
    return warning(message, *args, **kwargs)


def warn_once(message: str, *args, **kwargs):
    return warning_once(message, *args, **kwargs)


def error(message: str, *args, **kwargs):
    try:
        message = "\033[" + log_colors.error + "m" + message + "\033[0m"
        log.error(message, *args, **kwargs)
    except Exception as ex:
        # print(str(ex))
        pass
