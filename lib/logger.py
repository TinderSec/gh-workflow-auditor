import logging

def parse_log_level_input(input):
    if input == 'debug':
        level = logging.DEBUG
    elif input == 'info':
        level = logging.INFO
    elif input == 'warning':
        level = logging.WARNING
    elif input == 'error':
        level = logging.ERROR
    elif input == 'critical':
        level = logging.CRITICAL
    else:
        input = logging.INFO

    return level

def build_logger(log_level='info'):
    log_format = logging.Formatter('%(levelname)s: %(message)s')
    logger = logging.getLogger('Audit Log')
    log_level = parse_log_level_input(log_level)
    logger.setLevel(log_level)

    channel = logging.StreamHandler()
    channel.setFormatter(log_format)

    log_file = logging.FileHandler('scan.log')

    logger.addHandler(channel)
    logger.addHandler(log_file)
    return logger

