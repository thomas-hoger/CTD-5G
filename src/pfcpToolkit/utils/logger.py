class TColors:
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'

    BG_BLACK = '\033[40m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'

    RESET = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    INVERSE = '\033[7m'

class Log:
    def __init__(self, prefix):
        self.prefix = prefix
    
    def set_prefix(self, prefix):
        self.prefix = prefix

    def info(self, message):
        print(f"{TColors.BOLD}{TColors.BLUE}{self.prefix}{TColors.RESET} {message}")

    def error(self, message):
        print(f"{TColors.BOLD}{TColors.RED}{self.prefix}{TColors.RESET} {message}")

    def success(self, message):
        print(f"{TColors.BOLD}{TColors.GREEN}{self.prefix}{TColors.RESET} {message}")

    def warning(self, message):
        print(f"{TColors.BOLD}{TColors.YELLOW}{self.prefix}{TColors.RESET} {message}")
