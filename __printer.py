class printer:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    _debug = False

    def __init__(self, debug=True):
        self._debug = debug

    def ok(self, str):
        self.print_col( "[+]", str, self.OKGREEN)

    def info(self, str):
        self.print_col( "[*]", str, self.OKBLUE)

    def warn(self, str):
        self.print_col( "[~]", str, self.WARNING)

    def error(self, str):
        self.print_col( "[!]", str, self.FAIL)

    def debug(self, str):
        if self._debug:
            self.__default("[-] %s" % str)

    def print_col(self, str1, str2, col):
        print("%s%s%s %s" % (col, str1, self.ENDC, str2))

    def default(self, str):
        print(str)

