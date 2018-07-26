import re


class Printer:
    DEBUG = '\033[90m'
    PURPLE = '\033[95m'
    INFO = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    __debug_on = False
    __trace_on = False
    __wrap_length = 0

    def __init__(self, debug=True, trace=False, wrap=0):
        self.__debug_on = debug
        self.__trace_on = trace
        self.__wrap_length = wrap

    def ok(self, str):
        self.print_col("[+]", self.__wrap(str), self.OKGREEN)

    def info(self, str):
        self.print_col("[*]", self.__wrap(str), self.INFO)

    def warn(self, str):
        self.print_col("[~]", self.__wrap(str), self.WARNING)

    def error(self, str):
        self.print_col("[!]", self.__wrap(str), self.FAIL)

    def debug(self, str):
        if self.__debug_on:
            self.print_col("[-]", self.__wrap(str), self.DEBUG)

    def trace(self, str):
        if self.__trace_on:
            self.__default("[ ] {}".format(self.__wrap(str)))

    def print_col(self, str1, str2, col):
        print("{}{}{} {}".format(col, str1, self.ENDC, str2))

    def __default(self, str):
        print(str)

    def __wrap(self, str):
        if self.__wrap_length == 0:
            return str
        out = []
        wl = self.__wrap_length - 4 # "4" because of the "[x] "
        for line in str.split('\n'):
            tmp = line.strip()
            while len(tmp) > wl:
                # Try for a space to split on first so we don't mess up IP addresses and domains
                r = re.search(r"[\s]", tmp[wl - 1:])
                if r is not None:
                    i = r.start() + wl
                    out.append(tmp[:i].strip())
                    tmp = tmp[i:].strip()
                else:
                    if len(tmp) > wl + 15: # bit of a buffer to try and stop splitting the last word
                        # just hard split :(
                        out.append(tmp[:wl].strip())
                        tmp = tmp[wl:].strip()
                    else:
                        break
            out.append(tmp)
        # 4 spaces to accomdate "[x] "
        return("\n    ".join(out))
