import textwrap


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

    _debug_on = False
    _trace_on = False
    _wrap_length = 0

    def __init__(self, debug=True, trace=False, wrap=0):
        self._debug_on = debug
        self._trace_on = trace or trace
        self._wrap_length = wrap

    def ok(self, msg):
        self.print_col("[+]", self._wrap(msg), self.OKGREEN)

    def info(self, msg):
        self.print_col("[*]", self._wrap(msg), self.INFO)

    def warn(self, msg):
        self.print_col("[~]", self._wrap(msg), self.WARNING)

    def error(self, msg, exception: Exception = None):
        if exception:
            self.print_col("[!]", self._wrap(f"{msg}\n{getattr(exception, 'message', str(exception))}"), self.FAIL)
        else:
            self.print_col("[1]", self._wrap(msg), self.FAIL)

    def debug(self, msg):
        if self._debug_on:
            self.print_col("[-]", self._wrap(msg), self.DEBUG)

    def trace(self, msg):
        if self._trace_on:
            self.__default("[ ] {}".format(self._wrap(msg)))

    def print_col(self, str1, str2, col):
        print("{}{}{} {}".format(col, str1, self.ENDC, str2))

    @staticmethod
    def __default(msg):
        print(msg)

    def _wrap(self, msg):
        out = []
        init_indent = ""
        indent = " "*4
        for line in msg.splitlines():
            if self._wrap_length:
                out.append(textwrap.fill(line, self._wrap_length, initial_indent=init_indent, subsequent_indent=indent))
            else:
                out.append(init_indent + line)

            init_indent = indent

        return "\n".join(out)
