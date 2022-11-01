import textwrap


class Printer:

    DARK = {
        'DEBUG': '\033[0m',
        'PURPLE': '\033[35m',
        'INFO': '\033[34m',
        'OKGREEN': '\033[32m',
        'WARNING': '\033[33m',
        'FAIL': '\033[31m',
        'ENDC': '\033[0m',
        'BOLD': '\033[1m',
        'UNDERLINE': '\033[4m'
    }
    LIGHT = {
        'DEBUG': '\033[90m',
        'PURPLE': '\033[95m',
        'INFO': '\033[94m',
        'OKGREEN': '\033[92m',
        'WARNING': '\033[93m',
        'FAIL': '\033[91m',
        'ENDC': '\033[0m',
        'BOLD': '\033[1m',
        'UNDERLINE': '\033[4m'
    }

    _debug_on = False
    _trace_on = False
    _wrap_length = 0

    def __init__(self, debug=True, trace=False, wrap=0, dark=False):
        self._debug_on = debug or trace
        self._trace_on = trace
        self._wrap_length = wrap
        self._colours = self.DARK if dark else self.LIGHT

    def ok(self, msg, newline_before=False):
        self.print_col("[+]", self._wrap(msg), self._colours.get('OKGREEN'), newline_before)

    def info(self, msg, newline_before=False):
        self.print_col("[*]", self._wrap(msg), self._colours.get('INFO'), newline_before)

    def warn(self, msg, newline_before=False):
        self.print_col("[~]", self._wrap(msg), self._colours.get('WARNING'), newline_before)

    def error(self, msg, exception: Exception = None, newline_before=False):
        if exception:
            self.print_col("[!]", self._wrap(f"{msg}\n{getattr(exception, 'message', str(exception))}"), self._colours.get('FAIL'), newline_before)
        else:
            self.print_col("[1]", self._wrap(msg), self._colours.get('FAIL'), newline_before)

    def debug(self, msg, newline_before=False):
        if self._debug_on:
            self.print_col("[-]", self._wrap(msg), self._colours.get('DEBUG'), newline_before)

    def trace(self, msg, newline_before=False):
        if self._trace_on:
            self.__default("[ ] {}".format(self._wrap(msg)), newline_before)

    def print_col(self, str1, str2, col, newline_before=False):
        prefix = "\n" if newline_before else ""
        print("{}{}{}{} {}".format(prefix, col, str1, self._colours.get('ENDC'), str2))

    @staticmethod
    def __default(msg, newline_before=False):
        prefix = "\n" if newline_before else ""
        print(f"{prefix}{msg}")

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
