#! /usr/bin/env python3

import argparse
import importlib
import sys
import textwrap

from pathlib import Path


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
            self.print_col("[!]", self._wrap(f"{msg}\n{getattr(exception, 'message', str(exception))}"), self.FAIL, fn=sys.stderr.write, add_newline=True)
        else:
            self.print_col("[!]", self._wrap(msg), self.FAIL, fn=sys.stderr.write, add_newline=True)

    def debug(self, msg):
        if self._debug_on:
            self.print_col("[-]", self._wrap(msg), self.DEBUG)

    def trace(self, msg):
        if self._trace_on:
            self.__default("[ ] {}".format(self._wrap(msg)))

    def print_col(self, str1, str2, col, fn=print, add_newline=False):
        fn("{}{}{} {}".format(col, str1, self.ENDC, str2))
        if add_newline:
            fn("\n")

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


def on_message(message, data):
    if message.get('type', '') == 'send':
        printer.ok("MSG: " + message.get('payload', ''))
        
    elif message.get('type', '') == 'error':
        printer.warn(message.get('description', '') + " (line " + message.get('lineNumber', '?') + ")")


if not importlib.util.find_spec('frida'):
    sys.stderr.write("Error: frida module not found\n")
    sys.exit(-2)

import frida

parser = argparse.ArgumentParser("Frida Spawner", description="Spawn a process with Frida and run the script")
parser.add_argument('package', help='Spawn a new process and attach')
parser.add_argument('scripts', help='Script(s) to hook', nargs='+')
parser.add_argument("-nk", "--nokill", dest="nokill", help="Don't kill the process when exiting", required=False, action="store_true")
parser.add_argument("-v", "--verbose", dest="verbose", help="Verbose output", required=False, action="store_true")
args = parser.parse_args()
printer = Printer(debug=args.verbose)

scripts = []
for script in args.scripts:
    p = Path(script)
    if not p.exists() or not p.is_file():
        printer.error(f"Invalid script file '{script}'")
        sys.exit(-1)
    with open(script, 'r') as f:
        scripts.append(f.read())
        printer.debug(f"Loaded '{script}'")

printer.info(f"Spawning {args.package}")
try:
    pid = frida.get_usb_device().spawn(args.package)
    session = frida.get_usb_device().attach(pid)

    script = session.create_script("{" + "};\n{".join(scripts) + "}")
    script.on('message', on_message)
    script.load()
    printer.info("Loaded script")
    
    frida.get_usb_device().resume(pid)
    printer.info("Connected to app. Use Ctrl-C to exit")
    sys.stdin.read()

except KeyboardInterrupt:
    try:
        if not args.nokill:
            printer.warn(f"Killing {args.package}")
            frida.get_usb_device().kill(pid)
        session.detach()
    except:
        pass
    sys.exit(0) 

except frida.NotSupportedError as e:
    printer.error(f"Unable to launch package '{args.package}", e)

# except Exception as e:
#     printer.error(f"Unknown error", e)
