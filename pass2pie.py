#! /usr/bin/env python3

"""
pass2pie.py: Attempt to the common base name (e.g. "password" in "P@55word" and "Password123") from a list of passwords.
It can also attempt to determine "themes", e.g. days of week, months, etc...

Can output this in human readable text format, or in a CSV format suitable for importing into a spreadsheet to produce pie charts, etc...

Refer to the Help for full details of the available options.

Requirements:

History:
0.1 - First revision
0.2 - Added support for Company specific themed words. Added "weekend" to Day theme.
0.3 - Changed to ".format" instead of "%s", because it's the future!
"""
__author__ = "b4dpxl"
__credits__ = ["https://github.com/ins1gn1a/"]
__license__ = "GPL"
__version__ = 0.3

import argparse
import operator
import os
import re
import sys
try:
    from __printer import Printer
except:
    print("ERROR: Please download __printer.py from https://raw.githubusercontent.com/b4dpxl/tools/master/__printer.py")
    sys.exit(1)

def main():

    parser = argparse.ArgumentParser(description="""Password common base word analyser.
    
Passwords are supplied in a text file, optionally with a username. If a username is supplied, the 
fields are separated with a colon. For example:

  username1:password1
  username2:password2

The username can be omitted, leaving just a list of passwords, or it can be blanked. For example:

  :password1
  :password2

The output formats are 'txt' (the default) which provides a more 'human readable' view. Or 'csv', which
provides a format intended for use in Excel to create pie charts or similar.
""", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('--count', dest="count", help="Report results with more than this number of matches. Default 10", default=10, type=int)
    parser.add_argument('--output', "-o", dest="output", default="txt", help="Output format", choices=["txt", "csv"])
    parser.add_argument('--other', dest="other", help="Include 'Other' record", required=False, action="store_true")
    parser.add_argument('--themed', dest="themed", help="Group by 'theme'", required=False, action="store_true")
    parser.add_argument('--company', "-c", dest="company", help="Company words to check for, e.g. Company name or City. Note, requires --themed", required=False, action="append")
    parser.add_argument(dest="file", help="Input file, password or username:password per line")
    parser.add_argument('--version', '-v', action='version', version='%(prog)s {}'.format(__version__))
    args = parser.parse_args()

    themes = {
        "Month": ["january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december"],
        "Season": ["summer", "winter", "spring", "autumn"],
        "Day": ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday", "today", "tomorrow", "yesterday", "weekend"],
        "Company": []
    }
    # themes_month_short = [ i[0:3] for i in themes_months ]

    # clean up Company words
    if args.company is not None:
        themes["Company"] = [x.lower().strip() for x in args.company]

    pattern = re.compile(r"""^(.+?)(?=[^a-zA-Z]+$)""")
    leet = {'$': 's',
            '!': 'i',
            '0': 'o',
            '@': 'a',
            '1': 'i',
            '2': 'z',
            '3': 'e',
            '4': 'a',
            '5': 's',
            '6': 'g',
            '7': 't',
            '8': 'b',
            '9': 'g'
            }

    if not os.path.isfile(args.file):
        Printer().error( "{} does not exist".format(args.file))
        sys.exit(1)

    with open(args.file, 'r') as f:
        total = 0
        passes = {}
        for pwd in [x.strip().lower() for x in f.readlines()]:

            if ":" in pwd:
                pwd = pwd.split(":")[1].strip()

            if len(pwd) > 0:
                total = total + 1
                if pattern.match(pwd):
                    pwd = pattern.match(pwd).groups()[0]

                for x,y in leet.items():
                    pwd = pwd.replace(x, y)

                if args.themed:
                    for theme in themes:
                        if pwd in themes[theme]:
                            pwd = "[%s]" % theme

                if pwd in passes:
                    passes[pwd] = passes[pwd] + 1
                else:
                    passes[pwd] = 1

        sorted_pwd = sorted(passes.items(), key=operator.itemgetter(1), reverse=True)

        if args.output == "csv":
            print("Base word,Count,Percentage,Label")
        else:
            Printer().info("Base word            Count - Percentage")

        remainder = total

        for pwd in sorted_pwd:
            if pwd[1] >= args.count:
                remainder -= pwd[1]
                if args.output == "csv":
                    # adds extra column to be used for pie chart labels
                    print("{0[0]},{0[1]},{1:.2%},{0[0]} ({1:.2%})".format(pwd, pwd[1] / total))
                else:
                    Printer().ok(("{0[0]:<20} {0[1]:5} - {1:.2%}").format(pwd, pwd[1] / total))

        if args.other:
            if args.output == "csv":
                print("{0},{1},{2:.2%},{0} ({2:.2%})".format("[Other]", remainder, remainder / total))
            else:
                Printer().ok("{:<20} {:5} - {:.2%}".format("[Other]", remainder, remainder / total))
                Printer().info( "Total passwords: {:>9}".format(total))


main()
