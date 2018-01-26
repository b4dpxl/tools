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
"""

import argparse
import operator
import re


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
    parser.add_argument("--count", dest="count", help="Report results with more than this number of matches. Default 10", default=10, type=int)
    parser.add_argument("--output", "-o", dest="output", default="txt", help="Output format", choices=["txt", "csv"])
    parser.add_argument("--other", dest="other", help="Include 'Other' record", required=False, action="store_true")
    parser.add_argument("--themed", dest="themed", help="Group by 'theme'", required=False, action="store_true")
    parser.add_argument("--company", "-c", dest="company", help="Company words to check for, e.g. Company name or City. Note, requires --themed", required=False, action="append")
    parser.add_argument(dest="file", help="Input file, password or username:password per line")
    args = parser.parse_args()

    themes = {
        "Month": ["january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december"],
        "Season": ["summer", "winter", "spring", "autumn"],
        "Day": ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday", "today", "tomorrow", "yesterday", "weekend"],
        "Company": []
    }
    #themes_month_short = [ i[0:3] for i in themes_months ]

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
            print("Base word : Count (of %d): Percentage" % total)

        remainder = total
        remain_pct = 100

        for pwd in sorted_pwd:
            if pwd[1] >= args.count:
                remainder = remainder - pwd[1]
                pct = round((100.0 / total) * pwd[1], 1)
                remain_pct = remain_pct - pct
                if args.output == "csv":
                    # adds extra column to be used for pie chart labels
                    print("%s,%d,%s%%,%s (%s%%)" % (pwd[0], pwd[1], pct, pwd[0], pct))
                else:
                    print("%s : %d : %s%%" % ( pwd[0], pwd[1],pct ))

        if args.other:
            remain_pct = round(remain_pct, 1)
            if args.output == "csv":
                print("[Other],%d,%s%%,[Other] (%s%%)" % (remainder, remain_pct, remain_pct))
            else:
                print("[Other] : %d : %s%%" % (remainder, remain_pct))


main()
