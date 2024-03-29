#!/usr/bin/env python3

from io import StringIO
import urllib.request
import csv, gzip, re
import ssl

ssl._create_default_https_context = ssl._create_unverified_context

def get_rir_del():
    return StringIO(urllib.request.urlopen("https://raw.githubusercontent.com/rfc1036/whois/next/as_del_list").read().decode("utf-8", errors="ignore"))

def get_ripe_assigned():
    db = gzip.GzipFile(fileobj=urllib.request.urlopen("https://ftp.ripe.net/ripe/dbase/split/ripe.db.aut-num.gz")).read().decode("utf-8", errors="ignore")
    assigned = []
    asn_re = re.compile(r'aut-num: +AS(\d+)')
    for line in db.splitlines():
        if line.startswith("aut-num"):
            a = asn_re.findall(line)
            if (len(a) == 1): assigned.append(int(a[0]))
    assigned.sort()
    return assigned

def get_ripe_nir_as_block_rages():
    ranges = []
    asb_re = re.compile(r'as-block: +AS(\d+) +- +AS(\d+)')
    dsc_re = re.compile(r'descr: +(.+)')
    db = gzip.GzipFile(fileobj=urllib.request.urlopen("https://ftp.ripe.net/ripe/dbase/split/ripe.db.as-block.gz")).read().decode("utf-8", errors="ignore")
    pending = []
    for line in db.splitlines():
        if line.startswith("as-block"):
            pending = asb_re.findall(line)
            continue
        if line.startswith("descr"):
            a = dsc_re.findall(line)
            if (len(a) == 1 and a[0] != "ripe ASN block"):
                if (len(pending) != 1 or len(pending[0]) != 2): continue
                ranges.append((int(pending[0][0]), int(pending[0][1])))
    return ranges

def in_ranges(n, ranges):
    for (a, b) in ranges:
        if (n >= a and n <= b): return (True, b)
    return (False, 0)

def get_ripe_holes():
    asns = get_ripe_assigned()

    last_asn = 0
    ranges = []
    for asn in asns:
        if last_asn == 0:
            last_asn = asn
            continue
        if asn - last_asn > 1:
            ranges.append((last_asn + 1, asn))
        last_asn = asn
        if asn > 0xffff: break
    return ranges

def get_ripe_ranges():
    f = get_rir_del()
    rows = csv.reader(f, delimiter='\t')

    ranges = []
    for row in rows:
        try:
            if (len(row) == 0 or row[0][0] == '#'): continue
            if (row[2] == 'ripe'): ranges.append((int(row[0]), int(row[1])))
        except IndexError:
            print("failed to parse line {}".format(row))
        except ValueError:
            print("failed to parse line {}".format(row))

    f.close()
    return ranges

def filter_ripe_holes(ranges):
    hole_asns = []
    ripe_ranges = get_ripe_ranges()
    nir_blocks = get_ripe_nir_as_block_rages()
    skip_until = 0
    for (s, e) in ranges:
        for i in range(s, e):
            if i < skip_until: continue
            is_ripe, _ = in_ranges(i, ripe_ranges)
            if (is_ripe): 
                is_nir, skip_until = in_ranges(i, nir_blocks)
                if not is_nir: hole_asns.append(i)
    
    print("{} free 2-byte ASNs found:".format(len(hole_asns)))
    i = 0
    for asn in hole_asns:
        print("{:6}".format(asn), end='')
        i = i+1
        if (i % 13 == 0): print('')

filter_ripe_holes(get_ripe_holes())
