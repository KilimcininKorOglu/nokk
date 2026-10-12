#!/usr/bin/env python3
"""Load fixed pages in nokk and in Chrome on the same machine; report memory and time.

  python3 tools/bench/bench.py                        # nokk + Chrome, 3 runs each
  python3 tools/bench/bench.py --runs 5 --no-chrome
  NOKK=./target/release/nokk python3 tools/bench/bench.py --json out.json

Memory is the peak PSS of the whole process tree, sampled every 100 ms (for Chrome
only its own processes count, not the Python driver). Time is the wall clock from
start to a loaded page, process start included. The median of the runs is reported.
Chrome is Chrome 151 through Playwright (`pip install playwright`, `channel="chrome"`).
Both load each page once from a cold profile; use an idle machine.
"""
import argparse, json, os, statistics, subprocess, sys, tempfile, time

PAGES = [
    ('example.com', 'https://example.com/'),
    ('Hacker News', 'https://news.ycombinator.com/'),
    ('Wikipedia article', 'https://en.wikipedia.org/wiki/Rust_(programming_language)'),
    ('github.com', 'https://github.com/'),
    ('bbc.com/news', 'https://www.bbc.com/news'),
]

CHROME_DRIVER = r'''
import asyncio, sys, tempfile
from playwright.async_api import async_playwright
async def main():
    async with async_playwright() as p:
        b = await p.chromium.launch(channel="chrome", headless=True)
        pg = await b.new_page()
        await pg.goto(sys.argv[1], wait_until="load", timeout=90000)
        print(await pg.title())
        await b.close()
asyncio.run(main())
'''


def tree(pid):
    out, todo = [], [pid]
    while todo:
        p = todo.pop()
        out.append(p)
        try:
            for t in os.listdir(f'/proc/{p}/task'):
                with open(f'/proc/{p}/task/{t}/children') as f:
                    todo += [int(x) for x in f.read().split()]
        except OSError:
            pass
    return out


def comm(p):
    try:
        with open(f'/proc/{p}/comm') as f:
            return f.read().strip()
    except OSError:
        return ''


def pss_kb(p):
    try:
        with open(f'/proc/{p}/smaps_rollup') as f:
            for line in f:
                if line.startswith('Pss:'):
                    return int(line.split()[1])
    except OSError:
        pass
    return 0


def measure(cmd, only=None):
    """Run `cmd`; return (wall seconds, peak PSS in MB, exit code)."""
    t0 = time.time()
    pr = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    peak = 0
    while pr.poll() is None:
        total = sum(pss_kb(p) for p in tree(pr.pid) if not only or only in comm(p))
        peak = max(peak, total)
        time.sleep(0.1)
    return time.time() - t0, peak / 1024, pr.returncode


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--runs', type=int, default=3)
    ap.add_argument('--no-chrome', action='store_true')
    ap.add_argument('--json', help='also write the raw runs here')
    args = ap.parse_args()
    if not sys.platform.startswith('linux'):
        sys.exit('PSS sampling reads /proc: Linux only')
    nokk = os.environ.get('NOKK', 'target/release/nokk')
    driver = None
    if not args.no_chrome:
        driver = tempfile.NamedTemporaryFile('w', suffix='.py', delete=False)
        driver.write(CHROME_DRIVER)
        driver.close()
    with open('/proc/loadavg') as f:
        load = f.read().split()[0]
    raw, rows = {}, []
    for name, url in PAGES:
        runs = {'nokk': [], 'chrome': []}
        for _ in range(args.runs):
            # Alternate the engines so a change in machine load hits both.
            runs['nokk'].append(measure([nokk, '--log', 'error', '--load', url, '--eval', '1']))
            if driver:
                runs['chrome'].append(measure([sys.executable, driver.name, url], only='chrome'))
        raw[name] = runs
        med = lambda xs, i: statistics.median(x[i] for x in xs) if xs else None
        rows.append((name, med(runs['nokk'], 1), med(runs['chrome'], 1), med(runs['nokk'], 0), med(runs['chrome'], 0)))
        print(f'{name}: done', file=sys.stderr)
    if driver:
        os.unlink(driver.name)
    fmt_mb = lambda v: '—' if v is None else f'{v:.0f} MB'
    fmt_s = lambda v: '—' if v is None else f'{v:.1f} s'
    print(f'Median of {args.runs} runs, load average {load} at start.\n')
    print('| Page | nokk memory | Chrome memory | nokk time | Chrome time |')
    print('|---|---|---|---|---|')
    for name, nm, cm, nt, ct in rows:
        print(f'| {name} | {fmt_mb(nm)} | {fmt_mb(cm)} | {fmt_s(nt)} | {fmt_s(ct)} |')
    if args.json:
        with open(args.json, 'w') as f:
            json.dump({'load': load, 'runs': raw}, f, indent=1)


if __name__ == '__main__':
    main()
