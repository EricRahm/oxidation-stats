#!/usr/bin/env python
#
# This script fetches symbol files from Mozilla's symbol server matching a
# local Firefox install, determines unique source files mentioned in them, and
# then sums the lines in each source file by reading them from a local clone
# of the mozilla-central Mercurial repository (which the script will update to
# match the revision used to build the copy of Firefox).
#
# The output is a list of file lines by extension in descending order.

from collections import defaultdict
import requests
import sys
from urllib.parse import urljoin
import os.path
import re
from subprocess import check_call, check_output, CalledProcessError, STDOUT
from configparser import ConfigParser
import struct
from zipfile import ZipFile
from concurrent.futures import ThreadPoolExecutor
from operator import itemgetter

uuid_re = re.compile('uuid (.+)')
def get_mac_sym_url(path):
    uuid = None
    for line in check_output(['otool', '-l', path]).decode("utf-8").splitlines():
        m = uuid_re.search(line)
        if not m:
            continue
        uuid = m.group(1)
        break
    if uuid is None:
        return None
    rel = '{filename}/{id}/{filename}.sym'.format(
        filename=os.path.basename(path), id=uuid.replace('-', '') + '0')
    return rel

def get_symbol_url(path):
    file_type = check_output(['file', '-Lb', path]).decode("utf-8")
    if file_type.startswith('Mach-O'):
        return get_mac_sym_url(path)
    return None
    #elif file_type.startswith('ELF'):
    #    return get_elf_sym_url(path)
    # elif PE...

class App(object):
    def __init__(self, basedir, datadir):
        self.basedir = basedir
        self.datadir = datadir
        self.searchdirs = [self.basedir]
        if self.datadir:
            self.searchdirs.append(self.datadir)

    def open(self, path):
        for d in self.searchdirs:
            p = os.path.join(d, path)
            if os.path.exists(p):
                return open(p, 'r')
        raise Exception('File not found: %s' % path)

    def has_file(self, path):
        for d in self.searchdirs:
            f = os.path.join(d, path)
            if os.path.exists(f) and not os.path.isdir(f):
                return True
        return False

    def find_file(self, file_name):
        """Looks in the application directory for the first file named
        |file_name|, and returns its path relative to the application
        directory. This function does not look in directories ending in
        '.dSYM' or '.sym'."""
        for f in self.files():
            if os.path.basename(f) == file_name:
                return os.path.relpath(f, self.basedir)
        return None

    def files(self):
        for dirpath, dirnames, filenames in os.walk(self.basedir):
            for name in filenames:
                yield os.path.join(dirpath, name)
            for name in dirnames[:]:  # [:] so that .remove() plays nicely with for-in
                ext = os.path.splitext(name)[1]
                if ext == ".dSYM" or ext == ".sym":
                    dirnames.remove(name)

class ZippedApp(App):
    def __init__(self, file):
        self.zip = ZipFile(file, 'r')

    def open(self, path):
        return self.zip.open(path, 'r')

    def has_file(self, path):
        try:
            info = self.zip.getinfo(path) # throws if path is not found
            return True
        except:
            return False

    def files(self):
        for f in self.zip.namelist():
            yield f

def guess_app_os(app):
    if app.has_file('xul.dll'):
        f = app.open('xul.dll')
        # Derived from file(1)'s magic(5) data:
        # >>>(0x3c.l+4)   leshort         0x14c   Intel 80386
        # >>>(0x3c.l+4)   leshort         0x8664  x86-64
        f.seek(0x3c)
        offset, = struct.unpack('<L', f.read(4))
        f.seek(offset + 4)
        cputype, = struct.unpack('<H', f.read(2))
        if cputype == 0x14c:
            isa = 'x86'
        elif cputype == 0x8664:
            isa = 'x86_64'
        else:
            raise RuntimeError('Unknown CPU type in PE headers')
        return 'WINNT', isa
    elif app.has_file('libxul.so'):
        f = app.open('libxul.so')
        # Derived from file(1)'s magic(5) data:
        # >>18    leshort         3               Intel 80386,
        # >>18    leshort         40              ARM,
        # >>18    leshort         62              x86-64,
        f.read(18) # Not using seek because file objects returned by
                   # ZipFile.open don't support that
        cputype, = struct.unpack('<H', f.read(2))
        if cputype == 3:
            isa = 'x86'
        elif cputype == 40:
            isa = 'arm'
        elif cputype == 62:
            isa = 'x86_64'
        else:
            raise RuntimeError('Unknown CPU type in ELF headers')
        if app.has_file('AndroidManifest.xml'):
            return 'Android', isa
        return 'Linux', isa
    elif app.has_file('XUL'):
        return 'Darwin', 'x86'
    else:
        raise RuntimeError('Unknown app type')


def file_lines(path):
    with open(path, 'r') as f:
        for line in f:
            if line.startswith('FILE'):
                yield line.split(' ', 2)[-1].rstrip()

if len(sys.argv) < 3:
    print("usage: %s <firefox install dir> <mozilla-central repo clone>" % sys.argv[0], file=sys.stderr)
    sys.exit(1)

moz_app_dir = sys.argv[1]
repo = sys.argv[2]
moz_res_dir = None
if os.path.isdir(moz_app_dir):
    mac_app_dir = os.path.join(moz_app_dir, "Contents", "MacOS")
    if os.path.exists(mac_app_dir):
        moz_res_dir = os.path.join(moz_app_dir, "Contents", "Resources")
        moz_app_dir = mac_app_dir

if os.path.isdir(moz_app_dir):
    app = App(moz_app_dir, moz_res_dir)
else:
    app = ZippedApp(moz_app_dir)

try:
    OS, isa = guess_app_os(app)
except:
    print >>sys.stderr, '%s: Failed to determine OS of the given app.' % sys.argv[0]
    sys.exit(1)

if OS == "Darwin" and len(sys.argv) == 4:
    print >>sys.stderr, "%s: warning: Apple GDB only looks for symbols next to binaries." % sys.argv[0]
    print >>sys.stderr, "%s: warning: Most likely you do not want to specify the [path to store in] argument." % sys.argv[0]
    # allow things to proceed anyway

if not app.has_file('application.ini'):
    print >>sys.stderr, "No application.ini found in %s. Did you pass the right path to your Firefox install dir?" % moz_app_dir
    sys.exit(1)

appini = app.open('application.ini')
c = ConfigParser()
c.readfp(appini)

rev = c.get('App', 'SourceStamp')

symbol_server_url = 'https://symbols.mozilla.org/'
def download_file(url, path):
    if not os.path.exists(path):
        req = requests.get(url)
        req.raise_for_status()
        with open(path, 'wb') as f:
            for chunk in req.iter_content(chunk_size=1024):
                if chunk: # filter out keep-alive new chunks
                    f.write(chunk)

def count_lines(repo, name):
    path = os.path.join(repo, name)
    if os.path.isfile(path):
        return len(open(path, 'rb').readlines())
    return 0

print('Updating {} to rev {}'.format(repo, rev), file=sys.stderr)
with open(os.devnull, 'w') as FNULL:
    check_call(['hg', 'up', '-r', rev], cwd=repo, stdout=FNULL, stderr=STDOUT)
all_files = set()
for path in app.files():
    rel_symbol_url = get_symbol_url(path)
    if not rel_symbol_url:
        continue
    url = urljoin(symbol_server_url, rel_symbol_url)

    local_path = os.path.join('/tmp', rel_symbol_url.replace('/', '_'))
    try:
        download_file(url, local_path)
    except requests.HTTPError:
        print("Failed to download %s" % url, file=sys.stderr)
        continue
    files = list(file_lines(local_path))
    all_files.update(files)

type_lines = defaultdict(int)
with ThreadPoolExecutor(max_workers=16) as executor:
    hg_files = [f for f in all_files if f.startswith('hg:')]
    total = len(hg_files)
    def get_lines(f):
        _, _, path, _ = f.split(':', 3)
        return (os.path.splitext(path)[1], count_lines(repo, path))
    for i, (ext, lines) in enumerate(executor.map(get_lines, hg_files)):
        type_lines[ext] += lines

rust_total = 0
other_total = 0
for k, v in sorted(type_lines.items(), key=itemgetter(1), reverse=True):
    #print('%s\t%d' % (k, v))
    if k == '.rs':
        rust_total += v
    else:
        other_total += v

print('%d\t%d' % (other_total, rust_total))
