#!/usr/bin/env python

"""
Hard link duplicate files found in directory trees. Files on separate
devicds/partitions are not linked to each other.

Use "find . -type f -links 1" to see what's unique.
"""

from __future__ import print_function

import argparse
import sys
import os
import logging
import hashlib
import functools
import itertools
import collections
import operator
from time import time
import stat
import locale
import csv


HistoryInfo = collections.namedtuple('HistoryInfo', 'device inode mtime filehash')
FileInfo = collections.namedtuple('FileInfo', 'path mtime size device inode')

HISTORY_CSV = '.dedup.history.csv'

MIN_FILE_SIZE = 1
CHUNK_SIZE = 512 * 64

if (sys.version_info > (3, 0)):
    CHUNKING_SENTINEL = b''
else:
    CHUNKING_SENTINEL = ''


def main():
    args = parse_args()

    locale.setlocale(locale.LC_ALL, '')

    logging.basicConfig(format='[%(levelname)s] %(message)s', level=args.log_level)
    logging.debug(args)

    fileinfos = gather_files(args.dirs, args.min_file_size, args.ignore_dot_dir, args.ignore_dot_files)

    dedup(fileinfos, args.history)


def parse_args():
    argparser = argparse.ArgumentParser()
    argparser.add_argument('dirs', metavar='DIRECTORY', nargs='*', default=[os.getcwd()],
                           type=validate_path,
                           help='directories to dedup (default: ["."])')
    argparser.add_argument('--dot-files', action='store_false', dest='ignore_dot_files',
                           help='include .* files (default: False)')
    argparser.add_argument('--dot-dirs', action='store_false', dest='ignore_dot_dir',
                           help='include .* directories (default: False)')
    argparser.add_argument('-m', '--min-file-size', metavar='bytes', type=int, default=MIN_FILE_SIZE,
                           help='minimum file size that will get linked (default: %d)' % MIN_FILE_SIZE)
    argparser.add_argument('-H', '--history', metavar='CSV',
                           help='previous CSV file (default: ~/%s)' % HISTORY_CSV)
    verbosity = argparser.add_mutually_exclusive_group()
    verbosity.add_argument('-q', '--quiet', action='store_const', dest='log_level',
                           const=logging.WARNING, default=logging.INFO)
    verbosity.add_argument('-v', '--verbose', action='store_const', dest='log_level',
                           const=logging.DEBUG)

    args = argparser.parse_args()

    if args.history is None:
        args.history = os.path.join(os.path.expanduser('~'), HISTORY_CSV)

    return args


def dedup(fileinfos, history_file):
    HashGenerator.load_history(history_file)

    recovered_bytes = 0
    try:
        duplicate_groups = list(group_duplicates(fileinfos))

        logging.info('about to link %d files', len(duplicate_groups))

        for duplicate_group in duplicate_groups:
            recovered_bytes += link_duplicates(duplicate_group)
    except KeyboardInterrupt:
        logging.warning('quiting (recieved <ctrl-c>)')

    HashGenerator.save_history()
    logging.info('recovered: %s bytes', locale.format('%d', int(recovered_bytes), grouping=True))


def group_duplicates(filepaths):
    filepaths = list(filepaths)
    filepaths.sort(key=operator.attrgetter('size', 'mtime'), reverse=True)

    fileinfo_by_hash = {}
    for key, group in itertools.groupby(filepaths, key=operator.attrgetter('size', 'device')):
        group = list(group)
        if all_same(f.inode for f in group):
            # Group already linked to same data
            continue

        logging.debug('found group (%d items)', len(group))
        # Let's find possible duplicates by hashing files of the same size
        for finfo in group:
            logging.debug('\tfound file: %r', finfo.path)
            fileinfo_by_hash.setdefault(HashGenerator.create_hash(finfo, (finfo.device, finfo.inode)), []).append(finfo)

        # Now, link the duplicates
        for duplicate_group in fileinfo_by_hash.values():
            yield duplicate_group

        fileinfo_by_hash.clear()


def link_duplicates(finfo_group):
    it = iter(finfo_group)
    source = next(it)

    recovered_bytes = 0
    for link in it:
        if source.inode == link.inode:
            logging.debug('%s already linked %s; skipping', link.path, source.path)
            continue
        old_link = link.path + '.dedup.rm'
        try:
            os.rename(link.path, old_link)
            os.link(source.path, link.path)
            recovered_bytes += link.size
        except KeyboardInterrupt:
            logging.warning('cleaning up after <ctrl>-c', link.path, source.path)
            if os.path.exists(old_link):
                os.rename(old_link, link.path)
            raise
        except:
            logging.warning('could not link "%s" from "%s"', link.path, source.path)
            if os.path.exists(old_link):
                os.rename(old_link, link.path)
        else:
            os.unlink(old_link)
            print('linked', link.path, 'from', source.path)

    return recovered_bytes


def make_file_info(path, stats):
    return FileInfo(path, mtime=int(stats.st_mtime), size=stats.st_size, device=stats.st_dev, inode=stats.st_ino)


def make_history_info(device, inode, mtime, filehash, filename=None):
    return HistoryInfo(device=int(device), inode=int(inode), mtime=int(float(mtime)), filehash=filehash)


def validate_path(path):
    path = os.path.abspath(path)

    if not os.path.exists(path):
        raise argparse.ArgumentError(path)

    path_mode = os.stat(path).st_mode
    if not stat.S_ISDIR(path_mode):
        raise argparse.ArgumentError('path "%s" must be a directory' % path)
    if stat.S_ISLNK(path_mode):
        raise argparse.ArgumentError('path "%s" cannot be a symlink' % path)
    return path


def all_same(values):
    it = iter(values)
    try:
        first = next(it)
    except StopIteration:
        return True
    return all(first == x for x in it)


def gather_files(paths, min_file_size, ignore_dot_dir, ignore_dot_files):
    """Generate all files from provided path.
    """
    start = time()

    try:
        min_file_size = int(min_file_size)
    except TypeError:
        logging.warning('bad min file size %r; using 0', min_file_size)
        min_file_size = 0

    logging.info('gathering files')
    num_files = 0
    for path in paths:
        for fulldir, dirs, files in os.walk(path):
            if ignore_dot_dir and os.path.basename(fulldir).startswith('.'):
                logging.debug('skipping dot directory "%s"', fulldir)
                continue

            if os.path.islink(fulldir):
                logging.debug('skipping directory "%s" is symlink', fulldir)
                continue

            for finfo in _scan_dir(fulldir, files, min_file_size, ignore_dot_files):
                num_files += 1
                yield finfo

    logging.info('gathered %d files in %0.2fs', num_files, time() - start)


def _scan_dir(fulldir, files, min_file_size, ignore_dot_files):
    for f in files:
        if ignore_dot_files and f.startswith('.'):
            continue

        fpath = os.path.normpath(os.path.join(fulldir, f))

        try:
            stats = os.lstat(fpath)
        except OSError as err:
            logging.warning('bad file or broken symlink "%s": %s', fpath, str(err))
            continue

        if stats.st_size < min_file_size:
            logging.debug('skipping small file "%s" (<%d)', fpath, min_file_size)
            continue

        if not stat.S_ISREG(stats.st_mode):
            logging.debug('skipping non-regular file "%s"', fpath)
            continue

        yield make_file_info(path=fpath, stats=stats)


class HashGenerator(object):
    chunk_size = CHUNK_SIZE
    history_file = None

    _hash_by_ino = {}
    _dirty = False

    @classmethod
    def create_hash(cls, fileinfo, inode=None):
        fpath = fileinfo.path
        if inode is None:
            stats = os.stat(fpath)
            inode = (stats.st_dev, stats.st_ino)

        if inode in cls._hash_by_ino:
            filehash, mtime = cls._hash_by_ino[inode]
            if mtime == fileinfo.mtime:
                logging.debug('file %s already scanned', fpath)
                return filehash
            logging.debug('file %s modified; updating cache...', fpath)

        sha = hashlib.sha256()
        with open(fpath, 'rb') as f:
            read_chunk = functools.partial(f.read, cls.chunk_size)
            for chunk in iter(read_chunk, CHUNKING_SENTINEL):
                sha.update(chunk)

        hash_ = sha.hexdigest()
        cls._hash_by_ino[inode] = (hash_, fileinfo.mtime)
        cls._dirty = True
        logging.debug('file %s scanned as %r', fpath, hash_)
        return hash_

    @classmethod
    def load_history(cls, history_file):
        if cls.history_file is not None:
            logging.warning('history file already loaded')
            return

        cls.history_file = history_file
        try:
            with open(history_file, 'r') as fin:
                csvr = csv.DictReader(fin)
                for r in csvr:
                    h = make_history_info(**r)
                    cls._hash_by_ino[(h.device, h.inode)] = (h.filehash, h.mtime)
        except IOError:
            logging.warning('missing history data; hashing all files')
        else:
            logging.info('loaded history file (%d items) from %s', len(cls._hash_by_ino), history_file)

    @classmethod
    def save_history(cls):
        if not cls._dirty:
            return

        tmp_history_csv = os.path.join(os.path.dirname(cls.history_file), 'tmp.' + os.path.basename(cls.history_file))

        with open(tmp_history_csv, 'w') as fout:
            csvw = csv.DictWriter(fout, fieldnames=HistoryInfo._fields)
            csvw.writerow(dict((k, k) for k in HistoryInfo._fields))

            for (device, inode), (filehash, mtime) in cls._hash_by_ino.items():
                csvw.writerow(dict(device=device, inode=inode, mtime=mtime, filehash=filehash))

        os.rename(tmp_history_csv, cls.history_file)
        logging.info('wrote history (%d items) to %s', len(cls._hash_by_ino), cls.history_file)


if __name__ == '__main__':
    sys.exit(main())
