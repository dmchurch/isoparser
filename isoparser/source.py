import datetime
import struct
import urllib
import cStringIO
from itertools import izip

import path_table
import record
import volume_descriptors
import susp


SECTOR_LENGTH = 2048


class SourceError(Exception):
    pass


class Source(object):
    def __init__(self, cache_content=False, min_fetch=16):
        self._buff = None
        self._len = 0
        self._sectors = {}
        self.cache_content = cache_content
        self.min_fetch = min_fetch
        self.susp_starting_index = None
        self.susp_extensions = []
        self.rockridge = False

    def __len__(self):
        return self._len - self.cursor

    @property
    def cursor(self):
        if not self._buff:
            return None
        return self._buff.tell()

    @cursor.setter
    def cursor(self, pos):
        self._buff.seek(pos)

    def rewind_raw(self, l):
        if self.cursor < l:
            raise SourceError("Rewind buffer under-run")
        self.cursor -= l

    def unpack_raw(self, l):
        data = self._buff.read(l)
        if len(data) < l:
            raise SourceError("Source buffer under-run")
        return data

    def unpack_all(self):
        return self.unpack_raw(len(self))

    def unpack_boundary(self):
        return self.unpack_raw(SECTOR_LENGTH - (self.cursor % SECTOR_LENGTH))

    def _unpack_both(self, st):
        raw = self.unpack_raw(struct.calcsize('<'+st))
        le = struct.unpack('<'+st, raw)
        be = struct.unpack('>'+st, raw)
        return le, be

    def unpack_both(self, st):
        assert len(st) == 1
        ((a, _), (_, b)) = self._unpack_both(st+st)
        if a != b:
            raise SourceError("Both-endian value mismatch")
        return a

    def unpack_string(self, l):
        return self.unpack_raw(l).rstrip(' ')

    def unpack(self, st):
        if st[0] not in '<>':
            st = '<' + st
        d = struct.unpack(st, self.unpack_raw(struct.calcsize(st)))
        if len(st) == 2:
            return d[0]
        else:
            return d

    _pack_cache = {}
    def unpack_smart(self, st):
        if st not in self._pack_cache:
            needs_both = False
            pack_list = []

            for code in st:
                if code in 'cbB':
                    pack_list.append((code, None))
                elif code == 't':
                    pack_list.append(('6Bb', 'dir_datetime'))
                elif code == 'T':
                    pack_list.append(('17s', None))
                else:
                    pack_list.append((code * 2, 'both'))
                    needs_both = True

            pack_st = ''.join(p[0] for p in pack_list)
            pack_struct = struct.Struct('<'+pack_st)
            pack_struct_be = struct.Struct('>'+pack_st) if needs_both else None

            self._pack_cache[st] = (pack_list, pack_struct, pack_struct_be)
        else:
            (pack_list, pack_struct, pack_struct_be) = self._pack_cache[st]

        raw = self.unpack_raw(pack_struct.size)
        a = pack_struct.unpack(raw)
        b = pack_struct_be.unpack(raw) if pack_struct_be else a

        value_iter = izip(a, b)
        for (pack, handler), (value, _) in izip(pack_list, value_iter):
            if handler == 'dir_datetime':
                date = [value] + [value_iter.next()[0] for i in xrange(6)]
                yield self._unpack_dir_datetime(date)
            elif handler == 'both':
                _, be_value = value_iter.next()
                if value != be_value:
                    raise SourceError("Both-endian value mismatch")
                yield value
            else:
                yield value

    def rewind(self, st):
        self.rewind_raw(struct.calcsize(st))

    # Represented by 'T' in unpack_smart
    def unpack_vd_datetime(self):
        return self.unpack_raw(17)  # TODO

    # Represented by 't' in unpack_smart
    def unpack_dir_datetime(self):
        return self.unpack_lazy_dir_datetime()()

    def unpack_lazy_dir_datetime(self):
        date = self.unpack('<6Bb')
        return lambda: self._unpack_dir_datetime(date)

    def _unpack_dir_datetime(self, t):
        t_offset = t[-1] * 15
        tz = ISO_tzinfo(t_offset)
        t_datetime = datetime.datetime(t[0]+1900, *t[1:-1], tzinfo=tz)
        return t_datetime

    def unpack_volume_descriptor(self):
        ty = self.unpack('B')
        identifier = self.unpack_string(5)
        version = self.unpack('B')

        if identifier != "CD001":
            raise SourceError("Wrong volume descriptor identifier")
        if version != 1:
            raise SourceError("Wrong volume descriptor version")
        
        if ty == 0:
            vd = volume_descriptors.BootVD(self)
        elif ty == 1:
            vd = volume_descriptors.PrimaryVD(self)
        elif ty == 2:
            vd = volume_descriptors.SupplementaryVD(self)
        elif ty == 3:
            vd = volume_descriptors.PartitionVD(self)
        elif ty == 255:
            vd = volume_descriptors.TerminatorVD(self)
        else:
            raise SourceError("Unknown volume descriptor type: %d" % ty)
        return vd

    def unpack_path_table(self):
        return path_table.PathTable(self)

    def unpack_record(self):
        start_cursor = self.cursor
        length = self.unpack('B')
        if length == 0:
            self.rewind('B')
            return None
        new_record = record.Record(self, length-1, self.susp_starting_index)
        assert self.cursor == start_cursor + length
        return new_record

    def unpack_susp(self, maxlen, possible_extension=0):
        if maxlen < 4:
            return None
        start_cursor = self.cursor
        signature, length, version = self.unpack('2sBB')
        if maxlen < length:
            self.rewind_raw(4)
            return None
        if possible_extension < len(self.susp_extensions):
            extension = self.susp_extensions[possible_extension]
            ext_id_ver = (extension.ext_id, extension.ext_ver)
        else:
            ext_id_ver = None
        try:
            new_susp = susp.SUSP_Entry.unpack(self, ext_id_ver, (signature, version), length - 4)
        except susp.SUSPError:
            self.cursor = start_cursor
            # Fall into the next if statement
        if self.cursor != start_cursor + length:
            self.cursor = start_cursor + 4
            new_susp = susp.UnknownEntry(self, ext_id_ver, (signature, version), length - 4)
        assert self.cursor == start_cursor + length
        return new_susp

    def seek(self, start_sector, length=SECTOR_LENGTH, is_content=False):
        self._buff = cStringIO.StringIO()
        do_caching = (not is_content or self.cache_content)
        n_sectors = 1 + (length - 1) // SECTOR_LENGTH
        fetch_sectors = max(self.min_fetch, n_sectors) if do_caching else n_sectors
        need_start = None

        def fetch_needed(need_count):
            data = self._fetch(need_start, need_count)
            self._buff.write(data)
            if do_caching:
                for sector_idx in xrange(need_count):
                    self._sectors[need_start + sector_idx] = data[sector_idx*SECTOR_LENGTH:(sector_idx+1)*SECTOR_LENGTH]

        for sector in xrange(start_sector, start_sector + fetch_sectors):
            if sector in self._sectors:
                if need_start is not None:
                    fetch_needed(sector - need_start)
                    need_start = None
                # If we've gotten past the sectors we actually need, don't continue to fetch
                if sector >= start_sector + n_sectors:
                    break
                self._buff.write(self._sectors[sector])
            elif need_start is None:
                need_start = sector

        if need_start is not None:
            fetch_needed(start_sector + fetch_sectors - need_start)

        self._buff.seek(length)
        self._buff.truncate()
        self._len = length
        self.cursor = 0

    def save_cursor(self):
        return (self._buff, self._len)

    def restore_cursor(self, cursor_def):
        self._buff, self._len = cursor_def

    def _fetch(self, sector, count=1):
        raise NotImplementedError

    def get_stream(self, sector, length):
        raise NotImplementedError


class FileStream(object):
    def __init__(self, file, offset, length):
        self._file = file
        self._offset = offset
        self._length = length
        self.cur_offset = 0

    def read(self, *args):
        size = args[0] if args else -1
        self._file.seek(self._offset + self.cur_offset)
        if size < 0 or size > self._length - self.cur_offset:
            size = self._length - self.cur_offset
        data = self._file.read(size)
        if data:
            self.cur_offset += len(data)
        return data

    def close(self):
        pass


class FileSource(Source):
    def __init__(self, path, **kwargs):
        super(FileSource, self).__init__(**kwargs)
        self._file = open(path, 'rb')

    def _fetch(self, sector, count=1):
        self._file.seek(sector*SECTOR_LENGTH)
        return self._file.read(SECTOR_LENGTH*count)

    def get_stream(self, sector, length):
        return FileStream(self._file, sector*SECTOR_LENGTH, length)


class HTTPSource(Source):
    def __init__(self, url, **kwargs):
        super(HTTPSource, self).__init__(**kwargs)
        self._url = url

    def _fetch(self, sector, count=1):
        return self.get_stream(sector, count*SECTOR_LENGTH).read()

    def get_stream(self, sector, length):
        opener = urllib.FancyURLopener()
        opener.http_error_206 = lambda *a, **k: None
        opener.addheader("Range", "bytes=%d-%d" % (
            SECTOR_LENGTH * sector,
            SECTOR_LENGTH * sector + length - 1))
        return opener.open(self._url)

class ISO_tzinfo(datetime.tzinfo):
    _tzcache = {}
    def __new__(cls, offset):
        if offset not in cls._tzcache:
            cls._tzcache[offset] = datetime.tzinfo.__new__(cls, offset)
        return cls._tzcache[offset]
    def __init__(self, offset):
        self.offset = offset
        self.delta = datetime.timedelta(minutes=offset)
    def utcoffset(self, dt):
        return self.delta
    def dst(self, dt):
        return datetime.timedelta(0)
    def tzname(self, dt):
        if not self.offset:
            return "UTC"
        return "%+d%02d" % (self.offset // 60, self.offset % 60)

ISO_UTC = ISO_tzinfo(0)
