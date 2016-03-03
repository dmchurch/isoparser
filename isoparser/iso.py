import susp
import rockridge

class ISO(object):
    def __init__(self, source):
        self._source = source

        # Unpack volume descriptors
        self.volume_descriptors = {}
        sector = 16
        while True:
            self._source.seek(sector)
            sector += 1

            vd = self._source.unpack_volume_descriptor()
            self.volume_descriptors[vd.name] = vd

            if vd.name == "terminator":
                break

        # Unpack the path table
        self._source.seek(
            self.volume_descriptors['primary'].path_table_l_loc,
            self.volume_descriptors['primary'].path_table_size)
        self.path_table = self._source.unpack_path_table()
        self.path_cache = {}

        # Save a reference to the root record
        self.root = self.volume_descriptors['primary'].root_record

        # Check to see if SUSP is enabled
        root_record = self.root.current_directory
        if root_record.embedded_susp_entries and isinstance(root_record.embedded_susp_entries[0], susp.SP):
            self._source.susp_starting_index = root_record.embedded_susp_entries[0].len_skp
            self._source.susp_extensions = [e for e in root_record.susp_entries if isinstance(e, susp.ER)]
            if any(((er.ext_id, er.ext_ver) in rockridge.EXT_VERSIONS) for er in self._source.susp_extensions):
                self._source.rockridge = True
        else:
            self._source.susp_starting_index = False


    def record(self, *path):
        """
        Retrieves a record for the given path.
        """
        record = None
        if self._source.rockridge:
            path = list(path)
        else:
            path = [part.upper() for part in path]


        subpath = []
        # Resolve as much of the path as possible via the path table or path cache
        while path and not record:
            record = self.path_cache.get(tuple(path))
            if not record and not self._source.rockridge:
                try:
                    record = self.path_table.record(*path)
                except KeyError:
                    record = None
            if not record:
                subpath.insert(0, path.pop())

        if record is None:
            record = self.root

        # Resolve the remainder of the path by walking record children
        while subpath:
            part = subpath.pop(0)
            path.append(part)
            record = record.find_child(part) # Can raise KeyError
            if record.is_directory:
                self.path_cache[tuple(path)] = record

        return record
