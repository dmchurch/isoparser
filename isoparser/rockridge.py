from susp import SUSP_Entry, susp_assert

RRIP_109 = ('RRIP_1991A', 1)
RRIP_112 = ('IEEE_P1282', 1)

EXT_VERSIONS = (RRIP_109, RRIP_112)

class RR(SUSP_Entry):
    _implements = [
        RRIP_109 + ('RR', 1),
    ]

    PX = 1
    PN = 2
    SL = 4
    NM = 8
    CL = 16
    PL = 32
    RE = 64
    TF = 128

    _repr_props = ('flags',)

    def __init__(self, source, ext_id_ver, sig_version, length):
        super(RR, self).__init__(source, ext_id_ver, sig_version, length)
        susp_assert(length == 1)
        self.flags = source.unpack('B')

class PX(SUSP_Entry):
    _implements = [
        RRIP_109 + ('PX', 1),
        RRIP_112 + ('PX', 1),
    ]

    _repr_props = ('mode','nlinks','uid','gid')

    def __init__(self, source, ext_id_ver, sig_version, length):
        super(PX, self).__init__(source, ext_id_ver, sig_version, length)
        if length == 32:
            (self.mode,
             self.nlinks,
             self.uid,
             self.gid,
            ) = source.unpack_smart('IIII')
        elif length == 40:
            (self.mode,
             self.nlinks,
             self.uid,
             self.gid,
             self.ino,
            ) = source.unpack_smart('IIIII')

class PN(SUSP_Entry):
    _implements = [
        RRIP_109 + ('PN', 1),
        RRIP_112 + ('PN', 1),
    ]

    _repr_props = ('dev_high', 'dev_low')

    def __init__(self, source, ext_id_ver, sig_version, length):
        super(PN, self).__init__(source, ext_id_ver, sig_version, length)
        susp_assert(length == 16)
        self.dev_high = source.unpack_both('I')
        self.dev_low  = source.unpack_both('I')

class SL(SUSP_Entry):
    _implements = [
        RRIP_109 + ('SL', 1),
        RRIP_112 + ('SL', 1),
    ]

    CONTINUE = 1
    CURRENT  = 2
    PARENT   = 4
    ROOT     = 8

    _repr_props = ('flags', 'path')

    def __init__(self, source, ext_id_ver, sig_version, length):
        super(SL, self).__init__(source, ext_id_ver, sig_version, length)
        susp_assert(length >= 2) # Needs SL flags and at least one component
        target = source.cursor + length
        self.flags = source.unpack('B')
        self.path = ""
        while source.cursor < target:
            comp_flags   = source.unpack('B')
            comp_len     = source.unpack('B')
            comp_content = source.unpack_raw(comp_len)
            susp_assert(source.cursor <= target)
            if comp_flags == SL.CURRENT:
                susp_assert(comp_len == 0)
                self.path += "."
            elif comp_flags == SL.PARENT:
                susp_assert(comp_len == 0)
                self.path += ".."
            elif comp_flags == SL.ROOT:
                susp_assert(comp_len == 0)
            elif comp_flags in (0, SL.CONTINUE):
                susp_assert(comp_len > 0)
                self.path += comp_content
            else:
                susp_assert(False) # Unknown SL flags

            if comp_flags == SL.CONTINUE:
                # If this is a root component or an unfinished component, don't append a /
                pass
            elif comp_flags == 0 and source.cursor == target and (self.flags & SL.CONTINUE == 0):
                # If this is the last component in the link, don't append a /
                pass
            else:
                # Otherwise, append a /
                self.path += "/"

class NM(SUSP_Entry):
    _implements = [
        RRIP_109 + ('NM', 1),
        RRIP_112 + ('NM', 1),
    ]

    _repr_props = ('flags', 'name')

    CONTINUE = 1
    CURRENT  = 2
    PARENT   = 4

    def __init__(self, source, ext_id_ver, sig_version, length):
        super(NM, self).__init__(source, ext_id_ver, sig_version, length)
        susp_assert(length >= 1)
        self.flags = source.unpack('B')
        name_content = source.unpack_raw(length - 1)
        if self.flags == NM.CURRENT:
            susp_assert(length == 1)
            self.name = "."
        elif self.flags == NM.PARENT:
            susp_assert(length == 1)
            self.name = ".."
        elif self.flags in (0, NM.CONTINUE):
            susp_assert(length > 1)
            self.name = name_content

class datetime_property(object):
    def __init__(self, name):
        self.name = name

    def __get__(self, inst, owner):
        if inst is None:
            return self
        value = getattr(inst, "_"+self.name)
        if callable(value):
            value = value()
        setattr(inst, self.name, value)
        delattr(inst, "_"+self.name)
        return value

class TF(SUSP_Entry):
    _implements = [
        RRIP_109 + ('TF', 1),
        RRIP_112 + ('TF', 1),
    ]

    _repr_props = ('flags', 'creation', 'modify', 'access', 'attributes', 'backup', 'expiration', 'effective')

    CREATION   = 1
    MODIFY     = 2
    ACCESS     = 4
    ATTRIBUTES = 8
    BACKUP     = 16
    EXPIRATION = 32
    EFFECTIVE  = 64
    LONG_FORM  = 128

    creation   = datetime_property('creation')
    modify     = datetime_property('modify')
    access     = datetime_property('access')
    attributes = datetime_property('attributes')
    backup     = datetime_property('backup')
    expiration = datetime_property('expiration')
    effective  = datetime_property('effective')

    def __init__(self, source, ext_id_ver, sig_version, length):
        super(TF, self).__init__(source, ext_id_ver, sig_version, length)
        susp_assert(length >= 1)
        self.flags = source.unpack('B')
        if self.flags & TF.LONG_FORM:
            unpack_datetime = source.unpack_vd_datetime
        else:
            unpack_datetime = source.unpack_lazy_dir_datetime

        self._creation   = unpack_datetime() if self.flags & TF.CREATION else None
        self._modify     = unpack_datetime() if self.flags & TF.MODIFY else None
        self._access     = unpack_datetime() if self.flags & TF.ACCESS else None
        self._attributes = unpack_datetime() if self.flags & TF.ATTRIBUTES else None
        self._backup     = unpack_datetime() if self.flags & TF.BACKUP else None
        self._expiration = unpack_datetime() if self.flags & TF.EXPIRATION else None
        self._effective  = unpack_datetime() if self.flags & TF.EFFECTIVE else None
