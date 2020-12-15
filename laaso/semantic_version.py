#
# laaso/semantic_version.py
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
'''
Semantic versioning and associated operations
'''
import functools
import re

from laaso.base_defaults import EXC_VALUE_DEFAULT

@functools.total_ordering
class SemanticVersion():
    '''
    Wrap a version string.
    Looks for things of the form major.minor or major.minor.patch
    form: MAJOR.MINOR or MAJOR.MINOR.PATCH
          MAJOR: int
          MINOR: int
          PATCH: int
    '''
    def __init__(self, major=None, minor=None, patch=None):
        if major is None:
            raise ValueError("must specify valid major version")
        self.major = int(major)
        self.minor = None
        self.patch = None
        if minor is not None:
            self.minor = int(minor)
            if patch is not None:
                self.patch = int(patch)
        elif patch is not None:
            raise ValueError("cannot have patch without minor")

    def __hash__(self):
        return sum([hash(x) for x in (self.major, self.minor, self.patch) if x])

    def __repr__(self):
        ret = "%s(major=%s" % (type(self).__name__, repr(self.major))
        if self.minor is not None:
            ret += ', ' + "minor=%s" % repr(self.minor)
            if self.patch is not None:
                ret += ', ' + "patch=%s" % repr(self.patch)
        ret += ")"
        return ret

    def __str__(self):
        ret = "%s" % self.major
        if self.minor is not None:
            ret += ".%s" % self.minor
        if self.patch is not None:
            ret += ".%s" % self.patch
        return ret

    def __len__(self):
        assert self.major is not None
        ret = 1
        if self.minor is not None:
            ret += 1
        if self.patch is not None:
            ret += 1
        return ret

    RE_1 = r'(?P<major1>[0-9]+)'
    RE_2 = r'(?P<major2>[0-9]+)\.(?P<minor2>[0-9]+)'
    RE_3 = r'(?P<major3>[0-9]+)\.(?P<minor3>[0-9]+)\.(?P<patch3>[0-9]+)'
    RE_TUP = (RE_3, RE_2, RE_1)
    RE_TXT = r'(' + '|'.join(RE_TUP) + r')'
    RE_TXT_ABS = '^'+ RE_TXT + '$'
    RE_RE = re.compile(RE_TXT)
    RE_RE_ABS = re.compile(RE_TXT_ABS)

    def __lt__(self, other):
        if not isinstance(other, SemanticVersion):
            # other is not SemanticVersion or a subclass of SemanticVersion
            raise TypeError("'<' not supported between instances of '%s' and '%s'" % (type(self).__name__, type(other).__name__))

        if not isinstance(self, type(other)):
            if not isinstance(other, type(self)):
                raise TypeError("'<' not supported between instances of '%s' and '%s'" % (type(self).__name__, type(other).__name__))
            # other is a subclass of this item
            return other.__ge__(self)

        return bool(self._lt(other))

    def _lt(self, other, none_nopatch=False):
        '''
        Core of the less-than operator. Returns True/False for definite,
        or None for all-compared.
        '''
        if self.major < other.major:
            return True
        if self.major > other.major:
            return False

        if self.minor is None:
            return other.minor is not None
        if other.minor is None:
            return False
        if self.minor < other.minor:
            return True
        if self.minor > other.minor:
            return False

        if self.patch is None:
            if none_nopatch and other.patch is None:
                return None
            return other.patch is not None
        if other.patch is None:
            return False
        if self.patch < other.patch:
            return True
        if self.patch > other.patch:
            return False
        return None

    def __eq__(self, other):
        if not isinstance(other, SemanticVersion):
            # other is not SemanticVersion or a subclass of SemanticVersion
            return False

        if not isinstance(self, type(other)):
            if not isinstance(other, type(self)):
                return False
            # other is a subclass of SemanticVersion
            return other.__eq__(self)

        return self._eq(other)

    def _eq(self, other):
        '''
        Core of the equal operator
        '''
        if self.major != other.major:
            return False
        if self.minor != other.minor:
            return False
        if self.patch != other.patch:
            return False
        return True

    @classmethod
    def from_match(cls, match):
        '''
        Generate from a match object for a regexp built using RE_TXT.
        '''
        d = match.groupdict()
        if d['major3'] is not None:
            return cls(major=d['major3'], minor=d['minor3'], patch=d['patch3'])
        if d['major2'] is not None:
            return cls(major=d['major2'], minor=d['minor2'])
        return cls(major=d['major1'])

    @classmethod
    def from_text(cls, txt, exc_value=EXC_VALUE_DEFAULT):
        '''
        Generate from a string
        '''
        if not isinstance(txt, str):
            raise exc_value("%s %r is not str" % (type(txt), txt))
        match = cls.RE_RE_ABS.search(txt)
        if not (match and match.group(0)):
            raise exc_value("not a semantic version")
        return cls.from_match(match)

    @classmethod
    def valid_with_patch(cls, txt):
        '''
        Return whether txt is a semantic version with a patch.
        '''
        class NotSemanticVersion(Exception):
            '''
            Used to identify invalid semantic versions.
            '''
            # no specialization here

        try:
            sv = cls.from_text(txt, exc_value=NotSemanticVersion)
        except NotSemanticVersion:
            return False

        return (sv.major is not None) and (sv.minor is not None) and (sv.patch is not None)

@functools.total_ordering
class SemanticVersionExtra(SemanticVersion):
    '''
    Wrap a version string.
    Looks for things of the form major.minor or major.minor.patch
    form: MAJOR.MINOR.PATCH-EXTRA MAJOR.MINOR.PATCH-EXTRA.STRING
          MAJOR: int
          MINOR: int
          PATCH: int
          EXTRA: int
          STRING: str
    '''
    def __init__(self, major=None, minor=None, patch=None, extra=None, string=None):
        super().__init__(major=major, minor=minor, patch=patch)
        self.extra = None
        self.string = None
        if (self.minor is None) and (extra is not None):
            raise ValueError("cannot have extra without minor")
        if extra is not None:
            self.extra = int(extra)
            if string is not None:
                self.string = str(string)
        elif string:
            raise ValueError("cannot have string without extra")

    def __hash__(self):
        return sum([hash(x) for x in (self.major, self.minor, self.patch, self.extra, self.string) if x])

    def __repr__(self):
        ret = "%s(major=%s" % (type(self).__name__, repr(self.major))
        if self.minor is not None:
            ret += ', ' + "minor=%s" % repr(self.minor)
        if self.patch is not None:
            ret += ', ' + "patch=%s" % repr(self.patch)
        if self.extra is not None:
            ret += ', ' + "extra=%s" % repr(self.extra)
        if self.string is not None:
            ret += ', ' + "string=%s" % repr(self.string)
        ret += ")"
        return ret

    def __str__(self):
        ret = "%s" % self.major
        if self.minor is not None:
            ret += ".%s" % self.minor
        if self.patch is not None:
            ret += ".%s" % self.patch
        if self.extra is not None:
            ret += "-%s" % repr(self.extra)
        if self.string is not None:
            ret += ".%s" % self.string
        return ret

    def __len__(self):
        assert self.major is not None
        ret = super().__len__()
        if self.extra is not None:
            ret += 1
        if self.string is not None:
            ret += 1
        return ret

    RE_4 = r'(?P<major4>[0-9]+)\.(?P<minor4>[0-9]+)\.(?P<patch4>[0-9]+)\-(?P<extra4>[1-9][0-9]*)'
    RE_4np = r'(?P<major4np>[0-9]+)\.(?P<minor4np>[0-9]+)\-(?P<extra4np>[1-9][0-9]*)' # pylint: disable=invalid-name
    RE_5 = r'(?P<major5>[0-9]+)\.(?P<minor5>[0-9]+)\.(?P<patch5>[0-9]+)\-(?P<extra5>[1-9][0-9]*)\.(?P<string5>[^\s]+)$'
    RE_5np = r'(?P<major5np>[0-9]+)\.(?P<minor5np>[0-9]+)\-(?P<extra5np>[1-9][0-9]*)\.(?P<string5np>[^\s]+)$' # pylint: disable=invalid-name
    RE_TUP = tuple([RE_5, RE_4, RE_5np, RE_4np] + list(SemanticVersion.RE_TUP))
    RE_TXT = r'(' + '|'.join(RE_TUP) + r')'
    RE_TXT_ABS = '^'+ RE_TXT + '$'
    RE_RE = re.compile(RE_TXT)
    RE_RE_ABS = re.compile(RE_TXT_ABS)

    def _lt(self, other, none_nopatch='ignored'):
        '''
        See SemanticVersion._lt().
        '''
        ret = super()._lt(other, none_nopatch=True)
        if ret is not None:
            return ret

        oextra = getattr(other, 'extra', None)
        if self.extra is None:
            return oextra is not None
        if oextra is None:
            return False
        if self.extra < oextra:
            return True
        if self.extra > oextra:
            return False

        ostring = getattr(other, 'string', None)
        if self.string is None:
            return ostring is not None
        if ostring is None:
            return False
        if self.string < ostring:
            return True
        if self.string > ostring:
            return False

        return None

    def _eq(self, other):
        '''
        See SemanticVersion._eq()
        '''
        if not super()._eq(other):
            return False
        if self.extra != getattr(other, 'extra', None):
            return False
        if self.string != getattr(other, 'string', None):
            return False
        return True

    @classmethod
    def from_match(cls, match):
        '''
        Generate from a match object for a regexp built using RE_TXT.
        '''
        d = match.groupdict()
        if d['major5'] is not None:
            return cls(major=d['major5'], minor=d['minor5'], patch=d['patch5'], extra=d['extra5'], string=d['string5'])
        if d['major5np'] is not None:
            return cls(major=d['major5np'], minor=d['minor5np'], extra=d['extra5np'], string=d['string5np'])
        if d['major4'] is not None:
            return cls(major=d['major4'], minor=d['minor4'], patch=d['patch4'], extra=d['extra4'])
        if d['major4np'] is not None:
            return cls(major=d['major4np'], minor=d['minor4np'], extra=d['extra4np'])
        if d['major3'] is not None:
            return cls(major=d['major3'], minor=d['minor3'], patch=d['patch3'])
        if d['major2'] is not None:
            return cls(major=d['major2'], minor=d['minor2'])
        return cls(major=d['major1'])
