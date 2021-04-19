#
# laaso/output.py
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
'''
Output management for Python code.
Defines a class TextIOWrapperFilter which is used to wrap sys.stdout and sys.stderr.
That class may be used to:
  reflect output contents to a file
  redact secrets
'''
import functools
import io
import sys
import threading

from laaso.util import (getframe,
                        getframename,
                       )

_CAPTURE_LOCK = threading.Lock()
_STDERR_WRAPPED = False
_STDOUT_WRAPPED = False

class _Capture():
    '''
    Singleton used to do the work of capturing stdout/stderr.
    '''
    _lock = threading.Lock()
    _stderr_saved = None # part of https://github.com/pytest-dev/pytest/issues/5502 workaround
    _stdout_saved = None # part of https://github.com/pytest-dev/pytest/issues/5502 workaround
    _stderr_wrapped = False
    _stdout_wrapped = False

    @classmethod
    def capture(cls):
        '''
        Apply TextIOWrapperFilter to sys.stdout and sys.stderr.
        This operation is thread-safe and idempotent.
        Do not call directly; call via global capture() (for style, not correctness).
        '''
        with cls._lock:
            if not cls._stderr_wrapped:
                cls._stderr_saved = sys.stderr
                sys.stderr = TextIOWrapperFilter(sys.stderr)
                cls._stderr_wrapped = True
            if not cls._stdout_wrapped:
                cls._stdout_saved = sys.stderr
                sys.stdout = TextIOWrapperFilter(sys.stdout)
                cls._stdout_wrapped = True

    @classmethod
    def uncapture_for_pytest(cls):
        '''
        Undo capture(). This works around pytest bug https://github.com/pytest-dev/pytest/issues/5502
        '''
        with cls._lock:
            if cls._stderr_wrapped:
                sys.stderr = cls._stderr_saved
                cls._stderr_saved = None
                cls._stderr_wrapped = False
            if cls._stdout_wrapped:
                sys.stdout = cls._stdout_saved
                cls._stdout_saved = None
                cls._stdout_wrapped = False

def capture():
    '''
    Apply TextIOWrapperFilter to sys.stdout and sys.stderr.
    This operation is thread-safe and idempotent; feel free to
    call it more than once.
    '''
    _Capture.capture()

def uncapture_for_pytest():
    '''
    Reverse capture(). Only for use with pytest. See _Capture.uncapture_for_tests().
    '''
    _Capture.uncapture_for_pytest()

@functools.total_ordering
class Redaction():
    '''
    One redacted string for TextIOWrapperFilter.
    Two items with identical keys are equal. Otherwise,
    items are sorted by value length, then by key.
    '''
    def __init__(self, key, value):
        self._key = key
        self._value = value

        if not isinstance(self._key, str):
            raise TypeError("%s(): key must be str" % type(self).__name__)
        if not isinstance(self._value, str):
            raise TypeError("%s(): value must be str" % type(self).__name__)
        if not self._key:
            raise ValueError("%s(): invalid key" % type(self).__name__)

    def __repr__(self):
        return "%s(%r, %r)" % (type(self).__name__, self._key, self._value)

    @property
    def key(self):
        '''
        Getter
        '''
        return self._key

    @property
    def value(self):
        '''
        Getter
        '''
        return self._value

    def __lt__(self, other):
        if len(self._value) > len(other.value):
            return True
        if len(self._value) < len(other.value):
            return False
        if self._value < other.value:
            return True
        if self._value > other.value:
            return False
        return self.key < other.key

    def __eq__(self, other):
        return (self._key == other.key) and (self._value == other.value)

    def __gt__(self, other):
        if len(self._value) > len(other.value):
            return False
        if len(self._value) < len(other.value):
            return True
        if self._value < other.value:
            return False
        if self._value > other.value:
            return True
        return self.key > other.key

    def __hash__(self):
        return (hash(self._key) + hash(self._value)) % 0xffffffffffffffff

class TextIOWrapperFilter(io.TextIOWrapper):
    '''
    This wraps an io.TextIOWrapper object. Calls to write and writelines
    are intercepted and filtered.
    One object wraps one stream. Filters are shared across streams.
    Redactions are stored as Redaction objects. Those are sorted
    with longer values coming first so we DTRT when one secret
    embeds another.
    cfile is the "capture file". This is either None or a file-like object.
    When cfile is set, output is mirrored there. This is leveraged by logblob.
    '''
    def __init__(self, wrapped_obj): # pylint: disable=super-init-not-called
        assert not isinstance(wrapped_obj, type(self))
        for x in self.LAASO_PRIVATE_ATTRS:
            if x not in ('write', 'writelines'):
                assert not hasattr(wrapped_obj, x)
        self._laaso_wrapped = wrapped_obj
        self.laaso_rawwrite = self._laaso_wrapped.write
        self.laaso_rawwritelines = self._laaso_wrapped.writelines
        self._laaso_cfile = None

    def __del__(self):
        with self._laaso_cfile_lock:
            if self._laaso_cfile:
                try:
                    self._laaso_cfile.flush()
                except Exception:
                    # We are sitting beneath logging and we are being destroyed.
                    # There's nowhere to go with a log message.
                    pass
        super().__del__()

    LAASO_PRIVATE_ATTRS = ('LAASO_PRIVATE_ATTRS',
                           '_laaso_cfile',
                           '_laaso_cfile_lock',
                           '_laaso_wrapped',
                           '_redact_lock',
                           '_redactions',
                           'add_redaction',
                           'cfile',
                           'cfile_write',
                           'laaso_rawwrite',
                           'laaso_rawwritelines',
                           'laaso_wrapped',
                           'redact',
                           'write',
                           'writelines',
                          )

    _redact_lock = threading.Lock()
    _redactions = list()

    # Share the lock across objects to handle the (common) case where
    # cfile is shared across objects.
    _laaso_cfile_lock = threading.Lock()

    def cfile_write(self, data):
        '''
        Best effort to write data to cfile.
        Swallows exceptions.
        '''
        with self._laaso_cfile_lock:
            if self._laaso_cfile:
                if 'b' in self._laaso_cfile.mode:
                    # cfile wants bytes
                    if isinstance(data, str):
                        data = bytes(data, encoding='utf-8')
                else:
                    # cfile wants str
                    if isinstance(data, (bytes, bytearray)):
                        data = str(data, encoding='utf-8')
                try:
                    self._laaso_cfile.write(data)
                except Exception as exc:
                    err = "%s.%s cannot write cfile; discarding cfile: %r\n" % (type(self).__name__, getframe(0), exc)
                    if 'b' in self._laaso_cfile.mode:
                        err = bytes(err, encoding='utf-8')
                    self._laaso_cfile = None
                    self.laaso_rawwrite(err)
                    self._laaso_wrapped.flush()

    @property
    def cfile(self):
        '''
        Getter
        '''
        return self._laaso_cfile

    @cfile.setter
    def cfile(self, value):
        '''
        Setter
        '''
        assert isinstance(value, (type(None), io.IOBase))
        with self._laaso_cfile_lock:
            if value is None:
                self._laaso_cfile = None
                return
            assert not self._laaso_cfile
            self._laaso_cfile = value

    @property
    def laaso_wrapped(self):
        '''
        Getter
        '''
        return self._laaso_wrapped

    @classmethod
    def add_redaction(cls, key, value):
        '''
        Adds a filter. In subsequent write operations,
        occurrences of the string value are replaced with
        REDACTED:key. Passing None for value removes the filter for key.
        '''
        assert isinstance(key, str)
        assert isinstance(value, str)
        tmp = Redaction(key, value)
        with cls._redact_lock:
            if tmp not in cls._redactions:
                cls._redactions.append(tmp)
                cls._redactions.sort()

    def __getattribute__(self, name):
        if name in super().__getattribute__('LAASO_PRIVATE_ATTRS'):
            return super().__getattribute__(name)
        return self._laaso_wrapped.__getattribute__(name)

    def __setattr__(self, name, value):
        if name in super().__getattribute__('LAASO_PRIVATE_ATTRS'):
            return super().__setattr__(name, value)
        return self._laaso_wrapped.__setattr__(name, value)

    def __delattr__(self, name):
        if name in super().__getattribute__('LAASO_PRIVATE_ATTRS'):
            return super().__delattr__(name)
        return self._laaso_wrapped.__delattr__(name)

    @classmethod
    def redact(cls, txt):
        '''
        Apply filters to txt
        '''
        for r in cls._redactions:
            txt = txt.replace(r.value, 'REDACTED:'+r.key)
        return txt

    def write(self, b):
        if not isinstance(b, str):
            raise TypeError("%s() argument must be str, not %s" % (getframename(0), type(b).__name__))
        c = self.redact(b)
        self.laaso_rawwrite(c)
        self.cfile_write(b)

    def writelines(self, lines):
        b = ''.join(lines)
        self.write(b)

def output_redact(key, value):
    '''
    Trivial wrapper to add a key/value redaction pair to all TextIOWrapperFilter objects.
    The key is a hint to anyone reading the output about what is redacted.
    For example, if you say output_redact('thing', 'abcde'), then any occurrance
    of 'abcde' in the output is replaced with 'REDACTED:thing'.
    '''
    assert isinstance(value, str)
    if value:
        TextIOWrapperFilter.add_redaction(key, value)
