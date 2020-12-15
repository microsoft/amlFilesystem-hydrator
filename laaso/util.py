#
# laaso/util.py
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
'''
Various utility functions and classes.
'''
import argparse
import collections
import copy
import datetime
import enum
import errno
import functools
import inspect
import ipaddress
import logging
import os
import pprint
import re
import shlex
import subprocess
import sys
import threading
import time
import traceback
import uuid

from laaso.base_defaults import (EXC_VALUE_DEFAULT,
                                 PF,
                                )
from laaso.exceptions import (ApplicationExit,
                              CommandFailed,
                              CommandTimeout,
                             )

def re_abs(txt):
    '''
    Given regexp text, return a string that is that
    same regexp with begin and end applied.
    '''
    return '^' + txt + '$'

# 1 UUID
RE_UUID_TXT = r'([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})'
RE_UUID_RE = re.compile(RE_UUID_TXT)
RE_UUID_ABS = re.compile(re_abs(RE_UUID_TXT))

UUID_ZERO = str(uuid.UUID(int=0))
UUID_ONE = UUID_ZERO.replace('0', '1')

class ArgExplicit(argparse.Action):
    '''
    This may be passed to an argparse argument using action=.
    It stores the values in namespace.args_explicit (set).
    '''
    def __call__(self, parser, namespace, value, option_string=None):
        setattr(namespace, self.dest, value)
        if hasattr(namespace, 'args_explicit'):
            namespace.args_explicit.add(self.dest)
        else:
            setattr(namespace, 'args_explicit', {self.dest})

def getframename(idx):
    '''
    Return a string that is the name of the caller
    '''
    f = sys._getframe(idx+1) # pylint: disable=protected-access
    return f.f_code.co_name

def getframe(idx):
    '''
    Return a string of the form caller_name:linenumber.
    idx is the number of frames up the stack, so 1 = immediate caller.
    '''
    f = sys._getframe(idx+1) # pylint: disable=protected-access
    return "%s:%s" % (f.f_code.co_name, f.f_lineno)

def getframes(idx):
    '''
    return string call stack idx levels up
    '''
    frames = ""
    for i in range(0, idx):
        f = sys._getframe(i+1) # pylint: disable=protected-access
        frames += "%s:%s:%s\n" % (f.f_code.co_filename, f.f_code.co_name, f.f_lineno)
    return frames

def _expand_item_filter(dd,
                        expand_enum,
                        item_key_filter,
                        item_value_filter,
                        include_callable,
                        ipaddress_as_string,
                        noexpand_types):
    '''
    Post-process the result of expand_item.
    Include only items that contain keys matched by callable item_key_filter.
    Example in action:
        expand_item_pformat(vmdesc.vm_create_op, item_key_filter=lambda x: x.lower().find('correlation') >= 0)
    '''
    if item_key_filter is None:
        item_key_filter = lambda x: True
    assert callable(item_key_filter)
    if item_value_filter is None:
        item_value_filter = lambda x: True
    assert callable(item_value_filter)
    r_args = (expand_enum,
              item_key_filter,
              item_value_filter,
              include_callable,
              ipaddress_as_string,
              noexpand_types)
    if isinstance(dd, (list, set, tuple)):
        as_list = [_expand_item_filter(x, *r_args) for x in dd if item_value_filter(x)]
        if isinstance(dd, list):
            return as_list
        return type(dd)(as_list)
    if not isinstance(dd, (collections.OrderedDict, collections.defaultdict, dict)):
        return dd
    ret = dict()
    for k, v in dd.items():
        if isinstance(v, dict):
            v = _expand_item_filter(v, *r_args)
            if v:
                ret[k] = v
        elif isinstance(k, str) and item_key_filter(k):
            if isinstance(v, str) and item_value_filter(v):
                ret[k] = v
    return ret

def expand_item(item,
                expand_enum=False,
                include_callable=True,
                ipaddress_as_string=False,
                item_key_filter=None,
                item_value_filter=None,
                noexpand_types=None):
    '''
    For printing, dictify an arbitrary item.
    '''
    assert isinstance(noexpand_types, (tuple, type(None)))
    noexpand_types = noexpand_types or tuple()
    r_args = (expand_enum,
              include_callable,
              ipaddress_as_string,
              noexpand_types)
    if item_key_filter or item_value_filter:
        return _expand_item_filter(_expand_item(item, 0, set(), *r_args), expand_enum, item_key_filter, item_value_filter, include_callable, ipaddress_as_string, noexpand_types)
    return _expand_item(item, 0, set(), *r_args)

def _expand_item(item,
                 depth,
                 sawids,
                 expand_enum,
                 include_callable,
                 ipaddress_as_string,
                 noexpand_types):
    '''
    Recursive portion of expand_item().
    depth: Recursion depth for this logical call.
    sawids: Set of object identities observed here or above in the stack.
            Used to avoid circularity.
    '''
    sawids = set(sawids)
    if id(item) in sawids:
        return "SEEN %r" % item
    sawids.add(id(item))
    depth += 1
    if depth >= 500:
        return item
    if item is None:
        return item
    if isinstance(item, logging.Logger):
        return repr(item)
    if isinstance(item, (ipaddress.IPv4Address, ipaddress.IPv6Address, ipaddress.IPv4Network, ipaddress.IPv6Network)):
        if ipaddress_as_string:
            return str(item)
        return repr(item)
    if isinstance(item, enum.Enum):
        if expand_enum:
            return item.value
        return item
    if isinstance(item, (bool, bytearray, bytes, complex, datetime.datetime, float, int, memoryview, range, str)):
        return item
    if any([inspect.isclass(item), inspect.isgenerator(item), inspect.ismodule(item), inspect.isroutine(item)]):
        return repr(item)
    if isinstance(item, noexpand_types):
        return item
    r_args = (depth,
              sawids,
              expand_enum,
              include_callable,
              ipaddress_as_string,
              noexpand_types)
    if isinstance(item, (frozenset, list, set, tuple)):
        if include_callable:
            tmp = [_expand_item(x, *r_args) for x in item]
        else:
            tmp = [_expand_item(x, *r_args) for x in item if not callable(x)]
        if isinstance(item, frozenset):
            try:
                return frozenset(tmp)
            except TypeError:
                # conversion made something go unhashable; just return it as a list (best we can do)
                return tmp
        if isinstance(item, set):
            try:
                return set(tmp)
            except TypeError:
                # conversion made something go unhashable; just return it as a list (best we can do)
                return tmp
        if isinstance(item, tuple):
            return tuple(tmp)
        assert isinstance(item, list)
        return tmp
    if isinstance(item, (collections.OrderedDict, collections.defaultdict)):
        ret = collections.OrderedDict()
    elif isinstance(item, dict):
        ret = dict()
    else:
        ret = dict()
        try:
            item = vars(item)
        except Exception:
            return repr(item)
    for k, v in item.items():
        if (not include_callable) and callable(v):
            continue
        ek = _expand_item(k, *r_args)
        ev = _expand_item(v, *r_args)
        try:
            ret[ek] = ev
        except TypeError:
            ret[repr(item)] = ev
    return ret

def indent_pformat(item, prefix=PF):
    '''
    Like pprint.pformat(item), but prepends prefix to each line.
    '''
    sep = '\n' + prefix
    tmp1 = item if isinstance(item, str) else pprint.pformat(item)
    tmp2 = sep.join(tmp1.splitlines())
    return prefix + tmp2

def indent_simple(item, prefix=PF):
    '''
    Returns each thing in item indented
    '''
    sep = '\n' + prefix
    if isinstance(item, (list, set, tuple)):
        return prefix + sep.join(item)
    return prefix + sep.join([str(x) for x in item])

def indent_numbered(item, prefix=PF, start=1):
    '''
    Return each thing numbered
    '''
    if isinstance(item, str):
        item = item.splitlines()
    elif not isinstance(item, (list, set, tuple)):
        item = list(item)
    maxval = len(item) + start - 1
    idxlen = len(str(maxval))
    ret = ''
    s = ''
    for lineno, line in enumerate(item, start=start):
        ret += f"{s}{prefix}{lineno:0{idxlen}d} {line}"
        s = '\n'
    return ret

def expand_item_pformat(item, prefix=PF, expand_enum=False, item_key_filter=None, item_value_filter=None, noexpand_types=None):
    '''
    Like pprint.pformat(expand_item(item)), but prepends prefix to each line.
    '''
    return indent_pformat(expand_item(item, expand_enum=expand_enum, item_key_filter=item_key_filter, item_value_filter=item_value_filter, noexpand_types=noexpand_types), prefix=prefix)

def indent_exc(prefix=PF):
    '''
    Indented human-readable exception stack.
    '''
    return indent_simple([x.rstrip() for x in traceback.format_exc().splitlines()], prefix=prefix)

def indent_stack(prefix=PF):
    '''
    Indented stack (not exception stack)
    '''
    tmp = ['Traceback (most recent call last):']
    for x in traceback.format_stack(f=sys._getframe(1)): # pylint: disable=protected-access
        tmp.extend(x.splitlines())
    return indent_simple(tmp, prefix=prefix)

def unlink(path):
    '''
    Unlink the given path. Ignore ENOENT.
    '''
    assert path
    try:
        os.unlink(path)
    except OSError as exc:
        if exc.errno != errno.ENOENT:
            raise

def logger_handler_format(handler):
    '''
    Peek at the internals of a logging.Handler and its logging.Formatter.
    Return the format string. Silently returns None if that peeking
    is incorrect.
    '''
    try:
        # My kingdom for an accessor.
        return handler.formatter._fmt # pylint: disable=protected-access
    except Exception:
        return None

def logger_effective_handlers(logger):
    '''
    Return a list of all handlers applied to the given logger.
    '''
    ret = dict()
    while logger:
        for handler in logger.handlers:
            ret[id(handler)] = handler
        if not logger.propagate:
            break
        if isinstance(logger, logging.RootLogger):
            break
        logger = logger.parent
    return list(ret.values())

def logger_pytest_capture_handlers(logger):
    '''
    Return a list of all pytest log capture handlers attached to a logger.
    This is useful to force inheriting pytest loggers,
    to adjust log formats, etc.
    '''
    try:
        import _pytest.logging # so when we create new loggers we can attach to pytest handlers # pylint: disable=import-outside-toplevel
    except ModuleNotFoundError:
        return list()
    return [x for x in logger_effective_handlers(logger) if isinstance(x, _pytest.logging.LogCaptureHandler)]

def logger_format_guess(logger):
    '''
    Guess the log format for a logger. This scans the handlers
    for an object. If they all have the same format, return it.
    Otherwise, return None. If there are no handlers, return None.
    This peeks at the internals of the logging.Formatter class.
    If that peeking is incorrect, silently return None.
    '''
    try:
        have_fmt = False
        fmt = None
        while logger:
            for handler in logger.handlers:
                if not have_fmt:
                    fmt = logger_handler_format(handler)
                    have_fmt = True
                    continue
                if logger_handler_format(handler) != fmt:
                    if isinstance(logger, logging.RootLogger):
                        break
                    return None
            if not logger.propagate:
                break
            if isinstance(logger, logging.RootLogger):
                break
            logger = logger.parent
        return fmt
    except Exception:
        return None

@functools.total_ordering
class CallResult():
    '''
    Simple representation of the result of a call.
    name: logical name of the call; arbitrary string
    return: what the call returned.
    exc: exception raised by the call.
    At least one of {return,exc} will always be None.
    '''
    def __init__(self, name, result=None, exc=None):
        self.name = name
        self.result = result
        self.exc = exc

    def __repr__(self):
        return "%s(%r, result=%r, exc=%r)" % (type(self).__name__, self.name, self.result, self.exc)

    def __hash__(self):
        return hash(self.name)

    def __lt__(self, other):
        if isinstance(other, type(self)):
            if self.name < other.name:
                return True
            if other.result and (not self.result):
                return True
            if self.result is not other.result:
                try:
                    if self.result < other.result:
                        return True
                except TypeError:
                    ts = type(self.result)
                    to = type(other.result)
                    if issubclass(ts, to) and (not issubclass(to, ts)):
                        # to is a subclass of ts
                        return True
                    if repr(self.result) < repr(other.result):
                        return True
            ts = type(self.exc)
            to = type(other.exc)
            if issubclass(ts, to) and (not issubclass(to, ts)):
                # to is a subclass of ts
                return True
            if repr(self.exc) < repr(other.exc):
                return True
            if isinstance(self, type(other)):
                # other is a subclass of self
                return False
            return True
        try:
            return not other.__lt__(self)
        except TypeError:
            raise
        except Exception as exc:
            # Nice try
            raise TypeError("'<' not supported between instances of '%s' and '%s'" % (type(self).__name__, type(other).__name__)) from exc

    def __eq__(self, other):
        if not isinstance(other, type(self)):
            return False
        if self.name != other.name:
            return False
        if self.result != other.result:
            return False
        if type(self.exc) is not type(other.exc):
            return False
        if repr(self.exc) != repr(other.exc):
            return False
        if isinstance(self, type(other)):
            return True
        return vars(self) == vars(other)

class ThreadWithCallResult(threading.Thread):
    '''
    threading.Thread that puts results/exceptions from run() in a CallResult
    '''
    def __init__(self, callresult, logger, cond, parallel, *args, target=None, **kwargs):
        super().__init__(*args, target=self.laaso_run, **kwargs)
        self._laaso_callresult = callresult
        self._laaso_logger = logger
        self._laaso_cond = cond
        self._laaso_parallel = parallel
        self._laaso_target = target

    def laaso_run(self, *args, **kwargs):
        '''
        Invoke the real run(), capturing results.
        '''
        callresult = self._laaso_callresult
        logger = self._laaso_logger
        cond = self._laaso_cond
        try:
            callresult.result = self._laaso_target(*args, **kwargs)
        except BaseException as exc:
            # Application objects should not raise SystemExit.
            # If we see that, it's an error.
            if not isinstance(exc, ApplicationExit):
                logger.error("ERROR: %r\n%s", exc, traceback.format_exc())
                logger.error("ERROR: %r", exc)
            with cond:
                callresult.exc = exc
            if not isinstance(exc, (Exception, SystemExit)):
                raise
        finally:
            self._laaso_parallel.thread_is_complete(self, callresult)

class Parallel():
    '''
    Do a bunch of things in.... parallel. Yeah.
    work is a dict of name:call pairs.
      name is a str.
      call is invoked as call() - use functools.partial if you want to pass arguments
    '''
    def __init__(self, work, max_outstanding=None, logger=None):
        self.work = work
        assert isinstance(self.work, dict)
        if not work:
            raise ValueError('work')
        self.logger = logger if logger is not None else logging.getLogger('laaso.parallel')
        self._results = list()
        self._cond = threading.Condition()
        self._launched = False
        # Here we hold a list of threads that have not yet launched.
        # When a thread completes, we discard our reference to it.
        # That is necessary to avoid a circular dependency, because
        # the thread gets a pointer up so it can tell us when it completes.
        self._threads_pending = collections.deque([ThreadWithCallResult(CallResult(name), self.logger, self._cond, self, target=call, name=name) for name, call in work.items()])
        self._threads_running = set()
        self._max_outstanding = max_outstanding
        assert (self._max_outstanding is None) or (isinstance(self._max_outstanding, int) and (self._max_outstanding > 0))
        self._cur_outstanding = 0
        self.kbd_intr = False

    def wait(self, timeout=None):
        '''
        Wait for work to complete. Returns bool - whether or not the work is complete.
        False means that the wait timed out before the threads completed.
        '''
        # Implementation note: it might seem like the return value
        # of this method could be the return of self._cond.wait().
        # The Python docs say:
        #   The return value is True unless a given timeout expired, in which case it is False.".
        #   Changed in version 3.2: Previously, the method always returned None.
        # Testing revealed that in Python 3.7, self._cond.wait() returns
        # True whether or not there is a timeout. Rather than doing anything
        # version-funky, we just ignore that return value and do an explicit
        # _done_NL() check.
        with self._cond:
            self._launch_NL()
            if timeout is not None:
                self._cond.wait(timeout=timeout)
                return self._done_NL()
            while not self._done_NL():
                self._cond.wait()
            return True

    def _can_launch_more_NL(self):
        '''
        Return whether it is okay to launch more threads.
        Caller holds lock for self._condp
        '''
        if self._max_outstanding is None:
            return True
        return len(self._threads_running) < self._max_outstanding

    def _launch_NL(self):
        '''
        Launch worker threads
        Caller holds lock for self._condp
        '''
        while self._threads_pending and self._can_launch_more_NL():
            thread = self._threads_pending.popleft()
            self._threads_running.add(thread)
            thread.start()

    def thread_is_complete(self, thread, callresult):
        '''
        The given thread has completed. This is upcalled from the thread.
        Launch more, wake waiters.
        '''
        with self._cond:
            assert thread in self._threads_running
            assert callresult not in self._results
            self._threads_running.discard(thread)
            # Do not preserve any reference to thread so there is no circular dependency.
            # Make that clear by doing the admittedly unnecessary del.
            del thread
            self._results.append(callresult)
            if isinstance(callresult.exc, KeyboardInterrupt):
                self.kbd_intr = True
            # We are eligible to launch more.
            self._launch_NL()
            # Some waiters like to get a poke even if we are not
            # done here so we can show progress.
            self._cond.notify_all()

    def done(self):
        '''
        Return whether or not all work is done
        '''
        return self._done_NL()

    def _done_NL(self):
        '''
        Return whether or not all work is done
        Caller holds lock for self._cond
        '''
        return len(self._results) >= len(self.work)

    def launch(self):
        '''
        Start the work
        '''
        with self._cond:
            self._launch_NL()

    def failed(self):
        '''
        Return a list of non-successful call results.
        '''
        with self._cond:
            # The less-than case is checking for failures during running
            assert len(self._results) <= len(self.work)
            ret = list()
            for cr in self._results:
                assert (cr.result is None) or (cr.exc is None)
                if cr.exc is not None:
                    if isinstance(cr.exc, ApplicationExit):
                        if cr.exc.code:
                            ret.append(cr)
                    else:
                        ret.append(cr)
            return ret

    def split_results(self):
        '''
        Return a list of both successful and non-successful call results.
        '''
        with self._cond:
            # The less-than case is checking for failures during running
            assert len(self._results) <= len(self.work)
            success_ret = list()
            failed_ret = list()
            for cr in self._results:
                assert (cr.result is None) or (cr.exc is None)
                if cr.exc is not None:
                    if isinstance(cr.exc, ApplicationExit):
                        if cr.exc.code:
                            failed_ret.append(cr)
                    else:
                        failed_ret.append(cr)
                else:
                    success_ret.append(cr)
            return success_ret, failed_ret

    def results(self):
        '''
        Returns a list of CallResult
        '''
        with self._cond:
            for cr in self._results:
                assert (cr.result is None) or (cr.exc is None)
            # The less-than case is checking for failures during running
            assert len(self._results) <= len(self.work)
            return list(self._results)

def elapsed(ts0, ts1=None):
    '''
    Return the amount of time elapsed since ts0.
    If ts1 is provided, this is the time elapsed from ts0 to ts1.
    If ts1 is not provided, this is the time elapsed from ts0 to now.
    '''
    if ts1 is None:
        ts1 = time.time()
    return max(ts1 - ts0, 0.0)

def cmd_env_str(env, suffix=' '):
    '''
    Return command-line string verion env or the empty string.
    '''
    if env:
        return ' '.join(["%s=%s" % (k, shlex.quote(env[k])) for k in sorted(env.keys())]) + suffix
    return ''

def cmd_str(cmd, env):
    '''
    Return a cut-and-paste-friendly dsecription of how to run a command
    '''
    return cmd_env_str(env) + ' '.join([shlex.quote(x) for x in cmd])

class LogExecute():
    '''
    Manage a run whose output is being logged.
    This implements execute_logged().
    '''
    def __init__(self, cmd, logger, log_level=logging.INFO, env=None, output=None, logfilter=None, timeout=None, chdir=None):
        '''
        Execute the given cmd (list). Route stderr to stdout, and monitor stdout.
        Use the given logger to log each line of stdout (line buffered).
        If output is not None, it is a list to which output lines are appended.
        Returns the exit status of the called process.
        '''
        if (output is not None) and (not isinstance(output, list)):
            raise TypeError("output expected None or list, not %s" % type(output).__name__)
        self.cmd = cmd
        self.logger = logger
        self.log_level = log_level
        self.env = env
        self.output = output
        self.logfilter = logfilter
        self.timeout = timeout
        self.chdir = chdir

        self.process = None
        self.timer = None
        self.timedout = False

        if (self.chdir is not None) and (not os.path.isdir(self.chdir)):
            self.logger.warning("cmd will attempt to chdir to non-existent directory %r", self.chdir)

    def _preexec_fn(self):
        '''
        This is invoked in the child process prior to the exec.
        '''
        if self.chdir is not None:
            os.chdir(self.chdir)

    def _timer_expire(self):
        '''
        Callback invoked when the timer expires.
        '''
        p = self.process # snapshot to avoid a lock
        if p is not None:
            self.logger.warning("timeout: %s", cmd_str(self.cmd, self.env))
            self.timedout = True
            p.kill()
        self.timer.cancel()

    def run(self):
        '''
        Run the command
        '''
        cmd = self.cmd
        logger = self.logger
        log_level = self.log_level
        env = self.env
        output = self.output
        logfilter = self.logfilter
        assert self.process is None
        assert self.timer is None
        do_kill = True
        try:
            self.process = subprocess.Popen(cmd, # pylint: disable=subprocess-popen-preexec-fn
                                            bufsize=1,
                                            stdin=subprocess.DEVNULL,
                                            stdout=subprocess.PIPE,
                                            stderr=subprocess.STDOUT,
                                            close_fds=True,
                                            shell=False,
                                            encoding='utf-8',
                                            preexec_fn=self._preexec_fn,
                                            env=env)
            if self.timeout is not None:
                self.timer = threading.Timer(self.timeout, self._timer_expire)
                self.timer.start()
            while True:
                if self.timedout:
                    break
                # For some reason, if there's a KeyboardInterrupt during this readline,
                # we do not get the exception.
                line = self.process.stdout.readline()
                if (not line) or self.timedout:
                    break
                line = line.rstrip('\n')
                if logfilter is not None:
                    line = logfilter(line)
                    if line is None:
                        continue
                if output is not None:
                    output.append(line)
                logger.log(log_level, line)
            do_kill = False
        except Exception as exc:
            self.logger.debug("%s command:\n%s\n%r", getframe(0), indent_exc(), exc)
            if self.process is not None:
                self.process.kill()
            raise CommandFailed(1, cmd, env) from exc
        finally:
            if do_kill and (self.process is not None):
                self.process.kill()
            if self.timer is not None:
                self.timer.cancel()
        if self.timedout:
            self.process.kill()
            raise CommandTimeout(self.cmd, self.timeout)
        pret = None
        t0 = time.time()
        count = 0
        warned = False
        while pret is None:
            count += 1
            pret = self.process.poll()
            if pret is not None:
                break
            if (count > 2) and (elapsed(t0) > 2) and (not warned):
                logger.warning("slow shutdown pid=%s %s", self.process.pid, cmd_str(cmd, env))
                warned = True
            time.sleep(0.1)
        assert pret is not None
        if self.timedout:
            raise CommandTimeout(self.cmd, self.timeout)
        return pret

def execute_logged(*args, **kwargs):
    '''
    Execute the given cmd (list). Route stderr to stdout, and monitor stdout.
    Use the given logger to log each line of stdout (line buffered).
    If output is not None, it is a list to which output lines are appended.
    Returns the exit status of the called process.
    '''
    le = LogExecute(*args, **kwargs)
    return le.run()

class OutputAccumulator():
    '''
    Stateful object to accumulate output when used with execute_logged().
    To capture output:
        thing = OutputAccumulator()
        execute_logged(..., logfilter=thing.logfilter)
    thing.output now contains the output from whatever execute_logged() ran
    '''
    def __init__(self):
        self.output = list()

    def logfilter(self, line):
        '''
        Pass this as the logfilter argument to execute_logged()
        '''
        self.output.append(line)
        return line

    def logfilter_silent(self, line):
        '''
        Pass this as the logfilter argument to execute_logged()
        '''
        self.output.append(line)

    def __contains__(self, txt):
        '''
        Return whether any line in self.output contains txt
        '''
        return any(txt in x for x in self.output)

    def contains(self, txt):
        '''
        Return whether any line in self.output contains txt
        '''
        return self.__contains__(txt)

class DirExcursion():
    '''
    Class that may be used to change directories, then
    pop back to the original directory. Operates as a context manager.
    The original directory is saved as attribute restore_to at
    construction time. The caller may modify restore_to so that
    restoration returns to a different directory. restore()
    may be invoked at any time to return to the original directory.
    It may be called repeatedly for this purpose.
    '''
    def __init__(self, *args):
        if len(args) > 1:
            raise ValueError("expected 0 or 1 argument")
        self.restore_to = os.getcwd()
        if args:
            os.chdir(args[0])

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.restore()

    def __del__(self):
        self.restore()

    def restore(self):
        '''
        Return to original directory
        '''
        os.chdir(self.restore_to)

class ArgumentParser(argparse.ArgumentParser):
    '''
    argparse.ArgumentParser with extended operations
    '''
    def get_argument_group(self, group_name, *args, **kwargs):
        '''
        Return the named argument group, creating it if necessary
        '''
        for ag in self._action_groups:
            if isinstance(ag, argparse._ArgumentGroup) and (ag.title == group_name): # pylint: disable=protected-access
                return ag
        return self.add_argument_group(group_name, *args, **kwargs)

def deep_update(orig_dict, new_dict, append_list=False):
    '''
    Recursively update nested dictionary orig_dict with contents of new_dict.
    When a list is encountered, the result is the new content appended to the old.
    Does not modify orig_dict or new_dict; returns the updated dict.
    '''
    ret = dict(orig_dict)
    for key, val in new_dict.items():
        if isinstance(val, collections.abc.Mapping):
            ret[key] = deep_update(orig_dict.get(key, type(val)()), val)
        elif isinstance(val, list) and append_list:
            ret[key] = (orig_dict.get(key, list()) + val)
        else:
            ret[key] = new_dict[key]
    return ret

class LogLevelExcursion():
    '''
    Class that may be used as a context to save and restore the log level on a logger.
    May be used as a context manager.
    '''
    def __init__(self, logger, log_level=None):
        self.logger = logger
        self.saved_log_level = logger.level
        if log_level is not None:
            self.logger.setLevel(log_level)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.restore()

    def __del__(self):
        self.restore()

    def restore(self):
        '''
        Restore to the saved log level
        '''
        self.logger.setLevel(self.saved_log_level)

def removeall(lst, value):
    '''
    Remove all occurrences of value from lst
    '''
    while True:
        try:
            lst.remove(value)
        except ValueError:
            return

def removeallof(lst, values):
    '''
    Remove all occurrences of items in values from lst
    '''
    for value in values:
        removeall(lst, value)

def truthy(value):
    '''
    Return whether value should be considered True
    '''
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return bool(value)
    if isinstance(value, str):
        if value.lower() in ('true', 'yes', 'on', '1'):
            return True
        if value.lower() in ('false', 'no', 'off', '0'):
            return False
        raise ValueError("cannot determine truthiness of %r" % value)
    raise TypeError("cannot determine truthiness of %s" % type(value))

class _TimeDeltaConverter():
    '''
    Object that provides the implementation of timedelta_from_string().
    I tried to find a package to do this, but I failed.
    Do not use this directly; call timedelta_from_string().
    '''
    def __init__(self, txt):
        if isinstance(txt, (bytearray, bytes)):
            self.txt_in = str(txt, encoding='utf-8')
        elif isinstance(txt, str):
            self.txt_in = txt
        else:
            raise TypeError("invalid txt type %s" % type(txt))
        self.txt_remain = self.txt_in.strip()
        self.td = datetime.timedelta()
        self.res = dict(self.RES)
        if not isinstance(txt, datetime.timedelta):
            while self.txt_remain:
                self._process_next()

    def __repr__(self):
        return "%s(%r)" % (type(self).__name__, self.txt_in)

    RES = {'d' : {'re' : re.compile(r'^([1-9][0-9]*)[\s]*(days|day|d)[\s]*'),
                  'dtk' : 'days',
                 },
           's' : {'re' : re.compile(r'^([1-9][0-9]*)[\s]*(seconds|second|s)[\s]*'),
                  'dtk' : 'seconds',
                 },
           'us' : {'re' : re.compile(r'^([1-9][0-9]*)[\s]*(microseconds|microsecond|us)[\s]*'),
                   'dtk' : 'microseconds',
                  },
           'ms' : {'re' : re.compile(r'^([1-9][0-9]*)[\s]*(milliseconds|millisecond|ms)[\s]*'),
                   'dtk' : 'milliseconds',
                  },
           'm' : {'re' : re.compile(r'^([1-9][0-9]*)[\s]*(minutes|minute|m)[\s]*'),
                  'dtk' : 'minutes',
                 },
           'h' : {'re' : re.compile(r'^([1-9][0-9]*)[\s]*(hours|hour|h)[\s]*'),
                  'dtk' : 'hours',
                 },
           'w' : {'re' : re.compile(r'^([1-9][0-9]*)[\s]*(weeks|week|w)[\s]*'),
                  'dtk' : 'weeks',
                 },
          }

    def _process_next(self):
        '''
        Match the next token or raise ValueError
        '''
        for rekey, reval in self.res.items():
            m = reval['re'].search(self.txt_remain)
            if m:
                kw = {reval['dtk'] : int(m.group(1))}
                self.td += datetime.timedelta(**kw)
                self.res.pop(rekey)
                self.txt_remain = self.txt_remain[len(m.group(0)):]
                return
        raise ValueError("timedelta_from_string: cannot parse %r" % self.txt_in)

def timedelta_from_string(txt):
    '''
    Given string txt, convert it to a datetime.timedelta.
    Examples:
        '3d1h' : datetime.timedelta(days=3, seconds=3600)
        '3 days 1 hour' : datetime.timedelta(days=3, seconds=3600)
        '2 week' : datetime.timedelta(days=14)
        '30m 1h 9s' : datetime.timedelta(seconds=5409)
        '8s 123ms' : datetime.timedelta(seconds=8, microseconds=123000)
    '''
    if isinstance(txt, datetime.timedelta):
        return txt
    return _TimeDeltaConverter(txt).td

class UpdateFlaggedDict(dict):
    '''
    This is dict with an extra attribute ('updated') that indicates whether or not
    the dict has been modified. dicts embedded in this dict are automatically
    converted to UpdateFlaggedDict. This means that those dicts are copied,
    not referenced, when assigned. A copy operation that would normally be shallow
    does a deep dive and copies UpdateFlaggedDicts. Both copy and deepcopy
    operations yield UpdateFlaggedDicts with updated=False.
    '''
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._copy_contents()
        self._updated = False

    @property
    def updated(self):
        '''
        Getter
        '''
        if self._updated:
            return True
        for v in self.values():
            if isinstance(v, type(self)) and v.updated:
                return True
        return False

    @updated.setter
    def updated(self, value):
        '''
        Setter
        '''
        assert isinstance(value, bool)
        for v in self.values():
            if isinstance(v, type(self)):
                v.updated = value
        self._updated = value

    def copy(self, *args, **kwargs):
        '''
        Overload the normal dict copy to force
        recursive copying of contents
        '''
        ret = super().copy(*args, **kwargs)
        if isinstance(ret, dict) and (not isinstance(ret, type(self))):
            ret = type(self)(ret)
        else:
            ret._copy_contents() # pylint: disable=protected-access
        return ret

    def _copy_contents(self):
        '''
        Walk self, replacing dict contents with type(self).
        '''
        upd = dict()
        for k, v in self.items():
            if isinstance(v, dict):
                upd[k] = type(self)(v)
        self.update(upd)

    def __copy__(self):
        return type(self)(self)

    def __delitem__(self, *args, **kwargs):
        '''
        Wraps super operation and flags an update.
        Always flags the update, even if the update is a noop
        or the operation raises an exception.
        '''
        self._updated = True
        return super().__delitem__(*args, **kwargs)

    def __deepcopy__(self, memodict):
        ret = type(self)()
        for k, v in self.items():
            ret[k] = copy.deepcopy(v, memodict)
        ret.updated = False
        return ret

    def __setitem__(self, key, value):
        '''
        Wraps super operation and flags an update.
        Always flags the update, even if the update is a noop
        or the operation raises an exception.
        '''
        self._updated = True
        if isinstance(value, dict):
            value = type(self)(value)
        return super().__setitem__(key, value)

    def clear(self, *args, **kwargs):
        '''
        Wraps super operation and flags an update.
        Always flags the update, even if the update is a noop
        or the operation raises an exception.
        '''
        self._updated = True
        return super().clear(*args, **kwargs)

    def pop(self, *args, **kwargs):
        '''
        Wraps super operation and flags an update.
        Always flags the update, even if the update is a noop
        or the operation raises an exception.
        '''
        self._updated = True
        return super().pop(*args, **kwargs)

    def popitem(self, *args, **kwargs):
        '''
        Wraps super operation and flags an update.
        Always flags the update, even if the update is a noop
        or the operation raises an exception.
        '''
        self._updated = True
        return super().popitem(*args, **kwargs)

    def setdefault(self, *args, **kwargs):
        '''
        Wraps super operation and flags an update.
        Always flags the update, even if the update is a noop
        or the operation raises an exception.
        '''
        self._updated = True
        return super().setdefault(*args, **kwargs)

    def update(self, *args, **kwargs):
        '''
        Wraps super operation and flags an update.
        Always flags the update, even if the update is a noop
        or the operation raises an exception.
        '''
        self._updated = True
        return super().update(*args, **kwargs)

def stringlist_normalize(data):
    '''
    Normalize data to a list of strings.
    data might be a string, a string that is a comma-separated list of strings,
    a list of strings, a list of comma-separated strings, etc. Flatten it out.
    '''
    # The common case is a single string with commas, so optimize for that.
    data = data or list()
    if not isinstance(data, str):
        if not data:
            return list()
        data = ','.join(data)
    return [x for x in data.split(',') if x]

def namer(*args):
    '''
    This is used to append keys to a name.
    The result is all non-empty args joined with dots.
    '''
    ret = ''
    for x in args:
        if isinstance(x, int):
            x = "[%s]" % x
            ret += x
            continue
        if not x:
            continue
        x = str(x)
        assert x
        if ret:
            if (x[0] != '[') or (x[-1] != ']'):
                ret += '.'
        ret += x
    return ret

class AttributeExcursion():
    '''
    Context manager that temporarily adds or modifies object attributes
    '''
    def __init__(self, obj, **kwargs):
        self.obj = obj
        self.saved = dict()
        self.added = set() # keys
        for attr, value in kwargs.items():
            try:
                self.saved[attr] = getattr(obj, attr)
            except AttributeError:
                self.added.add(attr)
            setattr(obj, attr, value)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.restore()

    def __del__(self):
        self.restore()

    def restore(self):
        '''
        Restore saved object state
        '''
        for attr, value in getattr(self, 'saved', dict()).items():
            setattr(self.obj, attr, value)
        for attr in getattr(self, 'added', set()):
            try:
                delattr(self.obj, attr)
            except AttributeError:
                pass

def get_firstattr(obj, *args, **kwargs):
    '''
    Search object obj for an attribute named in args and return it.
    args is searched in the order given. A default value may
    be provided via the default kwarg.
    '''
    try:
        default = kwargs.pop('default')
        has_default = True
    except KeyError:
        has_default = False
    if kwargs:
        raise TypeError("unexpected keyword arguments %s" % ','.join(sorted(kwargs.keys())))
    for arg in args:
        try:
            return getattr(obj, arg)
        except AttributeError:
            pass
    if has_default:
        return default
    if not args:
        raise AttributeError("%s: no attributes requested and no default provided" % getframename(0))
    raise AttributeError(args)

class EnvironmentExcursion():
    '''
    Context manager that temporarily adds or modifies environment variables
    '''
    def __init__(self, **kwargs):
        self.saved = dict()
        self.added = set()
        for k, v in kwargs.items():
            try:
                self.saved[k] = os.environ[k]
            except KeyError:
                self.added.add(k)
            os.environ[k] = v

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.restore()

    def __del__(self):
        self.restore()

    def restore(self):
        '''
        Restore saved object state
        '''
        for k, v in self.saved.items():
            os.environ[k] = v
        for k in self.added:
            try:
                del os.environ[k]
            except KeyError:
                pass

def uuid_normalize(val, key='uuid', exc_value=EXC_VALUE_DEFAULT) -> str:
    '''
    Return a normalized representation of a uuid.
    Normalized is a string as generated by uuid.UUID.__str__
    '''
    err = f'invalid {key}'
    if isinstance(val, str):
        try:
            return str(uuid.UUID(val.strip()))
        except Exception as exc:
            if exc_value:
                raise exc_value(f"{err}: {exc!r}") from exc
            return ''
    if isinstance(val, bytes):
        try:
            return str(uuid.UUID(bytes=val))
        except Exception as exc:
            if exc_value:
                raise exc_value(f"{err}: {exc!r}") from exc
            return ''
    if isinstance(val, uuid.UUID):
        return str(val)
    if exc_value:
        raise exc_value("%s: unexpected type %s" % (err, type(val)))
    return ''

def contains_other_uuid(txt, exclude):
    '''
    Returns whether txt contains a UUID other than those contained in exclude.
    '''
    exclude = {uuid_normalize(x) for x in exclude}
    while txt:
        m = RE_UUID_RE.search(txt)
        if not m:
            return False
        if m.group(1).lower() not in exclude:
            return True
        txt = txt[m.end():]
    return False

def contains_nonzero_uuid(txt):
    '''
    Returns whether txt contains a UUID other than all zeroes
    '''
    return contains_other_uuid(txt, exclude=[str(uuid.UUID(int=0))])

def search_regexps(regexps, txt):
    '''
    search every compiled regexp in regexps for txt.
    Return the first match.
    Return None for no match.
    Return None if txt is not a str.
    '''
    if not isinstance(txt, str):
        return None
    for regexp in regexps:
        res = regexp.search(txt)
        if res:
            return res
    return None

def reindent(txt, indent=''):
    '''
    Given txt as a multiline string, remove indentation
    so that the least indented line begins with no whitespace.
    Why do this? To simplify initializing a variable to a multi-line
    string whose contents are YAML.
    '''
    if isinstance(indent, int):
        indent = indent * ' '
    assert isinstance(txt, str)
    if not txt:
        return indent
    assert txt.find('\t') < 0 # tabs not supported
    tmp = txt.splitlines()
    least = min(len(x) - len(x.lstrip()) for x in tmp if x)
    if not least:
        return txt
    sep = '\n' + indent
    return indent + sep.join([x[least:] for x in tmp])

def has_explicit_kwarg(kls, arg):
    '''
    kls is a class
    Return whether arg is an explicit kwarg for kls.
    This is a bit guessy - we assume that if __init__ takes **,
    it passes it all along to the parent.
    '''
    for c in inspect.getmro(kls):
        ca = inspect.getfullargspec(c.__init__)
        if arg in ca.args:
            return True
        if not ca.varkw:
            return False
    return False
