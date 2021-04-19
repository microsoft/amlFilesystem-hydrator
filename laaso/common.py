#!/usr/bin/env python3
#
# laaso/common.py
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
'''
Some common Python mechanics.
'''
import argparse
import collections
import enum
import functools
import getpass
import inspect
import json
import logging
import logging.handlers
import multiprocessing
import os
import pathlib
import pprint
import pwd
import re
import shlex
import shutil
import subprocess
import sys
import syslog
import tempfile
import threading
import time
import traceback

import jinja2

import laaso
from laaso.azresourceid import (AzResourceId,
                                AzSubResourceId,
                                RE_RESOURCE_GROUP_ABS,
                                azresourceid_normalize_subscription_only,
                               )
import laaso.base_defaults
from laaso.base_defaults import EXC_VALUE_DEFAULT
from laaso.btypes import (LogTo,
                          ReadOnlyDict,
                         )
from laaso.exceptions import (AnsiblePlaybookFailed,
                              ApplicationExit,
                              ApplicationExitWithNote,
                              CommandFailed,
                              CommandTimeout,
                             )
import laaso.output
import laaso.util
from laaso.util import (ArgExplicit,
                        ArgumentParser,
                        OutputAccumulator,
                        PF,
                        Parallel,
                        cmd_str,
                        elapsed,
                        expand_item_pformat,
                        getframename,
                        indent_exc,
                        indent_simple,
                        indent_stack,
                        logger_format_guess,
                       )

PYTHON_REQUIREMENTS_CHECK_DEFAULT = laaso.util.truthy(os.environ.get('LAASO_PYTHON_REQUIREMENTS_CHECK', 'true'))

class Application():
    """
    The base class for an application.
    This might be something bound directly to the command-line,
    or it might be internal to some more complex structure.

    Child classes typically do this:
    def __init__(self, attr1=None, **kwargs):
        super().__init__(**kwargs)
        self.attr1 = attr1

    @classmethod
    def main_add_parser_args(cls, ap_parser):
        '''
        See laaso.Application.main_add_parser_args()
        '''
        super().main_add_parser_args(ap_parser)
        ap_parser.add_argument(...)
        ap_parser.add_argument(...)

    def main_execute(self):
        '''
        See laaso.Application.main_execute()
        '''
        self.stuff()
        self.more_stuff()
        raise ApplicationExit(0)
    """
    def __init__(self,
                 additional_jinja_filters=None,
                 additional_jinja_name_substitutions=None,
                 args_explicit=None,
                 debug=0,
                 exc_value=EXC_VALUE_DEFAULT,
                 ignore_unexpected=None,
                 log_level=None,
                 log_to=None,
                 logger_stream=None,
                 log_file=None,
                 log_fmt=None,
                 logger=None,
                 python_requirements_check=None,
                 username='',
                 **kwargs):
        '''
        debug: Debug level verbosity. In the common case, just using self.logger.debug()
               is sufficient. In cases where "extra" debugging is desired, that may be
               done with checks like "self.debug > 0", "self.debug > 1", etc.
               Applications may also choose to use this to enable extra functionality
               like sanity checking.
        exc_value: Raise this exception for invalid values passed to construction.
        log_level: Used to create logger if none is passed in; otherwise, ignored.
        '''
        self._cls_init()
        assert isinstance(ignore_unexpected, (type(None), dict)) and not ignore_unexpected
        self.args_explicit = args_explicit or set()
        self._args_saved = None # See args_process
        self.debug = debug
        self.exc_value = exc_value
        self._log_to = getattr(self, '_log_to', log_to)
        if self._log_to is None:
            self._log_to = self.LOG_TO_DEFAULT
        self._log_to = LogTo(self._log_to)
        self._logger_stream = getattr(self, '_logger_stream', logger_stream)
        if self._logger_stream is None:
            self._logger_stream = self._stream_for(self._log_to)
        self._log_file = log_file
        if not (hasattr(self, '_log_level') and hasattr(self, '_logger')):
            self._log_level, self._logger = self._logger_create(log_level, logger, stream=self._logger_stream,
                                                                log_file=self._log_file, log_fmt=log_fmt)
        self.username = username or username_default()
        self.logblob_consume_parser_args(kwargs)
        self.logblob_init()

        self.python_requirements_check = python_requirements_check if python_requirements_check is not None else PYTHON_REQUIREMENTS_CHECK_DEFAULT

        self._ansible_cfg_lock = threading.Lock()
        self._ansible_cfg_path = None

        self.playbook_progress = None

        self.jinja_filters = getattr(self, 'jinja_filters', dict())
        if additional_jinja_filters:
            for k, v in additional_jinja_filters.items():
                self.jinja_filters.setdefault(k, v)

        self.jinja_additional_substitutions = getattr(self, 'jinja_additional_substitutions', dict())
        if additional_jinja_name_substitutions:
            for k, v in additional_jinja_name_substitutions.items():
                self.jinja_additional_substitutions.setdefault(k, v)

        if kwargs:
            if isinstance(ignore_unexpected, dict):
                ignore_unexpected.update(kwargs)
            else:
                raise TypeError("%s: unexpected keyword arguments %s" % (type(self).__name__, ','.join(kwargs.keys())))

    # Child name for the logger of this class. This may be overloaded.
    # This is combined with parent names in logger_name_get().
    # If you want some other behavior in your class, overload logger_name_get(),
    # but do so bearing in mind the behavior of classes inheriting your logger_name_get().
    LOGGER_NAME = 'laaso'

    # Some standard log formats. Do not overload these in subclasses.
    # Instead, overload LOG_FORMAT.
    LOG_FORMAT_SIMPLE = "%(message)s"
    LOG_FORMAT_LOC = "%(asctime)s %(levelname).3s %(name)s:%(module)s:%(funcName)s:%(lineno)s: %(message)s"
    LOG_FORMAT_TS_LEVEL = "%(asctime)s %(levelname).3s %(message)s"
    LOG_FORMAT_LNAME_LEVEL = "%(name)s %(levelname).3s %(message)s"

    # Default log format for this class (overload in subclasses as necessary)
    LOG_FORMAT = LOG_FORMAT_SIMPLE

    LOG_LEVEL_DEFAULT = 'info'

    LOG_LEVEL_PYTEST = '' # pytest patches this

    LOG_LEVEL_CHOICES = ('debug', 'info', 'warning', 'error', 'critical')

    SYSLOG_IDENT = ''
    SYSLOG_FACILITY = syslog.LOG_USER
    SYSLOG_OPTIONS = syslog.LOG_PID

    @property
    def logger(self):
        '''
        Getter
        '''
        return self._logger

    @logger.setter
    def logger(self, logger):
        '''
        Setter
        '''
        if len(logger.handlers) > 1:
            assert not logger.propagate
        self._logger = logger

    @property
    def log_level(self):
        '''
        Getter
        '''
        return self._log_level

    @property
    def logger_stream(self):
        '''
        Getter
        '''
        return self._logger_stream

    @classmethod
    def logger_name_get(cls):
        '''
        Compute the logger name to use for this class.
        '''
        nc = list()
        prev = None
        for k in reversed(inspect.getmro(cls)):
            logger_name = getattr(k, 'LOGGER_NAME', '')
            if logger_name and (logger_name is not prev):
                nc.append(logger_name)
                prev = logger_name
        return '.'.join(nc)

    def _app_logger_create(self, **kwargs):
        '''
        Create the logger iff necessary
        '''
        if not (hasattr(self, '_log_level') and hasattr(self, '_logger')):
            log_level = getattr(self, '_log_level', kwargs.get('log_level', None))
            log_to = getattr(self, '_log_to', kwargs.get('log_to', None))
            logger_stream = getattr(self, '_logger_stream', kwargs.get('logger_stream', None))
            logger = getattr(self, 'logger', kwargs.get('logger', None))
            self._log_level, self._logger = self._logger_create(log_level, logger, stream=logger_stream, log_to=log_to)

    @staticmethod
    def _stream_for(logto):
        '''
        Return the stream for logto
        '''
        logto = LogTo(logto)
        if logto == LogTo.STDERR:
            return sys.stderr
        return sys.stdout

    @classmethod
    def _logger_create(cls, log_level, logger, stream=None, log_to=None, log_file=None, log_fmt=None):
        '''
        Return the logger to use in the caller context.
        This is always invoked from __init__(), so the
        case where self.logger is None is either a call
        from __init__() or an unbound call doing something funky.
        '''
        cls._cls_init()
        log_to = log_to if log_to is not None else cls.LOG_TO_DEFAULT
        log_fmt = log_fmt if log_fmt is not None else cls.LOG_FORMAT
        stream = stream if stream is not None else cls._stream_for(log_to)
        if log_file:
            pathname, _ = os.path.split(log_file)
            if not os.path.isdir(pathname):
                raise ValueError("Path %s must exist and be writeable in order to log to it." % pathname)
            if not os.access(pathname, os.W_OK):
                raise PermissionError("Path %s must be writeable in order to log to it." % pathname)
            logging.basicConfig(format=log_fmt, filename=log_file)
        else:
            logging.basicConfig(format=log_fmt, stream=stream)
        log_level = laaso.util.log_level_normalize(log_level if log_level is not None else cls.LOG_LEVEL_DEFAULT)
        if cls.LOG_LEVEL_PYTEST:
            log_level = min(laaso.util.log_level_normalize(cls.LOG_LEVEL_PYTEST), log_level)
        if logger is not None:
            return log_level, logger
        logger = logging.getLogger(name=cls.LOGGER_NAME)
        cls._logger_add_syslog_handler(logger)
        cls._logging_adjust_other_loggers() # Do this after getting our logger so we've created at least one non-root logger before this one
        logger.setLevel(log_level)
        return log_level, logger

    @classmethod
    def _logging_adjust_other_loggers(cls):
        '''
        Adjust log levels in known-noisy loggers. Azure SDKs, I'm looking at you.
        '''
        sup = (('azure.identity._internal.decorators', logging.ERROR),
              )
        for logger_name, log_level in sup:
            logger = logging.getLogger(name=logger_name)
            logger.setLevel(log_level)

    def _log_format(self):
        '''
        Return the canonical log format for this object.
        '''
        lf = logger_format_guess(self.logger)
        if lf:
            return lf
        return self.LOG_FORMAT

    def child_logger_generate(self, name, log_level=None, logger=None):
        '''
        Generate a child logger for the given logger.
        If no logger is specified, use self.logger.
        If log_level is specified, use that log_level; otherwise, use the log_level of the given logger.
        The child logger prefixes output with '[name] '.
        '''
        logger = logger if logger is not None else self.logger
        log_level = log_level if log_level is not None else logger.level
        logger_name = "%s.%s" % (logger.name, name)
        fmt = laaso.util.logger_format_guess(logger)
        if fmt is None:
            fmt = self._log_format()
        x = fmt.find('%(message)s')
        if x < 0:
            raise AssertionError("invalid log format %r" % fmt)
        # Insert the name in the format string
        fmt_prefix = fmt[:x].rstrip()
        if fmt_prefix and (not fmt_prefix.endswith(']')):
            fmt_prefix += ' '
        fmt = "%s[%s] %s" % (fmt_prefix, name, fmt[x:])
        formatter = logging.Formatter(fmt=fmt)
        handler = logging.StreamHandler(stream=sys.stdout)
        handler.setFormatter(formatter)
        new_logger = logging.getLogger(logger_name)
        new_logger.setLevel(log_level)
        new_logger.propagate = False
        new_logger.addHandler(handler)
        self._logger_add_syslog_handler(logger)
        # find any pytest handlers and duplicate them on this logger.
        # pytest does not see a non-propagating logger created during a test.
        # Future-proofing: does not add the same handler more than once,
        # in case a future version of pylint changes this behavior.
        have = {id(x) for x in new_logger.handlers}
        pytest_up_handlers = laaso.util.logger_pytest_capture_handlers(logger)
        for handler in pytest_up_handlers:
            if id(handler) not in have:
                new_logger.addHandler(handler)
                have.add(id(handler))
        return new_logger

    @classmethod
    def args_mandatory(cls):
        '''
        Return the names of the mandatory args for __init__ in order.
        '''
        arg_kinds = (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
        return [name for name, param in inspect.signature(cls.__init__).parameters.items() if (param.default == inspect.Parameter.empty) and (param.kind in arg_kinds)][1:]

    @staticmethod
    def dict_reflect_attrs(obj, d, *args, args_explicit=None, required=False):
        '''
        args are strings for attibutes of self.
        Copy those attributes into dict d.
        If required, raise AttributeError for an attribute that does not exist on self.
        If not required, ignore attributes that do not exist on self.
        Handy helper for ops like kwargs_for_self().
        required defaults to False for orchestration applications that
        call another application's kwargs_for_self on themself; by setting
        required to False, we cleanly handle the case where the target
        (child) application knows about an attribute that does not exist
        in the parent (self).
        '''
        assert isinstance(d, dict)
        for x in args:
            if isinstance(x, tuple):
                assert len(x) == 2
                assert isinstance(x[0], str)
                assert isinstance(x[1], str)
                kwarg_name, attr_name = x
            else:
                assert isinstance(x, str)
                kwarg_name = x
                attr_name = x
            try:
                d[kwarg_name] = getattr(obj, attr_name)
                if args_explicit is not None:
                    args_explicit.add(kwarg_name)
            except AttributeError:
                if required:
                    raise

    def kwargs_for_self(self, **kwargs):
        '''
        Return a new kwargs dict suitable for constructing a similar object.
        Subclasses overload _kwargs_for_self_copy and _kwargs_for_self_fixup, not this method.
        '''
        return self.kwargs_for_class(self, **kwargs)

    @classmethod
    def kwargs_for_class(cls, obj, **kwargs):
        '''
        Like kwargs_for_self, but does not bind an object.
        This allows cross-class usage for orchestration contexts
        in which an item of class B is being constructed using
        attributes from an item of class A, but neither A nor B
        are necessarily ancestors of each other.
        '''
        assert isinstance(obj, laaso.common.Application)
        ret = {'args_explicit' : set(obj.args_explicit),
               'debug' : obj.debug,
               'exc_value' : obj.exc_value,
               'log_level' : obj.log_level,
               'logger_stream' : obj.logger_stream,
               'logger' : obj.logger,
              }
        cls.dict_reflect_attrs(obj, ret,
                               'username',
                               args_explicit=ret['args_explicit'],
                              )
        cls._kwargs_for_self_copy(obj, ret)
        ret.update(kwargs)
        cls._kwargs_for_self_fixup(obj, ret)
        # All these args are explicit now. Do an assignment
        # to drop keys that were not transferred.
        ret['args_explicit'] = set(ret.keys())
        if obj.debug > 1:
            obj.logger.debug("%s kwargs_for_self returns:\n%s", type(obj).__name__, expand_item_pformat(ret))
        return ret

    @classmethod
    def _kwargs_for_self_copy(cls, obj, d):
        '''
        Called by kwargs_for_self() to transfer attributes
        from object obj to dict d. Signature is a classmethod
        so that kwargs_for_self() (our caller) may be invoked
        on an object with the wrong type to extract relevant
        attributes. That's handy in an orchestration context.
        '''
        # Copy any jinja filters or name substitutions that are
        # not already specified in the target dict d.
        # objkey is the attribute name in obj that serves as the src.
        # dkey is the correponsding kwarg name in d.
        for objkey, dkey in (('jinja_filters', 'additional_jinja_filters'),
                             ('jinja_additional_substitutions', 'additional_jinja_name_substitutions'),
                            ):
            ddict = d.setdefault(dkey, dict())
            for k, v in getattr(obj, objkey, dict()).items():
                ddict.setdefault(k, v)

    @classmethod
    def _kwargs_for_self_fixup(cls, obj, d):
        '''
        Called by kwargs_for_self() after attributes are set.
        This operation applies any additional transformations
        to the dict d.
        '''
        # Nothing to do here in the base class

    @staticmethod
    def logblob_init():
        '''
        Here in the Application base class, this does nothing.
        ApplicationLogBlobMixin defines this to do initialization
        work.
        '''
        # Nothing to do here

    @staticmethod
    def logblob_start():
        '''
        Here in the Application base class, this does nothing.
        ApplicationLogBlobMixin defines this to choose a blob name.
        '''
        # Nothing to do here

    @staticmethod
    def logblob_add_parser_args(ap_parser):
        '''
        This is invoked from laaso.common.Application.main_add_parser_args()
        to add command-line arguments for logblob.
        '''
        # Here in the base class, there is no logblob, so nothing to do.
        # The logblob mixin has its own implementation that adds arguments.

    @staticmethod
    def logblob_consume_parser_args(kwargs):
        '''
        This is invoked from Application.__init__() to consume
        kwargs. Pop all kwargs here. Note that kwargs is passed
        as a reference, not as **kwargs.
        '''
        # Here in the base class, there is no logblob, so nothing to do.

    @property
    def logblob_enable(self):
        '''
        Getter - whether or not logblob is enabled for this object.
        '''
        # Never a logblob here in the base class.
        return False

    @staticmethod
    def logblob_flush(**kwargs):
        '''
        Here in the Application base class, this does nothing.
        ApplicationLogBlobMixin defines this to flush the current
        log contents to the blob.
        '''
        # Nothing to do here

    def logblob_flush_noraise(self, log_level_success=None, **kwargs):
        '''
        Invoke self.logblob_flush(). Warn about and swallow Exceptions.
        '''
        try:
            if self.logblob_enable:
                logblob_name = getattr(self, 'logblob_name', '<unknown>')
                self.logblob_flush(**kwargs)
                if log_level_success is not None:
                    self.logger.log(log_level_success, "logged to blob %s", logblob_name)
        except Exception as exc:
            logblob_name = getattr(self, 'logblob_name', '')
            bns = ''
            if logblob_name:
                bns = " blob=%s" % logblob_name
            self.logger.warning("%s.logblob_flush failed%s (ignoring): %r\n%s", type(self).__name__, bns, exc, indent_exc())

    @classmethod
    def from_kwargs(cls, **kwargs):
        '''
        Some Application subclasses have mandatory arguments for __init__.
        Some callers only have a set of kwargs. This mediates between the two.
        Typically, subclasses do not overload this; they rely on signature inference.
        '''
        arg_names = cls.args_mandatory()
        args = cls.kwargs_extract(kwargs, arg_names)
        return cls(*args, **kwargs)

    @classmethod
    def kwargs_extract(cls, kwargs, attrs):
        '''
        Extract each value named in attrs from kwargs and return them as a list
        in the same order requested.
        This is intended as a helper for implementing from_kwargs().
        '''
        assert isinstance(kwargs, dict)
        assert isinstance(attrs, (list, tuple))
        caller_name = type(cls).__name__ + '.' + getframename(1)
        ret = list()
        for attr in attrs:
            try:
                ret.append(kwargs.pop(attr))
            except KeyError as exc:
                raise ValueError("%s: missing required argument %s" % (caller_name, attr)) from exc
        return ret

    @classmethod
    def kwargs_check(cls, kwargs):
        '''
        Raise an appropriate exception if kwargs is not empty.
        '''
        if kwargs:
            badkeys = sorted(kwargs.keys())
            fr = "%s.%s.%s" % (cls.__module__, cls.__name__, getframename(1))
            if len(badkeys) == 1:
                raise TypeError("%s() got an unexpected keyword argument '%s'" % (fr, badkeys[0]))
            raise TypeError("%s() got unexpected keyword arguments %s" % (fr, ','.join(badkeys)))

    _args_save_lock = threading.Lock()

    def args_save(self, args_saved):
        '''
        Save the given arguments (passed in dict form).
        '''
        with self._args_save_lock:
            assert self._args_saved is None
            self._args_saved = args_saved
            assert isinstance(self._args_saved, dict)

    @classmethod
    def from_args_dict(cls, args_dict):
        '''
        Return an application instance given args_dict
        '''
        return cls(**args_dict)

    @classmethod
    def main_handle_parser_args(cls, ap_args):
        '''
        ap_args is argparse.Namespace, the result of ArgumentParser.parse_args().
        Perform any transformations necessary.
        '''
        if not hasattr(ap_args, 'args_explicit'):
            setattr(ap_args, 'args_explicit', set())
        if hasattr(ap_args, 'subscription_config_path'):
            if ap_args.subscription_config_path:
                laaso.paths.subscription_config_filename_setdefault(ap_args.subscription_config_path)
            delattr(ap_args, 'subscription_config_path')

    ARGS_EXPLICIT_ONLY = set()

    @classmethod
    def main_app_setup(cls, cmd_args):
        '''
        Construct application object using the given command-line arguments (iterable of strings).
        This is not used by normal callers. It is split out from main()
        to support unit testing. The caller is responsible for exception handling, logging, etc.
        Returns (app, debug, exit_verbose, logger)
        '''
        ap_parser = ArgumentParser(allow_abbrev=False)
        cls.main_add_parser_args(ap_parser)
        ap_args = ap_parser.parse_args(args=cmd_args)
        cls.main_handle_parser_args(ap_args)

        args_dict = vars(ap_args)
        cls.handle_args_map(args_dict)
        for name in cls.ARGS_EXPLICIT_ONLY:
            if name not in ap_args.args_explicit:
                args_dict.pop(name, None)
        debug = ap_args.debug
        exit_verbose = args_dict.pop('exit_verbose', cls.EXIT_VERBOSE_ALWAYS)

        args_dict, args_saved = cls.args_process(args_dict)
        assert isinstance(args_dict, (dict,))
        assert isinstance(args_saved, (dict,))

        debug = args_dict.get('debug', debug)
        args_dict['exc_value'] = ApplicationExit

        app = cls.from_args_dict(args_dict)
        app.args_save(args_saved)
        setattr(app, '_args_saved', args_saved)
        debug = app.debug
        logger = app.logger
        if app.python_requirements_check:
            app.laaso_requirements_check()
        app.logblob_start()
        return (app, debug, exit_verbose, logger)

    @classmethod
    def _cls_init(cls):
        '''
        Perform start-of-day initialization
        '''
        laaso.output.capture()

    @classmethod
    def _logger_add_syslog_handler(cls, logger):
        '''
        Add a SysLogHandler to the given logger iff one is not already present
        '''
        if laaso.ONBOX:
            with syslog_state.syslog_lock:
                # Check to see if we already have a SysLogHandler
                for handler in logger.handlers:
                    if isinstance(handler, logging.handlers.SysLogHandler):
                        return
                handler = syslog_state.syslog_handler_generate()
                if handler:
                    logger.addHandler(handler)

    @classmethod
    def _syslog_openlog(cls):
        '''
        This is invoked first thing from cls.main().
        This does the openlog using the parameters SYSLOG_IDENT, SYSLOG_FACILITY, and SYSLOG_OPTIONS
        from the calling class.
        The default definition of SYSLOG_IDENT is the empty string.
        If the class for which main() is invoked does not overload
        SYSLOG_IDENT to something non-empty, this operation marks the
        openlog complete without doing anything.
        '''
        if laaso.ONBOX and cls.SYSLOG_IDENT:
            syslog_state.initialize(cls.SYSLOG_IDENT, cls.SYSLOG_FACILITY, cls.SYSLOG_OPTIONS)
        else:
            syslog_state.initialize('', None, None)

    @classmethod
    def main(cls, name):
        '''
        Entrypoint as from the command-line.
        '''
        if name == '__main__':
            cls._syslog_openlog()
            cls.main_with_args(sys.argv[1:])
            raise SystemExit(1)

    @classmethod
    def main_with_args(cls, cmd_args):
        '''
        Entrypoint as from the command-line.
        Define args parsing. cmd_args is typically sys.argv[1:].
        Typically, this is not overloaded. Instead, overload main_add_parser_args().
        '''
        cls._cls_init()
        c = None
        debug = 1
        exit_verbose = cls.EXIT_VERBOSE_ALWAYS or ('--exit_verbose' in cmd_args)
        logger = None

        try:
            c, debug, exit_verbose, logger = cls.main_app_setup(cmd_args)
            try:
                c.main_execute()
            finally:
                c.logblob_flush_noraise(log_level_success=logging.INFO)
            c.logger.error("%s.main_execute returned unexpectedly", type(c).__name__)
            c.logblob_flush_noraise(log_level=logging.INFO)
            raise ApplicationExit(1)
        except (ApplicationExit, SystemExit) as exc:
            if exit_verbose:
                if logger is not None:
                    if debug > 0:
                        logger.info("exit stack:\n%s", traceback.format_exc())
                    logger.info("exit code %r", exc.code)
                else:
                    assert exc.code
                    if debug > 0:
                        print("exit stack:\n%s" % traceback.format_exc())
                    print("exit code %r" % exc.code)
            elif not isinstance(exc.code, (bool, int)):
                if logger is not None:
                    logger.error("%s", exc.code)
                else:
                    log_to_stream = sys.stderr if cls.LOG_TO_DEFAULT == LogTo.STDERR.value else sys.stdout
                    print(str(exc.code), file=log_to_stream)
            if isinstance(exc, SystemExit):
                if c is not None:
                    c.logblob_flush_noraise()
                raise
            exit_code = int(bool(exc.code))
            if exit_code == 0:
                if c is not None:
                    try:
                        c.logblob_flush()
                    except Exception as exc2:
                        c.logger.warning("%s.logblob_flush failed (declaring failure): %r", type(c).__name__, exc2)
                        exit_code = 1
            else:
                if c is not None:
                    c.logblob_flush_noraise()
            raise SystemExit(exit_code) from exc
        except BaseException as exc:
            ve = expand_item_pformat(exc)
            if len(ve.splitlines()) > 500:
                if logger is not None:
                    logger.debug("truncating exc expansion because length is %d", len(ve.splitlines()))
                else:
                    print("truncating exc expansion because length is %d" % len(ve.splitlines()))
                ve = pprint.pformat(vars(exc))

            log_level = logging.WARNING
            if isinstance(exc, Exception):
                log_level = logging.ERROR

            if logger is not None:
                logger.log(log_level, "%r\n%s\n%s", exc, ve, traceback.format_exc())
            else:
                print("%r\n%s\n%s" % (exc, ve, traceback.format_exc()), flush=True)
        exit_code = 1
        if exit_verbose:
            if logger is not None:
                logger.info("exit code %r", exit_code)
                if debug > 0:
                    logger.info("exit stack:\n%s", '\n'.join(traceback.format_stack()))
            else:
                assert exit_code
                if debug > 0:
                    print("exit stack:\n%s" % '\n'.join(traceback.format_stack()), flush=True)
                print("exit code %r" % exit_code, flush=True)
        if exit_code == 0:
            if c is not None:
                try:
                    c.logblob_flush()
                except Exception as exc:
                    c.logger.warning("%s.logblob_flush failed (declaring failure): %r", type(c).__name__, exc)
                    exit_code = 1
        else:
            if c is not None:
                c.logblob_flush_noraise()
        raise SystemExit(exit_code)

    ARGS_SAVE = ()

    @classmethod
    def args_map(cls):
        '''
        Return a dict of key:val where key and val are both str.
        This is used to map command-line arguments (key) to
        keyword arguments (val) before constructing an object.
        '''
        return dict()

    @classmethod
    def handle_args_map(cls, args_dict):
        '''
        Apply args_map() to args_dict
        '''
        for k, v in cls.args_map().items():
            try:
                value = args_dict.pop(k)
            except KeyError:
                continue
            args_dict[v] = value

    @classmethod
    def args_process(cls, args_dict):
        '''
        Return a tuple of (args_dict, args_saved). Both are dicts.
        Classes may use this to extract values from ap_args
        before invoking their constructors. args_saved is
        stored as _args_saved in the new objects after they
        are constructed. This is only invoked and used in
        the command-line path. Outside that path, _args_saved
        is not updated from None. It is explicitly okay for
        this operation to perturb the contents of args_dict
        and then return it.
        This default implementation moves values from args_dict
        to args_saved according to the union of ARGS_SAVE
        through the class hierarchy.
        args_dict: result of argparse.ArgumentParser.parse_args() in dict form
        '''
        args_to_save = set()
        for kls in inspect.getmro(cls):
            try:
                args_to_save.update(getattr(kls, 'ARGS_SAVE'))
            except AttributeError:
                # Past our base class
                break
        args_saved = dict()
        for k in args_to_save:
            try:
                val = args_dict.pop(k)
                args_saved[k] = val
            except KeyError:
                pass
        return (args_dict, args_saved)

    @staticmethod
    def debug_default():
        '''
        Return default debug level.
        Intended to be called outside class context.
        Will print() errors and raise ApplicationExit on error.
        '''
        env = os.environ.get('AZURE_TOOL_DEBUG', '')
        if env:
            try:
                return int(env)
            except ValueError as exc:
                print("invalid value '%s' for AZURE_TOOL_DEBUG" % env)
                raise ApplicationExit(1) from exc
        return 0

    EXIT_VERBOSE_ALWAYS = False
    LOG_TO_DEFAULT = LogTo.STDOUT.value

    ARG_USERNAME_ADD = False
    ARG_USERNAME_HELP = argparse.SUPPRESS

    @classmethod
    def main_add_parser_args(cls, ap_parser):
        '''
        Add command-line arguments.
        Overload this to add your own arguments, and also invoke super().main_add_parser_args(ap_parser)
        '''
        group = ap_parser.get_argument_group('common')
        cls.logblob_add_parser_args(ap_parser) # Do this after adding the common group to get ordering correct.
        group.add_argument('--debug', type=int, default=cls.debug_default(),
                           action=ArgExplicit,
                           help='debug level')
        if not cls.EXIT_VERBOSE_ALWAYS:
            group.add_argument('--exit_verbose', action="store_true",
                               help='print/log exit status')
        group.add_argument('--log_level', type=str, default=cls.LOG_LEVEL_DEFAULT, choices=cls.LOG_LEVEL_CHOICES,
                           action=ArgExplicit,
                           help='log level')
        group.add_argument('--log_to', type=str, default=cls.LOG_TO_DEFAULT, choices=LogTo.values(),
                           action=ArgExplicit,
                           help='default log destination')
        group.add_argument('--log_file', type=str, default=None,
                           action=ArgExplicit,
                           help='log to the named file instead of stdout or stderr (overrides log_to)')
        group.add_argument('--python_requirements_check', type=int, default=None,
                           action=ArgExplicit,
                           help=argparse.SUPPRESS)
        group.add_argument('--subscription_config_path', type=str, default=None,
                           action=ArgExplicit,
                           help=argparse.SUPPRESS)
        if cls.ARG_USERNAME_ADD:
            group.add_argument('--username', type=str, default=username_default(),
                               action=ArgExplicit,
                               help=cls.ARG_USERNAME_HELP)

    def manager_kwargs(self, **kwargs):
        '''
        Return a kwargs dict suitable for passing to azure_tool.Manager()
        '''
        ret = {'debug' : self.debug,
               'log_level' : self._log_level,
               'logger' : self._logger,
               'username' : self.username,
              }
        ret.update(kwargs)
        return ret

    @classmethod
    def default_kwargs(cls):
        '''
        Return default kwargs for this class
        '''
        ret = dict()
        for kls in reversed(inspect.getmro(cls)):
            sig = inspect.signature(kls.__init__)
            ret.update({name : p.default for name, p in sig.parameters.items() if p.default is not inspect.Signature.empty})
        return ret

    @property
    def subscription_id_default(self):
        '''
        Getter for default subscription ID.
        Here in the base class, that's just the global default.
        '''
        return laaso.subscription_ids.subscription_default

    def subscription_info_get(self, subscription_id=None):
        '''
        Return the subscription descriptor for the given subscription_id.
        Returns an empty dict if the id is not found.
        Use laaso.subscription_info_get() to get a KeyError for not-found.
        '''
        # Do not consider self.subscription_id_default here.
        # In subclasses like ApplicationWithSubscription,
        # a caller may have explicitly set subscription_id to ''
        # to prevent anything from getting an implicit default.
        subscription_id = subscription_id or self.subscription_id_default
        try:
            return laaso.subscription_info_get(subscription_id)
        except KeyError:
            ret = {'location_defaults' : ReadOnlyDict()}
            ret['location_defaults'].default_value = ''
            return ReadOnlyDict(ret)

    @property
    def resource_group_default(self):
        '''
        Getter for name of default resource group.
        '''
        try:
            return self.resource_group or None
        except AttributeError:
            return None

    @staticmethod
    def main_execute():
        '''
        main_execute() does the work of an Application.
        Child classes typically overload this.
        '''
        # Nothing happens here in the base class
        raise ApplicationExit(0)

    @staticmethod
    def pw_get(username):
        '''
        Wrapper around pwd.getpwnam() that returns None rather
        than raising if the user does not exist.
        '''
        try:
            return pwd.getpwnam(username)
        except KeyError as exc:
            tmp = str(exc)
            if (tmp.find('name not found') >= 0) and (tmp.find(username) >= 0):
                return None
            raise

    @classmethod
    def pubkey_filename_default(cls, username=None, use_env=True, pw=None):
        '''
        Return default public key filename
        pw: result of pwd.getpwnam(username)
        '''
        if username:
            if pw:
                assert username == pw.pw_name
            else:
                pw = cls.pw_get(username)
        if not pw:
            if use_env:
                return os.path.join(os.environ.get('HOME', '/'), '.ssh', 'id_rsa.pub')
            return None
        return os.path.join(pw.pw_dir, '.ssh', 'id_rsa.pub')

    RESOURCE_GROUP_DEFAULT_INCLUDE_ENV = True

    @classmethod
    def arg_resource_group__default(cls):
        '''
        Return default resource_group for command-line.
        The quirky name is to avoid a substring match with 'resource_group_default'.
        '''
        if cls.RESOURCE_GROUP_DEFAULT_INCLUDE_ENV:
            return os.environ.get('LAASO_RESOURCE_GROUP', '')
        return ''

    def parallel(self, work, **kwargs):
        '''
        work is a dict of name:call pairs.
          name is a str.
          call is invoked as call() - use functools.partial if you want to pass arguments
        '''
        kwargs.setdefault('logger', self.logger)
        return Parallel(work, **kwargs)

    def cmd_simple(self, command, **kwargs):
        '''
        Execute a command using laaso.util.execute_logged().
        Raise CommandFailed on failure.
        Raise CommandTimeout on timeout.
        '''
        if isinstance(command, str):
            command = shlex.split(command)
        env = kwargs.pop('env', None)
        exit_status = laaso.util.execute_logged(command, self.logger, env=env, **kwargs)
        if exit_status:
            raise CommandFailed(exit_status, command, env)

    @staticmethod
    def ansible_cfg_path_validate(path, on_laaso_vm=False):
        '''
        Determine if path is a valid ansible.cfg.
        Checks that the path exists and is a file, and checks
        for certain known subdirs and filenames. This is not
        an exhaustive check for all files; having that would
        require knowing the manifest here. Instead, this catches
        common cases.
        '''
        if not isinstance(path, str):
            return False
        if not os.path.isfile(path):
            return False
        parent = os.path.split(os.path.abspath(path))[0]
        if on_laaso_vm:
            for f in ('common_init.tasks.yaml', 'infrastructure/fs_initialize.playbook.yaml'):
                if not os.path.isfile(os.path.join(parent, f)):
                    return False
        else:
            for d in ('files', 'infrastructure', 'plugins', 'vars'):
                if not os.path.isdir(os.path.join(parent, d)):
                    return False
            for f in ('common_init.tasks.yaml', 'laaso-id.tasks.yaml', 'ping.playbook.yaml'):
                if not os.path.isfile(os.path.join(parent, f)):
                    return False
        return True

    _ANSIBLE_CFG_ON_LAASO_VM = '/usr/laaso/ansible/ansible.cfg'

    @classmethod
    def ansible_cfg_search(cls):
        '''
        Search for ansible.cfg.
        '''
        cfg = os.environ.get('LAASO_ANSIBLE_CFG', '')
        if cfg:
            if cls.ansible_cfg_path_validate(cfg):
                return cfg
            # Cannot use user-specified directory. Do not search for others.
            return None
        if laaso.ONBOX:
            return cls._ANSIBLE_CFG_ON_LAASO_VM if os.path.isfile(cls._ANSIBLE_CFG_ON_LAASO_VM) else None
        # Common case: relative to the repo root. This happens when we
        # are sitting somewhere inside the repo.
        repo_root = laaso.paths.repo_root
        if repo_root:
            tmp = os.path.join(repo_root, 'src', 'ansible', 'ansible.cfg')
            if cls.ansible_cfg_path_validate(tmp):
                pf = '.' + os.path.sep
                if tmp.startswith(pf) and (len(tmp) > len(pf)):
                    return tmp[len(pf):]
                return tmp
        in_venv = bool(os.environ.get('VIRTUAL_ENV', ''))
        cfg_on_laaso_vm = cls._ANSIBLE_CFG_ON_LAASO_VM # snapshot to avoid improbable race
        if (not in_venv) and cls.ansible_cfg_path_validate(cfg_on_laaso_vm, on_laaso_vm=True):
            return cfg_on_laaso_vm
        return None

    @property
    def ansible_cfg_parent(self):
        '''
        Getter for the parent directory of ansible.cfg
        '''
        return os.path.split(self.ansible_cfg)[0]

    def ansible_path(self, path):
        '''
        Return path adjusted relative to the location of ansible.cfg
        '''
        if path.startswith(os.path.sep):
            return path
        return os.path.join(self.ansible_cfg_parent, path)

    @property
    def ansible_cfg(self):
        '''
        Getter for the path to ansible.cfg.
        Returns None if ansible.cfg cannot be found.
        '''
        with self._ansible_cfg_lock:
            if self._ansible_cfg_path is None:
                self._ansible_cfg_path = self.ansible_cfg_search()
            return self._ansible_cfg_path

    @ansible_cfg.setter
    def ansible_cfg(self, value):
        '''
        Setter for self.ansible_cfg. Supports only strings, not path-like objects.
        '''
        with self._ansible_cfg_lock:
            if not self.ansible_cfg_path_validate(value):
                self.logger.error("cannot set ansible_cfg to invalid path %r\n%s", value, indent_stack())
                raise ApplicationExit(1)
            self._ansible_cfg_path = value

    def ansible_cfg_check(self):
        '''
        Simple verification that the ansible.cfg file can be found
        and passes verification. Logs an error and raises ApplicationExit if not.
        '''
        if not self.ansible_cfg:
            raise ApplicationExit("cannot locate ansible.cfg")

    _ANSIBLE_ENV_INHERIT = ('CLINT_DISABLE_COLOR',
                            'HOME',
                            'LANG',
                            'LS_COLORS',
                            'PATH',
                            'PIP_NO_COLOR',
                            'PYTHONPATH',
                            'SSH_AUTH_SOCK',
                            'USER',
                            'VIRTUAL_ENV',
                           )

    @classmethod
    def ansible_env_inherit(cls, ansible_env, **kwargs):
        '''
        Return a copy of ansible_env with additional defaults (_ANSIBLE_ENV_INHERIT)
        inherited from the environment. If a key from _ANSIBLE_ENV_INHERIT is
        already set in ansible_env, it is left alone.
        '''
        ret = dict(ansible_env)
        for k in cls._ANSIBLE_ENV_INHERIT:
            if k not in ret:
                try:
                    ret[k] = os.environ[k]
                except KeyError:
                    continue
        ret.update(kwargs)
        return ret

    def ansible_env(self, **kwargs):
        '''
        Return a dict of environment variables for running
        ansible. If inherit is set, this also allows
        specific environment variables (_ANSIBLE_ENV_INHERIT)
        to be inherited from the external environment.
        '''
        if kwargs.pop('check', True):
            self.ansible_cfg_check()
        ret = {'ANSIBLE_CONFIG' : self.ansible_cfg}
        if laaso.paths.venv_ansible_collections and os.path.isdir(laaso.paths.venv_ansible_collections):
            ret['ANSIBLE_COLLECTIONS_PATH'] = laaso.paths.venv_ansible_collections
            ret['ANSIBLE_COLLECTIONS_PATHS'] = laaso.paths.venv_ansible_collections
        if self.username and (self.username != getpass.getuser()):
            kwargs['ANSIBLE_REMOTE_USER'] = self.username
        ret.update(kwargs)
        return ret

    @staticmethod
    def ansible_inventory_xlat(inventory):
        '''
        Given an inventory, translate it to a flat string.
        If the inventory is provided as a string, that string
        is returned. If the inventory is provided as a list,
        that string is translated to a properly comma-separated
        list. If you are passing a single network address, remember
        to pass it as a list so it is not interpreted as a
        filename. Valid inputs are strings and iterables.
        '''
        if isinstance(inventory, str):
            return inventory
        if not inventory:
            return ''
        if not isinstance(inventory, list):
            inventory = list(inventory)
        if not all(isinstance(x, str) for x in inventory):
            raise ValueError("invalid inventory contents")
        if len(inventory) == 1:
            return inventory[0] + ','
        return ','.join(inventory)

    # When we rewrite the ansible.cfg file, we copy that subtree
    # to a temp dir so ansible can find it. _ANSIBLE_CFG_IGNORE
    # is glob-style patterns to skip copying
    _ANSIBLE_CFG_IGNORE = ('.#*',
                          )

    def _ansible_cfg_rewrite(self, ansible_cfg_dir_dst, ansible_cfg_update, logger=None):
        '''
        Read src as the ansible subdirectory. Write it out to dst.
        ansible_cfg_update(line, dst) is invoked on each line.
        '''
        logger = logger if logger is not None else self.logger
        ansible_cfg_dir_src, ansible_cfg_name = os.path.split(self.ansible_cfg)
        shutil.copytree(ansible_cfg_dir_src, ansible_cfg_dir_dst, ignore=shutil.ignore_patterns(*self._ANSIBLE_CFG_IGNORE))
        ansible_cfg_dst = os.path.join(ansible_cfg_dir_dst, ansible_cfg_name)
        with open(self.ansible_cfg, 'r', encoding='ascii') as src:
            with open(ansible_cfg_dst, 'w', encoding='ascii') as dst:
                while True:
                    line = src.readline()
                    if not line:
                        break
                    ansible_cfg_update(line, dst)
        return ansible_cfg_dst

    RE_PLAYBOOK_STARTED = re.compile(r'^[\s]*\[started TASK: (.*) on ')

    def _logfilter_playbook_run(self, txt):
        '''
        This is passed as the logfilter to _ansible_execute_logged() when we run a playbook.
        '''
        if not txt.strip():
            return None
        m = self.RE_PLAYBOOK_STARTED.search(txt)
        if m:
            self.playbook_progress = m.group(1)
            return None
        return txt

    def ansible_run_playbook(self, playbook, inventory, ansible_cfg_update=None, env=None, logger=None, **kwargs):
        '''
        Run one playbook against the specified inventory.
        If env is specified, that is used.
        '''
        logger = logger if logger is not None else self.logger
        if env is not None:
            assert isinstance(env, dict)
            assert 'ANSIBLE_CONFIG' in env
        else:
            env = self.ansible_env()
        kwargs.setdefault('logfilter', self._logfilter_playbook_run)
        cfg = self.ansible_cfg
        if not cfg:
            raise ApplicationExit("cannot locate ansible.cfg")
        if ansible_cfg_update is None:
            return self._ansible_run_playbook(cfg, playbook, inventory, env, logger=logger, **kwargs)
        assert callable(ansible_cfg_update)
        with tempfile.TemporaryDirectory() as tmpdir_path:
            tmp_ansible_dir = os.path.join(tmpdir_path, 'src', 'ansible')
            cfg = self._ansible_cfg_rewrite(tmp_ansible_dir, ansible_cfg_update, logger=logger)
            env = dict(env)
            env['ANSIBLE_CONFIG'] = cfg
            for repo_path in ('laaso',):
                os.symlink(os.path.abspath(os.path.join(laaso.paths.repo_root, repo_path)), os.path.join(tmpdir_path, repo_path))
            return self._ansible_run_playbook(cfg, playbook, inventory, env, logger=logger, **kwargs)

    def _ansible_suggest_repro(self, cmd, env, logger=None, log_level=logging.ERROR):
        '''
        Helper that suggests an easy way to reproduce a playbook failure
        '''
        logger = logger if logger is not None else self.logger
        repro_env = None
        repro_cmd = None
        try:
            if laaso.ONBOX:
                pb_exe = '/usr/laaso/bin/ansible_run_playbook.py'
            elif (os.getcwd() == laaso.paths.repo_root) or (laaso.paths.repo_root == '.'):
                pb_exe = os.path.join('laaso', 'ansible_run_playbook.py')
            else:
                pb_exe = os.path.join(laaso.paths.repo_root, 'laaso', 'ansible_run_playbook.py')
            repro_cmd = [pb_exe] + cmd[1:]
            # Figure out what non-default entries are in env. non-default
            # is from the PoV of ApplicationWithInheritedAnsibleEnv
            if env:
                repro_env = dict(env)
                base_env = ApplicationWithInheritedAnsibleEnv.ansible_env_repro(self, check=False)
                pk = set()
                for k, v in repro_env.items():
                    if (k in base_env) and (base_env[k] == v):
                        pk.add(k)
                for k in pk:
                    repro_env.pop(k)
                repro_env_keys_sorted = sorted(repro_env.keys())
                repro_env_sorted = collections.OrderedDict()
                for k in repro_env_keys_sorted:
                    repro_env_sorted[k] = repro_env[k]
            else:
                repro_env = None
            logger.log(log_level, "REPRO CMD: %s", cmd_str(repro_cmd, repro_env_sorted))
        except Exception as exc:
            logger.error("could not generate repro command: %r\nenv:\n%s\nrepro_env:\n%s\ncmd: %s\nrepro_cmd: %s\n%s\n%scould not generate repro command: %r",
                         exc,
                         expand_item_pformat(env),
                         expand_item_pformat(repro_env),
                         cmd,
                         repro_cmd,
                         indent_exc(),
                         PF, exc)

    def _ansible_run_playbook(self, cfg, playbook, inventory, env,
                              extra_vars=None,
                              logger=None,
                              add_scfg=False,
                              exit_on_error=True,
                              log_level=logging.INFO,
                              suggest_repro=True,
                              verbosity=0,
                              **kwargs):
        '''
        Execute the playbook using the specified configuration and environment.
        When exit_on_error is set, failures from ansible-playbook trigger ApplicationExit.
        When exit_on_error is not set, these failures raise AnsiblePlaybookFailed.
        '''
        logger = logger if logger is not None else self.logger
        repro_log_level = kwargs.pop('repro_log_level', log_level)
        assert isinstance(env, dict)
        assert 'ANSIBLE_CONFIG' in env
        cfg_parent = os.path.split(cfg)[0]
        playbook_path = os.path.join(cfg_parent, playbook)
        if not os.path.isfile(playbook_path):
            try:
                ap = os.path.abspath(playbook_path)
                logger.error("%s does not exist or is not a file; abspath=%r", playbook_path, ap)
            except Exception as exc:
                logger.error("%s does not exist or is not a file; cannot determine abspath: %r", playbook_path, exc)
            raise ValueError("%s does not exist or is not a file" % playbook_path)

        inventory_str = self.ansible_inventory_xlat(inventory)

        cmd = [laaso.paths.ansible_playbook_exe, '--inventory='+inventory_str]
        lev = dict()
        if add_scfg:
            subscription_id = getattr(self, 'subscription_id', '')
            if hasattr(self, 'scfg_dict_generate'):
                lev['laaso_scfg'] = self.scfg_dict_generate() # pylint: disable=no-member
            else:
                lev['laaso_scfg'] = laaso.scfg.to_scfg_dict(subscription_default=subscription_id)
            if hasattr(self, 'subscription_defaults_generate'):
                laaso_subscription_defaults = self.subscription_defaults_generate() # pylint: disable=no-member
                laaso_subscription_defaults = self.jinja_filter_data(laaso_subscription_defaults)
                lev['laaso_subscription_defaults'] = laaso_subscription_defaults
            subscription_name_substitutions = laaso.paths.subscription_config_dict_from_default_data('subscription_name_substitutions')
            subscription_name_substitutions = self.name_substitutions_resolve(subscription_name_substitutions)
            lev['subscription_name_substitutions'] = {'subscription_name_substitutions' : subscription_name_substitutions}
            lev['laaso_subscription_config'] = self.subscription_config_generate()
        if extra_vars:
            lev.update(extra_vars)
        if lev:
            cmd.append('--extra-vars='+json.dumps(lev, default=str))
        cmd.append(playbook_path)
        if verbosity > 0:
            cmd.extend(['-v'] * verbosity)
        logger.log(log_level, "run: %s", cmd_str(cmd, env))
        try:
            exit_status = _ansible_execute_logged(cmd, logger, env=self.ansible_env_inherit(env), log_level=log_level, **kwargs)
        except CommandFailed as exc:
            logger.error("command failed: %s", cmd_str(cmd, env))
            if suggest_repro:
                self._ansible_suggest_repro(cmd, env, logger=logger, log_level=repro_log_level)
            if exit_on_error:
                raise ApplicationExit("playbook %s failed" % playbook) from exc
            raise AnsiblePlaybookFailed(playbook_path, inventory_str, cmd, env) from exc
        except CommandTimeout as exc:
            if suggest_repro:
                self._ansible_suggest_repro(cmd, env, logger=logger, log_level=repro_log_level)
            if exit_on_error:
                logger.error("command timed out: %s", cmd_str(cmd, env))
                raise ApplicationExit("playbook %s timed out" % playbook) from exc
            raise AnsiblePlaybookFailed(playbook_path, inventory_str, cmd, env) from exc
        except Exception as exc:
            if suggest_repro:
                self._ansible_suggest_repro(cmd, env, logger=logger, log_level=repro_log_level)
            logger.error("command failed (%r): %s", exc, cmd_str(cmd, env))
            raise ApplicationExit("playbook %s failed" % playbook) from exc
        except KeyboardInterrupt:
            if suggest_repro:
                self._ansible_suggest_repro(cmd, env, logger=logger, log_level=repro_log_level)
            logger.warning("interrupted while running: %s", cmd_str(cmd, env))
            raise
        if exit_status != 0:
            if exit_on_error:
                logger.error("command failed (%r): %s", exit_status, cmd_str(cmd, env))
                if suggest_repro:
                    self._ansible_suggest_repro(cmd, env, logger=logger, log_level=repro_log_level)
                raise ApplicationExit("playbook %s failed" % playbook)
            if suggest_repro:
                self._ansible_suggest_repro(cmd, env, logger=logger, log_level=repro_log_level)
            raise AnsiblePlaybookFailed(playbook_path, inventory_str, cmd, env)
        logger.log(log_level, "complete: %s", cmd_str(cmd, env))
        return cmd, env

    @property
    def ansible_lint_paths_default(self):
        '''
        Getter - paths to lint in ansible_run_lint if paths is not specified
        '''
        return [self.ansible_cfg_parent]

    @staticmethod
    def ansible_lint_files(yaml_paths):
        '''
        Given a list of paths, return a set of files to lint
        '''
        todo = set()
        for path in yaml_paths:
            if not os.path.exists(path):
                raise ApplicationExit("%r does not exist" % path)
            if os.path.isdir(path):
                todo.update([str(x) for x in pathlib.Path(path).glob('**/*.yaml')])
            else:
                todo.add(path)
        return todo

    def ansible_run_lint(self, files=None, paths=None):
        '''
        Run ansible-lint against one or more files/directories. When a directory
        is provided, include all .yaml files below it. If paths is falsey,
        default to all .yaml files where ansible.cfg is found (src/ansible).
        Returns the set of paths linted.
        For this operation, paths in and out are relative to cwd, not ansible.cfg.
        '''
        if not paths:
            if files:
                yaml_paths = list()
            else:
                yaml_paths = self.ansible_lint_paths_default
        elif isinstance(paths, str):
            yaml_paths = [paths]
        else:
            yaml_paths = paths
        todo = self.ansible_lint_files(yaml_paths)
        if files:
            todo.update(files)
        assert todo
        filenames = sorted(todo)
        # ansible-lint can take multiple files on the command-line, but when
        # that happens it can generate false negatives
        p = self.parallel({filename : functools.partial(self._ansible_run_lint_one, filename) for filename in filenames},
                          max_outstanding=multiprocessing.cpu_count())
        p.launch()
        p.wait()
        assert len(p.results()) == len(filenames)
        filenames_failed = [x.name for x in p.failed()]
        if filenames_failed:
            if laaso.ONBOX:
                exe = '/usr/laaso/bin/ansible_run_lint.py'
            elif (os.getcwd() == laaso.paths.repo_root) or (laaso.paths.repo_root == '.'):
                exe = os.path.join('laaso', 'ansible_run_lint.py')
            else:
                exe = os.path.join(laaso.paths.repo_root, 'laaso', 'ansible_run_lint.py')
            filenames_failed.sort()
            if len(filenames_failed) == 1:
                self.logger.error("failed lint on: %s", filenames_failed[0])
                self.logger.info("you can relint that file with: %s %s", exe, filenames_failed[0])
            else:
                self.logger.error("failed lint on:\n%s", indent_simple(filenames_failed))
                self.logger.info("you can relint those files with: %s %s", exe, ' '.join(filenames_failed))
            raise ApplicationExit(1)
        return todo

    LAASO_ANSIBLE_LINT_ONBOX = '/usr/laaso/bin/laaso_ansible_lint.py'

    @classmethod
    def ansible_lint_exe(cls):
        '''
        Return the name of the ansible-lint executable
        '''
        if laaso.ONBOX:
            return cls.LAASO_ANSIBLE_LINT_ONBOX
        return laaso.paths.repo_root_path('src', 'ansible', 'bin', 'laaso_ansible_lint.py')

    def _ansible_run_lint_one(self, filename):
        '''
        Lint one file
        '''
        def logfilter(line):
            '''
            Return whether or not to log the given line
            '''
            if line.startswith('Added ANSIBLE_COLLECTIONS_PATHS'):
                return None
            return line

        cmd = [self.ansible_lint_exe(), filename]
        ansible_env = self.ansible_env()
        self.logger.debug("run: %s", cmd_str(cmd, ansible_env))
        try:
            exit_status = _ansible_execute_logged(cmd, self.logger, env=self.ansible_env_inherit(ansible_env), logfilter=logfilter)
        except Exception as exc:
            self.logger.error("command failed (%r): %s", exc, cmd_str(cmd, ansible_env))
            raise ApplicationExit(1) from exc
        except KeyboardInterrupt:
            self.logger.warning("interrupted while running: %s", cmd_str(cmd, ansible_env))
            raise
        if exit_status:
            self.logger.error("command failed (%r): %s", exit_status, cmd_str(cmd, ansible_env))
            raise ApplicationExit(1)
        self.logger.info("%s OK", filename)

    WAIT_FOR_SSH_WAIT_SECS_DEFAULT = 600.0

    def ansible_wait_for_ssh(self, name, vm_ip, env=None, wait_secs=WAIT_FOR_SSH_WAIT_SECS_DEFAULT):
        '''
        The VM created successfully. Wait for it to accept ssh connections.
        '''
        self.logger.debug("wait for ssh to %s", vm_ip)
        playbook = 'ping.playbook.yaml'

        t0 = time.time()
        deadline = t0 + wait_secs
        output = OutputAccumulator()
        last_result = None
        while True:
            cmd = None
            try:
                cmd, env = self.ansible_run_playbook(playbook, [vm_ip], logfilter=output.logfilter, log_level=logging.DEBUG, exit_on_error=False, env=env, suggest_repro=False)
                return
            except AnsiblePlaybookFailed as exc:
                last_result = "%s.wait_for_ssh vm_ip=%s %r" % (type(self).__name__, vm_ip, exc)
                self.logger.debug("%s", last_result)
                cmd = exc.cmd
                env = exc.env
            t1 = time.time()
            if t1 >= deadline:
                self.logger.error("output:\n%s", indent_simple(output.output))
                self.logger.error("last result: %s", last_result)
                err = "waited %s, but %s (%s) did not become responsive to ssh" % (elapsed(t0, t1), name, vm_ip)
                self.logger.error("%s", err)
                if cmd:
                    self._ansible_suggest_repro(cmd, env)
                raise ApplicationExit(err)
            time.sleep(min(2.0, elapsed(t1, deadline)))

    def laaso_requirements_check(self):
        '''
        Compare the results of "pip freeze" with the contents of laaso/requirements.txt.
        Raise if the two do not match.
        This detects running with a stale virtualenv.
        '''
        if laaso.ONBOX:
            req_fn = '/usr/laaso/etc/laaso/requirements.txt'
        else:
            req_fn = laaso.paths.repo_root_path('laaso', 'requirements.txt')
        pip_exe = os.path.join(os.path.split(sys.executable)[0], 'pip3')
        pip_cmd = [pip_exe, '--no-cache-dir', 'freeze']
        try:
            with open(req_fn, 'r') as f:
                req_contents = f.read()
        except FileNotFoundError as exc:
            raise ApplicationExit("%s.%s: cannot find %r" % (type(self).__name__, getframename(0), req_fn)) from exc
        try:
            ret = subprocess.check_output(pip_cmd, stdin=subprocess.DEVNULL, stderr=subprocess.STDOUT, cwd=laaso.paths.repo_root, encoding='utf-8')
        except subprocess.CalledProcessError as exc:
            self.logger.error("cannot execute %s: %r\n%s", cmd_str(pip_cmd, None), exc, expand_item_pformat(exc))
            raise ApplicationExit("cannot execute pip for requirement.txt check") from exc
        exclude = ('pkg-resources==0.0.0',)
        pip_list = set(x for x in ret.splitlines() if x and x not in exclude)
        req_list = set(x for x in req_contents.splitlines() if x)
        if (sys.version_info.major <= 3) and (sys.version_info.minor < 7):
            # dataclasses new in Lib/dataclasses.py in 3.7; ignore it on older versions (CentOS 7.7 stuck on python3.6- yuck)
            pip_list = {x for x in pip_list if not x.startswith('dataclasses==')}
        diff = pip_list ^ req_list
        if diff:
            self.logger.error("%s virtualenv requirements check failed\n%s", type(self).__name__, indent_simple(sorted(diff)))
            raise ApplicationExit('virtualenv requirements check failed')

    @staticmethod
    def subscription_config_single_generate(data):
        '''
        This is used by subscription_config_generate to generate and return
        the dict for a single subscription. data is the complete config
        dict for the subscription.
        '''
        ret = dict()
        subscription_id = data.get('subscription_id', '')
        subscription_id = laaso.util.uuid_normalize(subscription_id, exc_value=None)
        if not subscription_id:
            return dict()
        uamis = data.get('uamis', list())
        if isinstance(uamis, list):
            for uami in data.get('uamis', list()):
                if isinstance(uami, dict):
                    ud = dict()
                    copy_keys_required = ('name', 'resource_group')
                    copy_keys_optional = ('verify_client_id',)
                    for k in copy_keys_required:
                        if k in uami:
                            ud[k] = uami[k]
                    if len(ud) == len(copy_keys_required):
                        ret.setdefault('uamis', list()).append(ud)
                    for k in copy_keys_optional:
                        if k in uami:
                            ud[k] = uami[k]
        if ret:
            ret['subscription_id'] = subscription_id
        return ret

    def subscription_config_generate(self):
        '''
        Return a dict that corresponds to the subscriptions block in the main config.
        This is filtered down to "need-to-know".
        '''
        ret = list()
        for subscription_data in laaso.paths.subscription_config_list_from_default_data('subscriptions'):
            if isinstance(subscription_data, dict) and subscription_data:
                out_data = self.subscription_config_single_generate(subscription_data)
                if out_data:
                    ret.append(out_data)
        return {'subscriptions' : ret}

    def subscription_value_get(self, key, *args, subscription_id=None, location=None):
        '''
        Get a per-subscription value identified by key. If that value
        is not found, and an extra argument is provided, that argument
        is used as the default. Otherwise, if the value is not found,
        raise a KeyError.
        '''
        assert isinstance(key, str)
        subscription_id = subscription_id or self.subscription_id_default
        if not (subscription_id and isinstance(subscription_id, str)):
            raise ValueError("invalid subscription_id")
        if len(args) not in (0, 1):
            raise TypeError("%s.%s expected at most 2 arguments, got %d" % (type(self).__name__, getframename(0), len(args)))
        subscription_id = laaso.subscription_mapper.effective(subscription_id)
        for s in laaso.subscription_mapper.defaults:
            if s['subscription_id'] == subscription_id:
                try:
                    return s[key]
                except KeyError:
                    location = location if location is not None else self.location_effective(location)
                    name_subs = s.name_substitutions_get(location=location)
                    try:
                        return name_subs[key]
                    except KeyError:
                        pass
                    if args:
                        return args[0]
                    raise
        sns = laaso.subscription_mapper.name_substitutions_bcommon_get()
        try:
            return sns[key]
        except KeyError:
            if args:
                return args[0]
        raise KeyError(key)

    def location_value_get(self, key, *args, subscription_id=None, location=None):
        '''
        Like subscription_value_get, but retrieves the value from the location_defaults
        section of the subscription info.
        '''
        assert isinstance(key, str)
        subscription_id = subscription_id or self.subscription_id_default
        if not (subscription_id and isinstance(subscription_id, str)):
            raise ValueError("invalid subscription_id")
        if len(args) not in (0, 1):
            raise TypeError("%s.%s expected at most 2 arguments, got %d" % (type(self).__name__, getframename(0), len(args)))
        try:
            # Spell out the lookups explicitly on separate lines so that failures may be deduced from the KeyError traceback
            si = laaso.subscription_info_get(subscription_id, return_default=False)
            location = location or getattr(self, 'location', '') or si['location_default']
            if not location:
                raise ValueError("location invalid or unspecified")
            location_defaults = si['location_defaults']
            li = location_defaults[location]
            return li[key]
        except KeyError:
            if args:
                return args[0]
            raise

    def location_effective(self, *args):
        '''
        Given a location (region) specification, return the name of a location to use.
        When a location is truthy, we just use that. Otherwise, we fall back to
        the per-subscription default.
        args is simply zero or more possible locations tried in order; the first
        non-truthy arg is used.
        '''
        for arg in args:
            if arg:
                return arg
        location = getattr(self, 'location', '')
        if location:
            return location
        return self.subscription_value_get('location_default', laaso.base_defaults.LOCATION_DEFAULT_FALLBACK)

    def network_security_group_id_effective(self, location=None, network_security_group_id=None, resource_group=None, resource_group_fallback=None, subscription_id=None):
        '''
        Determine the ID of the network_security_group to use.
        If network_security_group_id starts with a /, assume it is fully-qualified and use it.
        If it has for a/b, treat that as resource_group/nsg_name.
        If it is specified as a bare name, use that with the appropriate resource_group.
        Fall back to 'standup-eastus2-nsg'.
        '''
        subscription_id = subscription_id or self.subscription_id_default
        if not subscription_id:
            raise self.exc_value("%s.%s: 'subscription_id' not specified" % (type(self).__name__, getframename(0)))
        subscription_info = self.subscription_info_get(subscription_id=subscription_id)
        location = location or subscription_info.get('location_default', '')
        nsg_rg = resource_group
        if network_security_group_id:
            if network_security_group_id.startswith('/'):
                return network_security_group_id
            tmp = network_security_group_id.split('/')
            if len(tmp) == 1:
                # bare name
                nsg_name = tmp[0]
            elif len(tmp) == 2:
                nsg_rg = tmp[0]
                nsg_name = tmp[1]
            else:
                raise ApplicationExit("invalid network_security_group_id %r" % network_security_group_id)
        else:
            nsg_rg = subscription_info.get('vnet_resource_group_default', '')
            nsg_name = subscription_info['location_defaults'][location].get('standup_nsg', '')
            if not nsg_name:
                raise ApplicationExit("no default standup_nsg for subscription=%r location=%r" % (subscription_info['subscription_id'], location))
        if not nsg_name:
            raise ApplicationExit("invalid network_security_group_id %r" % network_security_group_id)
        if network_security_group_id and resource_group and nsg_rg and (resource_group != nsg_rg):
            raise ApplicationExit("resource_group=%r is not consistent with network_security_group_id=%r" % (resource_group, network_security_group_id))
        nsg_rg = nsg_rg or resource_group or subscription_info.get('vnet_resource_group_default', '') or resource_group_fallback
        if not nsg_rg:
            raise ApplicationExit("'resource_group' not specified so cannot determine network_security_group_id")
        tmp = '/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Network/networkSecurityGroups/{nsg_name}'
        return tmp.format(subscription_id=subscription_id, resource_group=nsg_rg, nsg_name=nsg_name)

    @classmethod
    def mth(cls):
        '''
        Return a string of the form "Blah.x" where Blah is the name of this class
        and x is the frame name of the caller.
        '''
        return "%s.%s" % (cls.__name__, getframename(1))

    def jinja_filter_add(self, name, proc):
        '''
        Add proc as a jinja filter for name.
        Safe to call before calling __init__, so subclasses may
        add filters before calling super-init.
        '''
        jinja_filters = getattr(self, 'jinja_filters', dict())
        jinja_filters[name] = proc
        self.jinja_filters = jinja_filters

    def jinja_substitutions(self, **kwargs):
        '''
        Return jinja2 substitutions dict
        '''
        try:
            time_cur = kwargs.pop('time_cur')
        except KeyError:
            time_cur = time.time()
        assert isinstance(time_cur, float)
        tc = time.gmtime(time_cur)
        dt = time.strftime('%Y-%m-%d-%H-%M-%S', tc)
        dt_exact = dt + '-' + str(time_cur - int(time_cur))[2:]
        location_default = kwargs.get('location_default', self.location_effective())
        location = kwargs.get('location', getattr(self, 'location', location_default)) or ''
        subs = {'application_class' : type(self).__name__,
                'azure_certificate_store' : laaso.base_defaults.AZURE_CERTIFICATE_STORE,
                'datetime' : dt,
                'datetime_exact' : dt_exact,
                'scfg' : laaso.scfg,
                'location_value_get' : self.location_value_get,
                'subscription_ids' : laaso.subscription_ids,
                'subscription_mapper' : laaso.subscription_mapper,
                'time_cur' : time_cur,
                'user' : self.username,
                'username' : self.username,
               }
        if 'subscription_id' in kwargs:
            subs['subscription_id'] = kwargs['subscription_id']
        elif hasattr(self, 'subscription_id'):
            subs['subscription_id'] = getattr(self, 'subscription_id')
        try:
            subs['subscription_desc'] = self.subscription_info
        except AttributeError:
            pass
        if location_default or ('location_default' in kwargs):
            subs['location_default'] = location_default
        if location or ('location' in kwargs):
            subs['location'] = location
        subscription_id = subs.get('subscription_id', '')
        if subscription_id:
            si = laaso.subscription_info_get(subscription_id)
            subs = laaso.util.deep_update(subs, si.name_substitutions_get(location=location))

        subs.update(self.jinja_additional_substitutions)
        subs.update(kwargs)
        return subs

    def jinja_environment(self, additional_filters=None):
        '''
        Return jinja2.Environment
        '''
        # It is not obvious from the naming that saying undefined=jinja2.DebugUndefined
        # tells jinja to just not do any substitution when it sees
        # something undefined. We rely on this to be able to do some
        # substitutions up-front with jinja_filter_data(), then come
        # back to some values later with either jinja_filter_data()
        # or jinja_effective() to provide additional substitutions.
        jenv = jinja2.Environment(undefined=jinja2.DebugUndefined)
        jenv.filters.update(self.jinja_filters)
        if additional_filters:
            jenv.filters.update(additional_filters)
        return jenv

    def _jinja_effective(self, value, additional_substitutions=None, additional_filters=None, jenv=None, subs=None):
        '''
        Run value through jinja2 once
        '''
        assert isinstance(value, str)
        if not jenv:
            additional_substitutions = additional_substitutions or dict()
            jenv = self.jinja_environment(additional_filters=additional_filters)
        if subs is None:
            subs = self.jinja_substitutions(**additional_substitutions)
        template = jenv.from_string(value)
        return template.render(**subs)

    def jinja_effective(self, value, key='', additional_substitutions=None, je_loop_reset=None, **kwargs):
        '''
        Run value through jinja2 until it cannot be resolved further.
        Typically used as a helper during __init__.
        '''
        if not value:
            return value
        if isinstance(value, enum.Enum):
            return value
        if not isinstance(value, str):
            return value
        additional_substitutions = additional_substitutions or dict()
        prev = value
        while True:
            if je_loop_reset:
                je_loop_reset(additional_substitutions)
            try:
                newvalue = self._jinja_effective(prev, additional_substitutions=additional_substitutions, **kwargs)
            except (jinja2.exceptions.TemplateAssertionError, jinja2.exceptions.UndefinedError) as exc:
                # Cannot translate
                return prev
            except jinja2.exceptions.TemplateSyntaxError as exc:
                if key:
                    self.logger.warning("%s key=%r error expanding %r: %r", self.mth(), key, prev, exc)
                else:
                    self.logger.warning("%s error expanding %r: %r", self.mth(), prev, exc)
                raise
            except Exception as exc:
                self.logger.error("%s: key=%r prev=%r value=%r cannot compute jinja2 effective value: %r",
                                  self.mth(), key, prev, value, exc)
                raise
            if newvalue == prev:
                return newvalue
            prev = newvalue

    def jinja_filter_data(self, data, additional_substitutions=None, additional_filters=None):
        '''
        Iterate through data. Whenever a str value is encountered,
        run it through jinja2.
        '''
        additional_substitutions = additional_substitutions or dict()
        jenv = self.jinja_environment(additional_filters=additional_filters)
        subs = self.jinja_substitutions(**additional_substitutions)
        return self._jinja_filter_data__one(data, jenv, subs)

    def _jinja_filter_data__one(self, data, jenv, subs):
        '''
        Part of jinja_filter_data - recursively iterate.
        '''
        if isinstance(data, enum.Enum):
            # Do not translate if we are already a string enum value
            return data

        if isinstance(data, str):
            try:
                return self.jinja_effective(data, jenv=jenv, subs=subs)
            except (jinja2.exceptions.TemplateAssertionError, jinja2.exceptions.UndefinedError) as exc:
                # Cannot translate
                return data
            except jinja2.exceptions.TemplateSyntaxError as exc:
                self.logger.warning("%s error expanding %r: %r", self.mth(), data, exc)
                raise

        if isinstance(data, list):
            return [self._jinja_filter_data__one(x, jenv, subs) for x in data]
        if isinstance(data, (set, tuple)):
            return type(data)([self._jinja_filter_data__one(x, jenv, subs) for x in data])

        if isinstance(data, dict):
            return {k : self._jinja_filter_data__one(v, jenv, subs) for k, v in data.items()}

        # No translation
        return data

    def name_substitutions_resolve(self, name_substitutions):
        '''
        name_substitutions is a dict that we intend to re-export to
        the subscription config (yaml) on another node. This is
        plumbed through ansible playbooks as extra_vars.
        Resolve everything we can. This applies known special-cases
        for things like subscription IDs and resource IDs.
        '''
        def exval_sub(ret, key):
            '''
            If the named key is present in ret as a string,
            normalize any embedded subscription_id.
            '''
            v = ret.get(key, None)
            if isinstance(v, str) and v:
                ret[key] = azresourceid_normalize_subscription_only(v)

        ret = self.jinja_filter_data(name_substitutions)
        exval_sub(ret, 'genevaIdentityDefault')
        exval_sub(ret, 'genevaKeyVaultSubDefault')
        exval_sub(ret, 'omsWorkspaceIdDefault')
        return ret

def _ansible_execute_logged(cmd:list, logger:logging.Logger, **kwargs):
    '''
    Wrap execute_logged(). This method provides an intercept point for unit tests.
    '''
    return laaso.util.execute_logged(cmd, logger, **kwargs)

class _SyslogState():
    '''
    Singleton class - global syslog state
    '''
    _syslog_lock = threading.RLock()
    _syslog_initialized = False
    _syslog_ident = None
    _syslog_facility = None
    _syslog_options = None

    @property
    def syslog_lock(self):
        '''
        Getter - global lock for syslog state
        '''
        return self._syslog_lock

    @classmethod
    def initialize(cls, ident, facility, options):
        '''
        Initialize global state
        '''
        with cls._syslog_lock:
            if not cls._syslog_initialized:
                assert cls._syslog_ident is None
                assert cls._syslog_facility is None
                assert cls._syslog_options is None

                cls._syslog_ident = ident
                cls._syslog_facility = facility
                cls._syslog_options = options

                if cls._syslog_ident:
                    syslog.closelog()
                    syslog.openlog(cls._syslog_ident, cls._syslog_facility, cls._syslog_options)
                    syslog.setlogmask(syslog.LOG_UPTO(syslog.LOG_INFO))

            cls._syslog_initialized = True

    @classmethod
    def syslog_handler_generate(cls) -> logging.handlers.SysLogHandler:
        '''
        Generate and return a logging.handlers.SysLogHandler
        using the common syslog configuration.
        '''
        with cls._syslog_lock:
            cls.initialize('', None, None)
            if cls._syslog_ident:
                assert cls._syslog_facility is not None
                assert cls._syslog_options is not None
                handler = logging.handlers.SysLogHandler(address='/dev/log', facility=cls._syslog_facility)
                handler.ident = f"{cls._syslog_ident}[{os.getpid()}]: "
                return handler
        return None

syslog_state = _SyslogState()

class ApplicationWithSubscription(Application):
    '''
    Application that operates on a subscription
    '''
    def __init__(self, subscription_id=None, tenant_id=None, **kwargs):
        if subscription_id == 'default':
            # JIT translate this so we can have 'default' as a command-line
            # default to avoid translating subscription IDs before construction.
            # That avoids fetching and caching the config before construction.
            subscription_id = laaso.subscription_ids.subscription_default
        use_subscription_id = getattr(self, 'subscription_id', '') or subscription_id
        if self.SUBSCRIPTION_ID_REQUIRED:
            use_subscription_id = use_subscription_id or laaso.subscription_ids.subscription_default
        self.tenant_id = getattr(self, 'tenant_id', '') or tenant_id or laaso.scfg.tenant_id_default

        self.subscription_id_set(use_subscription_id)

        # We set the subscription id before we initialize the Application class.
        # This allows the logblob logging initialization to access the subscription id,
        # and can therefore be subscription-specific.
        super().__init__(**kwargs)

    @property
    def subscription_id(self):
        '''
        Getter
        '''
        return self._subscription_id or None

    @subscription_id.setter
    def subscription_id(self, value):
        '''
        Setter
        '''
        self.subscription_id_set(value)

    def subscription_id_set(self, value):
        '''
        Update self.subscription_id and related values
        '''
        # Only use the mapper if we must. Before the shepherd bootstraps,
        # it cannot safely use the mapper.
        subscription_id = laaso.util.uuid_normalize(value, key='subscription_id', exc_value=None)
        if not subscription_id:
            subscription_id = laaso.subscription_mapper.effective(value)
        self._subscription_id = subscription_id
        self.subscription_info = self.subscription_info_get()

    @property
    def subscription_id_default(self):
        '''
        Getter for default subscription ID.
        Do not fall back to the global default.
        A caller may have explicitly cleared subscription_id
        to prevent anything from getting an implicit default.
        '''
        return self.subscription_id

    SUBSCRIPTION_ID_ARG = True
    SUBSCRIPTION_ID_REQUIRED = True

    TENANT_ID_ARG_ADD = True

    @classmethod
    def main_add_parser_args(cls, ap_parser):
        '''
        See laaso.Application.main_add_parser_args()
        '''
        super().main_add_parser_args(ap_parser)
        group = ap_parser.get_argument_group('subscription')
        if cls.SUBSCRIPTION_ID_ARG:
            if cls.SUBSCRIPTION_ID_REQUIRED:
                group.add_argument('--subscription_id', type=str, default='default',
                                   action=ArgExplicit,
                                   help='subscription ID on which to operate (default %(default)r)')
            else:
                group.add_argument('--subscription_id', type=str, default='',
                                   action=ArgExplicit,
                                   help='subscription ID on which to operate (default to no subscription)')
        if cls.TENANT_ID_ARG_ADD:
            group.add_argument('--tenant_id', type=str, default='',
                               action=ArgExplicit,
                               help='Azure tenant_id')

    @classmethod
    def _kwargs_for_self_copy(cls, obj, d):
        '''
        See laaso.common.Application._kwargs_for_self_copy()
        '''
        super()._kwargs_for_self_copy(obj, d)
        cls.dict_reflect_attrs(obj, d, 'subscription_id', 'tenant_id')

    def manager_kwargs(self, **kwargs):
        '''
        See laaso.Application.manager_kwargs()
        '''
        ret = super().manager_kwargs()
        ret['subscription_id'] = self.subscription_id
        ret['tenant_id'] = self.tenant_id
        ret.update(kwargs)
        return ret

    def subscription_id_matches(self, subscription_id):
        '''
        Return whether subscription_id is the same as self.subscription_id.
        If both are falsey, they match.
        '''
        # this handles None as well as ''
        if bool(subscription_id) ^ bool(self.subscription_id):
            # one is truthy and one is falsey
            return False
        if not (subscription_id and self.subscription_id):
            # both are falsey (at least one is falsey, and we handled exactly one above)
            return True
        return subscription_id.lower() == self.subscription_id.lower()

    def parse_keyvault(self, keyvault, match_subscription_id=True, exc_value=None):
        '''
        keyvault is a str of the form 'keyvault-name' or 'keyvault-rg/keyvault-name'
        or a fully-qualified Azure resource ID.
        Return (keyvault_subscription_id, keyvault_rg, keyvault_name) as a tuple.
        '''
        exc_value = exc_value or self.exc_value
        if not keyvault:
            return ('', '', '')
        if not isinstance(keyvault, str):
            raise TypeError("keyvault must be str, not %s" % type(keyvault))
        toks = keyvault.split('/')
        if keyvault.startswith('/') and (not toks[0]) and all(toks[1:]) and (len(toks) == AzResourceId.ARGS_FROM_TEXT_TOKENS):
            kwa = dict()
            if match_subscription_id:
                kwa['subscription_id'] = self.subscription_id
            azrid = AzResourceId.from_text(keyvault, provider_name='Microsoft.KeyVault', resource_type='vaults', exc_value=exc_value, **kwa)
            return (azrid.subscription_id, azrid.resource_group_name, azrid.resource_name)
        if not all(toks):
            raise exc_value("cannot parse keyvault %r" % keyvault)
        if len(toks) == 1:
            rg = self.subscription_value_get('infra_resource_group_default', '')
            if not rg:
                raise exc_value("resource_group not known for keyvault %r" % keyvault)
            return (self.subscription_id, rg, toks[0])
        if len(toks) == 2:
            return (self.subscription_id, toks[0], toks[1])
        raise exc_value("cannot parse keyvault %r" % keyvault)

class ApplicationWithResourceGroup(ApplicationWithSubscription):
    '''
    Application that operates on a resource group
    '''
    def __init__(self, resource_group='', **kwargs):
        super().__init__(**kwargs)
        self.resource_group = resource_group or ''
        if self.RESOURCE_GROUP_REQUIRED and (not self.resource_group):
            raise self.exc_value("'resource_group' not specified")

    RESOURCE_GROUP_HELP = 'resource group for resource group operations'
    RESOURCE_GROUP_ARG_ADD = True
    RESOURCE_GROUP_ARG_GROUP = 'resource group'
    RESOURCE_GROUP_ARG_OPTIONAL = True
    RESOURCE_GROUP_REQUIRED = False

    @classmethod
    def main_add_parser_args(cls, ap_parser):
        '''
        See laaso.Application.main_add_parser_args()
        '''
        super().main_add_parser_args(ap_parser)
        if cls.RESOURCE_GROUP_ARG_ADD:
            if cls.RESOURCE_GROUP_ARG_OPTIONAL:
                group = ap_parser.get_argument_group(cls.RESOURCE_GROUP_ARG_GROUP)
                group.add_argument('--resource_group', type=str, default=cls.arg_resource_group__default(),
                                   action=ArgExplicit,
                                   help=cls.RESOURCE_GROUP_HELP)
            else:
                ap_parser.add_argument('resource_group', type=str, default=cls.arg_resource_group__default(),
                                       action=ArgExplicit,
                                       help=cls.RESOURCE_GROUP_HELP)

    @classmethod
    def _kwargs_for_self_copy(cls, obj, d):
        '''
        See laaso.common.Application._kwargs_for_self_copy()
        '''
        super()._kwargs_for_self_copy(obj, d)
        cls.dict_reflect_attrs(obj, d, 'resource_group')

    def manager_kwargs(self, **kwargs):
        '''
        See laaso.Application.manager_kwargs()
        '''
        ret = super().manager_kwargs()
        ret['resource_group'] = self.resource_group
        ret.update(kwargs)
        return ret

    def resource_group_effective(self, resource_group, required=True, exc_value=ValueError):
        '''
        Given a resource_group name, return a resource_group name to use.
        This defaults resource_group to self.resource_group, and either
        returns a string or raises an exception. IF required is set, the
        returned string is non-empty or exc_value is raised.
        '''
        resource_group = resource_group or self.resource_group
        if not resource_group:
            if required:
                raise exc_value("'resource_group' not specified")
            return ''
        if not isinstance(resource_group, str):
            raise TypeError("invalid resource_group type %s" % type(resource_group))
        if not RE_RESOURCE_GROUP_ABS.search(resource_group):
            raise exc_value("invalid resource_group name %r" % resource_group)
        return resource_group

    def resource_id_effective(self,
                              name,
                              provider_name,
                              resource_type,
                              namedesc='',
                              resource_group='',
                              subscription_id_must_match=True,
                              resource_group_must_match=False,
                              exc_value=ValueError):
        '''
        Convert a string that might be a bare name or a fully-qualified Azure resource_id to AzResourceId.
        provider_name is something like 'Microsoft.Network', 'Microsoft.KeyVault', etc.
        resource_type is something like 'virtualNetworks', 'virtualMachines', 'publicIPAddresses', etc.
        When a bare name is provided, use resource_group as the RG if it is provided; otherwise, use self.resource_group.
        namedesc is used to describe name in error messages.
        '''
        namedesc = namedesc or "%s/%s" % (provider_name, resource_type)
        if not isinstance(name, str):
            raise TypeError("invalid %s type %s" % (namedesc, type(name)))
        resource_group = self.resource_group_effective(resource_group, required=False, exc_value=exc_value)
        if name.startswith('/'):
            # /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/some-rg/providers/Microsoft.Network/publicIPAddresses/some-publicip
            azrid = AzResourceId.from_text(name, subscription_id=self.subscription_id, provider_name=provider_name, resource_type=resource_type, exc_desc=namedesc, exc_value=exc_value)
        else:
            toks = list(reversed(name.split('/')))
            if not all(toks):
                raise exc_value("invalid %s" % namedesc)
            if len(toks) == 1:
                resource_group = self.resource_group_effective(resource_group, required=True, exc_value=exc_value)
                azrid = AzResourceId(self.subscription_id, resource_group, provider_name, resource_type, toks[0], exc_value=exc_value)
            elif len(toks) == 2:
                azrid = AzResourceId(self.subscription_id, toks[1], provider_name, resource_type, toks[0], exc_value=exc_value)
            elif len(toks) == 3:
                azrid = AzResourceId(toks[2], toks[1], provider_name, resource_type, toks[0], exc_value=exc_value)
            else:
                raise exc_value("invalid %s %r" % (namedesc, name))
        if subscription_id_must_match and (azrid.subscription_id != self.subscription_id):
            raise exc_value("subscription_id mismatch")
        if resource_group_must_match and (azrid.resource_group_name != resource_group):
            raise exc_value("resource_group mismatch")
        return azrid

    def public_ip_id_effective(self, public_ip, **kwargs):
        '''
        Given public_ip as a string, interpret it and return an azure resource_id as a string
        '''
        kwargs.setdefault('namedesc', 'public_ip')
        azrid = self.resource_id_effective(public_ip, 'Microsoft.Network', 'publicIPAddresses', **kwargs)
        return str(azrid)

    def subnet_id_effective(self, name_or_id, subscription_id='', resource_group='', vnet_name='', location='', exc_value=ValueError):
        '''
        Determine an ID for a subnet.
        Takes a name or a desc.
        '''
        if not isinstance(name_or_id, str):
            raise TypeError("%s.%s: name_or_id must be str, not %s" % (type(self).__name__, getframename(0), type(name_or_id)))
        if not name_or_id:
            raise self.exc_value("%s.%s: invalid name_or_id %r" % (type(self).__name__, getframename(0), name_or_id))

        if name_or_id.startswith('/'):
            rid = AzSubResourceId.from_text(name_or_id,
                                            subscription_id=subscription_id,
                                            provider_name='Microsoft.Network',
                                            resource_type='virtualNetworks',
                                            exc_value=exc_value)
        else:
            toks = list(reversed(name_or_id.split('/')))
            if len(toks) == 1:
                _subscription_id = subscription_id or self.subscription_id
                _subscription_info = laaso.subscription_info_get(subscription_id)
                _location = location or getattr(self, 'location', _subscription_info.location_default)
                _resource_group = resource_group or self.subscription_info.get('vnet_resource_group_default', '') or self.resource_group
                _vnet_name = vnet_name or self.location_value_get('vnet', '', location=_location)
                rid = AzSubResourceId(_subscription_id,
                                      _resource_group,
                                      'Microsoft.Network',
                                      'virtualNetworks',
                                      _vnet_name,
                                      'subnets',
                                      toks[0])
            elif len(toks) == 2:
                _subscription_id = subscription_id or self.subscription_id
                _resource_group = resource_group or self.subscription_info.get('vnet_resource_group_default', '') or self.resource_group
                rid = AzSubResourceId(_subscription_id,
                                      _resource_group,
                                      'Microsoft.Network',
                                      'virtualNetworks',
                                      toks[1],
                                      'subnets',
                                      toks[0])
            elif len(toks) == 3:
                _subscription_id = subscription_id or self.subscription_id
                rid = AzSubResourceId(_subscription_id,
                                      toks[2],
                                      'Microsoft.Network',
                                      'virtualNetworks',
                                      toks[1],
                                      'subnets',
                                      toks[0])
            elif len(toks) == 4:
                rid = AzSubResourceId(toks[3],
                                      toks[2],
                                      'Microsoft.Network',
                                      'virtualNetworks',
                                      toks[1],
                                      'subnets',
                                      toks[0])
            else:
                raise exc_value("cannot parse %r" % name_or_id)
        return str(rid)

def username_default():
    '''
    Return the username to be used when not otherwise defined.
    This may be invoked before application objects are constructed.
    '''
    return getpass.getuser()

def child_app(parent, appclass, appargs, namestack, posargs=None):
    '''
    Construct an Application-like object of type appclass and return it.
    appargs is a dict of explicit arguments for the new app. This operation
    is allowed to scribble on appargs. parent is an Application-like object
    that owns the new app.
    '''
    assert namestack
    expect_logger = appargs.get('logger', parent.logger)
    appargs.setdefault('args_explicit', set()).update(appargs.keys())
    app_kwargs = appclass.kwargs_for_class(parent, **appargs)
    posargs = posargs or tuple()
    # appclass may or may not like namestack as an init arg.
    if laaso.util.has_explicit_kwarg(appclass, 'namestack'):
        app_kwargs.setdefault('namestack', namestack)
    try:
        app = appclass(*posargs, **app_kwargs)
    except ApplicationExitWithNote as exc:
        raise
    except ApplicationExit as exc:
        raise ApplicationExitWithNote(exc.code, note=namestack) from exc
    assert id(app.logger) == id(expect_logger)
    return app

class ApplicationWithInheritedAnsibleEnv(ApplicationWithSubscription):
    '''
    Application with the generated ansible environment expanded
    to include ANSIBLE_* settings from the calling environment.
    Inherits from ApplicationWithSubscription to enable --add_scfg
    functionality to ansible_run_playbook.py for testing purposes.
    '''
    def ansible_env(self, **kwargs):
        '''
        See laaso.Application.ansible_env()
        '''
        kwargs.update({k : v for k, v in os.environ.items() if k.startswith('ANSIBLE_')})
        return super().ansible_env(**kwargs)

    @classmethod
    def ansible_env_repro(cls, application_obj, **kwargs):
        '''
        Like ansible_env(), but is a classmethod. This supports
        the coerced call in _ansible_suggest_repro(). Here, we explicitly
        do not include things from the external environment so that
        when _ansible_suggest_repro() compares this result with
        that of application_obj.ansible_env(), the external settings
        show up as different. application_obj is typically
        not ansible_run_playbook.Application.
        '''
        return super().ansible_env(application_obj, **kwargs)

Application.main(__name__)
