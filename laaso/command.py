#
# laaso/command.py
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
'''
Implement the Command class which handles @command decorators.
'''
import functools
import inspect
import logging
import pprint
import sys

import laaso.output
from laaso.util import expand_item_pformat

class Command():
    '''
    Manage decorators for an application.
    These decorators enable exposing actions through
    the command line by defining and decorating the
    handler without touching other argument parsing.
    '''
    def __init__(self):
        self._commands = dict() # key=name value=_Item

    RESERVED_NAMES = ('actions',
                      'can_handle',
                      'commands',
                      'handle',
                      'print',
                     )

    @property
    def actions(self):
        '''
        Getter that returns a lexically-sorted list of
        handler names.
        '''
        return sorted(self._commands.keys())

    @classmethod
    def _name_valid(cls, name):
        '''
        Return whether name is usable as a decoration.
        Example:
            command = Command()
            @command._some_func
          That is not valid, because '_some_func' begins with '_'.
          We do not allow leading underscores to avoid exposing
          class internals and to easily avoid accidently exposing
          or shading the internals of this class. Similarly,
          all public methods and attributes must be enumerated
          in RESERVED_NAMES. See __getattr__() for this in action.
        '''
        if not isinstance(name, str):
            return False
        if not name:
            return False
        if name.startswith('_'):
            return False
        if name in cls.RESERVED_NAMES:
            return False
        return True

    def __getattr__(self, name):
        '''
        If name is not internal to this class, treat it as a decorator.
        '''
        if not self._name_valid(name):
            # Not a decoration
            raise AttributeError("'%s' object has no attribute '%s'" % (type(self).__name__, name))
        return functools.partial(self._decorate, name)

    def _decorate(self, decorator, func):
        '''
        Decorate the named func. decorator is the name of the
        decoration - eg:
            command = Command()
            @command.simple
            def some_func():
        generates _decorate('simple', 'some_func', some_func)
        '''
        printable = decorator.startswith('printable')
        printable_raw = decorator.endswith('_raw') or ('_raw_' in decorator)
        ci = _Item(decorator, func, printable=printable, printable_raw=printable_raw)
        if not self._name_valid(ci.name):
            raise ValueError("may not decorate using reserved name %r" % ci.name)
        if ci.name in self._commands:
            raise ValueError("duplicate command %r" % ci.name)
        self._commands[ci.name] = ci
        return ci.func

    def _handle(self, doit, name, decorators, *args, **kwargs):
        '''
        Try provided decorators until one is found or there is nothing left to try.
        '''
        if isinstance(decorators, str):
            return self._handle_one(doit, name, decorators, *args, **kwargs)
        for decorator in decorators:
            ret = self._handle_one(doit, name, decorator, *args, **kwargs)
            if ret:
                return ret
        return False

    def _handle_one(self, doit, name, decorator, *args, **kwargs):
        '''
        Invoke the registered handler for name.
        If no handler is registered, return False.
        If a handler is registered, return True.
        '''
        ci = self._commands.get(name, None)
        if not (ci and ci.decorator == decorator):
            return False
        if args:
            kls = ci.getclass()
            if kls:
                # We could check: if not isinstance(args[0], (kls,))
                # here. That would allow decorating method X in a class C1
                # and then executing X on class C2 which is a subclass of C1.
                # The behavior there could be unexpected; even if C2 overloads X,
                # C1.X is executed on the object. We already prevent redecorating
                # an inherited method through the name collision check, so
                # here we simply restrict the check to be exactly the
                # target class rather than allowing subclasses.
                if type(args[0]) is not kls: # pylint: disable=unidiomatic-typecheck
                    return False
        if doit:
            ret = ci.func(*args, **kwargs)
            if ci.printable_raw:
                laaso.output.capture()
                if isinstance(ret, (list, set, tuple)):
                    for x in ret:
                        if isinstance(x, str):
                            sys.stdout.laaso_rawwrite(x+'\n')
                        else:
                            sys.stdout.laaso_rawwrite(expand_item_pformat(x, prefix='')+'\n')
                else:
                    if isinstance(ret, str):
                        sys.stdout.laaso_rawwrite(ret+'\n')
                    else:
                        sys.stdout.laaso_rawwrite(expand_item_pformat(ret, prefix='')+'\n')
            elif ci.printable:
                if isinstance(ret, (list, set, tuple)):
                    for x in ret:
                        if isinstance(x, str):
                            print(x)
                        else:
                            print(expand_item_pformat(x, prefix=''))
                else:
                    if isinstance(ret, str):
                        print(ret)
                    else:
                        print(expand_item_pformat(ret, prefix=''))
        return True

    @staticmethod
    def print(item):
        '''
        print() the given item
        '''
        if isinstance(item, (list, set, tuple)):
            for x in item:
                if isinstance(x, str):
                    print(x)
                else:
                    print(expand_item_pformat(x, prefix=''))
        else:
            if isinstance(item, str):
                print(item)
            else:
                print(expand_item_pformat(item, prefix=''))

    def handle(self, name, decorators, *args, **kwargs):
        '''
        Invoke the registered handler for name.
        decorators may be a single string or something iterable.
        If no handler is registered, return False.
        If a handler is registered, return True.
        If more than one decorator is provided, decorators are tried
        in that order until a match is found. A return
        of False indicates no match.
        '''
        return self._handle(True, name, decorators, *args, **kwargs)

    def can_handle(self, name, decorators, *args, **kwargs):
        '''
        Like handle, but only returns whether the action would be handled.
        '''
        return self._handle(False, name, decorators, *args, **kwargs)

    def commands(self, decorators=None):
        '''
        Return a dict of name:func pairs. If decorators is None,
        returns everything. If decorators is a string, returns
        only those items decorated with that string. Otherwise,
        returns items whose decorators are in the given decorators
        (assumes something like list, set, tuple, etc).
        '''
        ret = dict()
        for name, ci in self._commands.items():
            if decorators is None:
                pass
            elif isinstance(decorators, str):
                if ci.decorator != decorators:
                    continue
            else:
                if ci.decorator not in decorators:
                    continue
            ret[name] = ci.func
        return ret

    def itemfuncs(self):
        '''
        Return a dict of item_name : func
        '''
        return {ci.decorator : ci.func for ci in self._commands.values()}

class _Item():
    '''
    A single decorated call managed by Command
    '''
    def __init__(self, decorator, func, printable=False, printable_raw=False):
        self.decorator = decorator
        self.func = func
        self.printable = printable
        self.printable_raw = printable_raw
        self.name = self.func.__name__

    def __repr__(self):
        return "%s(%r, %r, printable=%r, printable_raw=%r)" % (type(self).__name__, self.decorator, self.func, self.printable, self.printable_raw)

    DEBUG_NAMESPACE = False

    def getclass(self):
        '''
        Return the class of the decorated func. Returns None if
        this is a top-level function.
        '''
        kls = None
        members = inspect.getmembers(self.func)
        g = dict() # global namespace in which self.func was defined
        for m in members:
            if m[0] == '__globals__':
                g = m[1]
                break
        qns = self.func.__qualname__.split('.')
        if len(qns) > 1:
            kls = [g[qns[0]]] # use a list for debugging
            if not isinstance(kls[0], (type,)):
                raise RuntimeError("attempt to perform decorated handle on item not in the global namespace")
            for qn in qns[1:-1]:
                try:
                    kls.append(getattr(kls[-1], qn))
                    if not isinstance(kls[-1], (type,)):
                        raise RuntimeError("attempt to perform decorated handle on item not in the global namespace")
                except AttributeError as exc:
                    if self.DEBUG_NAMESPACE:
                        logging.basicConfig(format="%(message)s", stream=sys.stderr)
                        logger = logging.getLogger()
                        logger.error("ERROR: %s.getclass\n"
                                     " members\n%s\n"
                                     " qns %s\n"
                                     " qn %s\n"
                                     " kls %s\n%s",
                                     type(self).__name__,
                                     '\n'.join(['   '+x for x in pprint.pformat(members).splitlines()]),
                                     qns,
                                     qn,
                                     kls, '\n'.join(['   '+x for x in pprint.pformat(inspect.getmembers(kls[-1])).splitlines()]))
                    raise RuntimeError("attempt to perform decorated handle on item not in the global namespace") from exc
            return kls[-1]
        return None
