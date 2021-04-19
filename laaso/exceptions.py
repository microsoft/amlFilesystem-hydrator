#
# laaso/exceptions.py
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
'''
Exception classes shared across laaso modules
'''
import copy

class ApplicationException(Exception):
    '''
    Base class for application exceptions
    '''

class CommandFailedBase(ApplicationException):
    '''
    Base class for command failures. These are logically equivalent
    to various subprocess errors, except they come through child-process
    execution paths defined by LaaSO code.
    '''
    def __init__(self, txt, *args, **kwargs):
        super().__init__(txt)
        self.txt = txt
        self.args = copy.deepcopy(args)
        self.kwargs = copy.deepcopy(kwargs)

    def __str__(self):
        return "%s" % self.txt.strip()

    def __repr__(self):
        ret = "%s(%r" % (type(self).__name__, self.txt.strip())
        if self.args:
            ret += ', '
            ret += ', '.join([repr(x) for x in self.args])
        if self.kwargs:
            ret += ', '
            ret += ', '.join(["%s=%r" % (k, v) for k, v in self.kwargs.items()])
        ret += ')'
        return ret

class CommandFailed(CommandFailedBase):
    '''
    A child process command failed. Includes the exit_status.
    '''
    def __init__(self, exit_status, command, env, *args, **kwargs):
        self.exit_status = exit_status
        self.command = command
        self.env = env
        txt = "command failed (exit_status=%r)" % self.exit_status
        super().__init__(txt, exit_status, command, env, *args, **kwargs)
        self.args = copy.deepcopy(args)
        self.kwargs = copy.deepcopy(kwargs)

class CommandTimeout(CommandFailedBase):
    '''
    A child process command timed-out.
    '''
    def __init__(self, cmd, timeout, *args, **kwargs):
        txt = "Command %r timed out after %r" % (cmd, timeout)
        super().__init__(txt, cmd, timeout, timeout, *args, **kwargs)
        self.exit_status = 1
        self.txt = txt
        self.cmd = cmd
        self.timeout = timeout
        self.args = copy.deepcopy(args)
        self.kwargs = copy.deepcopy(kwargs)

class ApplicationExit(ApplicationException):
    '''
    This is interpreted as SystemExit, but it inherits from ApplicationException
    and not SystemExit. That makes it part of the Exception hierarchy
    and not BaseException. The intent is to use this as a replacement
    for SystemExit to simplify multithreaded orchestration.
    '''
    def __init__(self, code):
        self.code = code
        super().__init__(str(self.code))

    def __repr__(self):
        return "%s(%r)" % (type(self).__name__, self.code)

    def __str__(self):
        return str(self.code)

class ApplicationExitWithNote(ApplicationExit):
    '''
    Subclass of ApplicationExit with an extra note attached.
    Subclassed rather than making note a kwarg to simplify
    exception handling and chaining.
    '''
    def __init__(self, code, note):
        super().__init__(code)
        self.note = note or ''

    def __repr__(self):
        if self.note:
            return "%s(%r, note=%r)" % (type(self).__name__, self.code, self.note)
        return "%s(%r)" % (type(self).__name__, self.code)

    def __str__(self):
        if self.note:
            return "%s [%s]" % (self.code, self.note)
        return str(self.code)

class ResourceGroupMayNotBeDeleted(ApplicationExit):
    '''
    Policy forbids resource group delete
    '''
    # No specialization

class SchemaError(ApplicationException):
    '''
    The datastructure provided does not match the schema definition.
    This error is raised when validating data against a schema.
    Construting a schema may raise other errors such as TypeError
    or ValueError.
    '''
    # no specialization here

class AnsiblePlaybookFailed(ApplicationException):
    '''
    Ansible playbook execution failed
    '''
    def __init__(self, playbook, inventory, cmd, env):
        self.playbook = playbook
        self.inventory = inventory
        self.cmd = cmd
        self.env = env
        super().__init__("ansible playbook %r failed" % self.playbook)

    def __repr__(self):
        return "%s(%r, %r, %r, %r)" % (type(self).__name__, self.playbook, self.inventory, self.cmd, self.env)

    def __str__(self):
        return "playbook %r failed on inventory %r" % (self.playbook, self.inventory)

class ShellCommandException(ApplicationException):
    '''
    Error executing a shell command.
    '''
    # no specialization

class RepoRootNotFoundError(ApplicationException):
    '''
    Cannot locate repo root
    '''
    # no specialization here

class ContainerNameInvalidException(ValueError):
    '''
    container_name is not valid
    '''
    # no specialization here

class QueueNameInvalidException(ValueError):
    '''
    queue_name is not valid
    '''
    # no specialization here

class DevUserUnknownException(ApplicationException):
    '''
    Dev user name is unrecognized. See laaso.dev_users.DevUser.dev_user_get().
    '''
    def __init__(self, txt, name):
        super().__init__(txt)
        self.name = name

class SubscriptionConfigNotFoundError(ApplicationExit):
    '''
    Special case of ApplicationExit used to indicate that
    the exit reason is that the subscription config file
    is not found.
    '''
    # no specialization here
