#!/usr/bin/env python3
#
# laaso/_paths.py
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
'''
Support for locating filesystem contents

Environment variables:
  LAASO_REPO_ROOT - use this as the effective root of the LaaSO repo
  LAASO_SUBSCRIPTION_CONFIG - location of the src/config/testing_subscriptions.yaml equivalent
  LAASO_SUBSCRIPTION_NAME_SUBSTITUTIONS - override individual key/value pairs in toplevel subscription_name_substitutions dict
'''
import copy
import json
import os
import sys
import threading

import yaml

import laaso.base_defaults
from laaso.base_defaults import EXC_VALUE_DEFAULT
import laaso.onbox
from laaso.exceptions import (ApplicationExit,
                              RepoRootNotFoundError,
                              SubscriptionConfigNotFoundError,
                             )
import laaso.hydratorapp
import laaso.util

# Enabling _REPO_ROOT_SEARCH_SYSPATH tells repo_root_search
# to consider sys.path when looking for the root. This is typically
# disabled, but it is enabled by unit tests because they may
# be running in a pipeline.
_REPO_ROOT_SEARCH_PYTHONPATH = False

# Set this environment variable to a JSON-serialized dict.
# This dict is applied to subscription_name_substitutions
# when subscription_config_data is loaded.
# This is not applied to the cached contents to allow
# resetting with new values.
ENVIRON_SUBSCRIPTION_NAME_SUBSTITUTIONS = 'LAASO_SUBSCRIPTION_NAME_SUBSTITUTIONS'

class Paths():
    '''
    Manage finding/caching paths.
    This is expected to be a singleton in non-unit-testing environments.
    '''
    def __init__(self):
        self._repo_root_lock = threading.RLock()

        self._repo_root_path = None
        self._subscription_config_path = None
        self._subscription_config_data = None

    def reset(self, repo_root_path=None, subscription_config_filename='', subscription_config_data=None):
        '''
        Discard cached content. Useful for unit testing.
        Intentionally skips _subscription_config_data_apply_environ().
        '''
        with self._repo_root_lock:
            self._repo_root_path = repo_root_path
            self._subscription_config_path = None
            self._subscription_config_data = None
            if subscription_config_filename:
                self._subscription_config_path_set(subscription_config_filename)
            if subscription_config_data:
                assert self._subscription_config_path
                self._subscription_config_data_set(subscription_config_data)

    ######################################################################
    # repo root

    def _repo_root_search(self):
        '''
        Make a best-effort to find the repo root.
        '''
        tmp = os.environ.get('LAASO_REPO_ROOT', '')
        if tmp:
            if self.repo_root_validate(tmp):
                return tmp
            # Cannot use user-specified directory. Do not search for others.
            return None
        # Common case: sitting at the root of the repo
        tmp = os.path.normpath(os.getcwd())
        if self.repo_root_validate(tmp):
            return '.'
        # We could be running in the hydrator repo
        if laaso.hydratorapp.HYDRATOR_APP and self.repo_root_hydrator_validate(tmp):
            return '.'
        in_venv = bool(self.venv)
        if in_venv:
            # We may be in a subdir in the repo. Walk up the tree looking
            # for a valid directory. Do not cross a symlink boundary.
            cwd = '.'
            if not os.path.islink(cwd) and (cwd != os.path.sep):
                parent = os.path.normpath(os.path.join(cwd, '..'))
                while parent and os.path.isdir(parent) and (not os.path.islink(parent)):
                    tmp = os.path.normpath(parent)
                    if self.repo_root_validate(tmp):
                        return tmp
                    if laaso.hydratorapp.HYDRATOR_APP and self.repo_root_hydrator_validate(tmp):
                        return tmp
                    parent = os.path.join(parent, '..')
        if _REPO_ROOT_SEARCH_PYTHONPATH:
            for p in sys.path:
                if self.repo_root_validate(p):
                    return p
        return None

    @property
    def repo_root(self):
        '''
        Getter for path to the root of the repo.
        Note that this can return None. The result is not
        cached in that case.
        '''
        with self._repo_root_lock:
            if self._repo_root_path is None:
                self._repo_root_path = self._repo_root_search()
            return self._repo_root_path

    def repo_root_path(self, *args):
        '''
        Return path adjusted relative to the root of the repo.
        args are path components - as in os.path.join().
        '''
        if args:
            path = os.path.join(*args)
            if path.startswith(os.path.sep):
                # path is absolute - ignore self.repo_root
                return path
        repo_root = self.repo_root
        return self._repo_root_path_generate(repo_root, *args)

    @staticmethod
    def _repo_root_path_generate(repo_root, *args):
        '''
        Return a path relative to the given repo_root
        '''
        if repo_root is None:
            raise RepoRootNotFoundError("cannot locate repo root")
        if not args:
            return repo_root
        ret = os.path.join(repo_root, *args)
        pf = '.' + os.path.sep
        if ret.startswith(pf) and (len(ret) > len(pf)):
            return ret[len(pf):]
        return ret

    def laaso_repo_path(self, path_in_repo, path_out_of_repo):
        '''
        Given paths in and out of a repo, determine which is
        applicable and return it. If the path cannot be located,
        return None.
        '''
        if path_in_repo is not None:
            try:
                tmp = self.repo_root_path(path_in_repo)
                if os.path.exists(tmp):
                    return tmp
                # Fall through to use path_out_of_repo
            except RepoRootNotFoundError:
                pass
        if path_out_of_repo is None:
            return None
        if os.path.exists(path_out_of_repo):
            return path_out_of_repo
        return None

    @staticmethod
    def repo_root_validate(path):
        '''
        Determine if path is a repo root.
        Does not depend on git. Uses knowledge of what a repo "looks like".
        '''
        if not isinstance(path, str):
            return False
        if not os.path.isdir(path):
            return False
        for d in ('build', 'doc', 'image_descs', 'laaso', 'src'):
            if not os.path.isdir(os.path.join(path, d)):
                return False
        if not os.path.isdir(os.path.join(path, 'src', 'ansible')):
            return False
        for f in ('.ansible-lint', '.gitignore', 'pylintrc'):
            if not os.path.isfile(os.path.join(path, f)):
                return False
        if not os.path.isfile(os.path.join(path, 'laaso', 'common.py')):
            return False
        return True

    # Files to check for in repo_root_hydrator_validate()
    REPO_ROOT_HYDRATOR_FILES = ('laaso/blobcache.py',
                                'laaso/common.py',
                                'laaso/hydrator.py',
                                'laaso/hydratorapp.py',
                                'laaso/hydratorstats.py',
                               )

    @classmethod
    def repo_root_hydrator_validate(cls, path):
        '''
        Check if we are in the hydrator repo.
        '''
        if not isinstance(path, str):
            return False
        if not os.path.isdir(path):
            return False
        if not os.path.isdir(os.path.join(path, 'laaso')):
            return False
        for f in cls.REPO_ROOT_HYDRATOR_FILES:
            if not os.path.isfile(os.path.join(path, f)):
                return False
        return True

    ######################################################################
    # venv

    @property
    def venv(self):
        '''
        Getter for the root of the virtualenv or None if we are not in a virtualenv
        '''
        venv = os.environ.get('VIRTUAL_ENV', '')
        if venv and os.path.isdir(venv):
            return venv
        return None

    ANSIBLE_COLLECTIONS_PATHS_ONBOX = '/usr/laaso/venv/ansible-collections'

    @property
    def venv_ansible_collections(self):
        '''
        Getter for where to find ansible collections
        '''
        tmp = os.environ.get('ANSIBLE_COLLECTIONS_PATHS', '')
        if tmp:
            return tmp
        if laaso.onbox.ONBOX:
            return self.ANSIBLE_COLLECTIONS_PATHS_ONBOX
        venv = self.venv
        if venv:
            return os.path.join(venv, 'ansible-collections')
        return None

    ######################################################################
    # subscription_config_filename

    @property
    def subscription_config_filename(self):
        '''
        Getter for subsciption config filename - eg src/config/testing_subscriptions.yaml
        '''
        with self._repo_root_lock:
            if self._subscription_config_path:
                return self._subscription_config_path
            self._subscription_config_path = self._subscription_config_find()
            return self._subscription_config_path

    @subscription_config_filename.setter
    def subscription_config_filename(self, path):
        '''
        Setter for subsciption config filename
        '''
        with self._repo_root_lock:
            if self._subscription_config_path:
                raise ValueError("subscription_config_filename already set")
            self._subscription_config_path_set(path)

    def subscription_config_filename_setdefault(self, path):
        '''
        Set subsciption config filename iff it is not already set.
        Returns the new effective value.
        '''
        with self._repo_root_lock:
            if not self._subscription_config_path:
                self._subscription_config_path_set(path)
            return self._subscription_config_path

    CONFIG_DEFAULT_TUPLE_REPO = ('src', 'config', 'testing_subscriptions.yaml')
    CONFIG_DEFAULT_PATH_REPO = os.path.join(*CONFIG_DEFAULT_TUPLE_REPO)

    CONFIG_DEFAULT_PATH_ONBOX = '/usr/laaso/etc/laaso_config.yaml'

    def _subscription_config_find(self):
        '''
        Return the subscription config path to use.
        Does not validate it when it is user-supplied rather than inferred.
        Does not consider self._subscription_config_path.
        '''
        path = os.environ.get('LAASO_SUBSCRIPTION_CONFIG', '')
        if path:
            return path
        if laaso.onbox.ONBOX:
            if os.path.isfile(self.CONFIG_DEFAULT_PATH_ONBOX):
                return self.CONFIG_DEFAULT_PATH_ONBOX
        else:
            try:
                path = self.repo_root_path(*self.CONFIG_DEFAULT_TUPLE_REPO)
            except RepoRootNotFoundError:
                path = None
            if path and os.path.isfile(path):
                return path
        raise SubscriptionConfigNotFoundError("cannot locate subscription configuration; try setting LAASO_SUBSCRIPTION_CONFIG")

    def _subscription_config_path_set(self, path):
        '''
        Set the subscription config filename
        Caller holds self._repo_root_lock
        '''
        with self._repo_root_lock:
            if not isinstance(path, str):
                raise TypeError("path must be str, not %s" % type(path))
            if not path:
                raise ValueError("invalid (empty) path")
            self._subscription_config_path = path

    ######################################################################
    # subscription_config_data

    # _scd_cache: cache the parsed contents by filename
    # This is primarily useful for supporting testing where
    # we repeatedly reset and reparse.
    _scd_cache = {} # key=path value=data

    def scd_cache_reset(self):
        '''
        Clear the contents of _scd_cache.
        This is not done as part of the common reset path (laaso.reset_caches())
        because doing so defeats the purpose of the cache.
        '''
        with self._repo_root_lock:
            self._scd_cache.clear()

    @property
    def subscription_config_data(self):
        '''
        Read, parse, and cache the subscription config file.
        '''
        with self._repo_root_lock:
            if self._subscription_config_data is not None:
                assert isinstance(self._subscription_config_data, dict)
                return self._subscription_config_data
            data = self._scd_cache.get(self.subscription_config_filename, None)
            if not isinstance(data, dict):
                try:
                    with open(self.subscription_config_filename, 'r') as f:
                        contents = f.read()
                except FileNotFoundError as exc:
                    raise SubscriptionConfigNotFoundError("subscription config file %r not found" % self.subscription_config_filename) from exc
                try:
                    data = yaml.safe_load(contents)
                except yaml.error.MarkedYAMLError as exc:
                    raise ApplicationExit(f"cannot parse {self.subscription_config_filename!r}: error line {exc.problem_mark.line} column {exc.problem_mark.column}") from exc
                except yaml.error.YAMLError as exc:
                    # yaml.error.YAMLError is more readable with str than repr
                    raise ApplicationExit(f"cannot parse {self.subscription_config_filename!r}: error {exc}") from exc
                if data is None:
                    # empty file - interpret it as an empty dict
                    data = dict()
                if not isinstance(data, dict):
                    raise ApplicationExit(f"content of subscription config file {self.subscription_config_filename!r} is not a dict")
                self._scd_cache[self.subscription_config_filename] = data
            # Always force a copy so that the cache never shares a ref with what we use here
            data = copy.deepcopy(data)
            self._subscription_config_data_apply_environ(data, self.subscription_config_filename)
            self._subscription_config_data_set(data)
            return self._subscription_config_data

    @staticmethod
    def _subscription_config_data_apply_environ(data:dict, filename:str):
        '''
        Apply environment settings to data that is about to become subscription_config_data.
        The caller has already deepcopied data, so we may freely modify it in-place.
        '''
        subscription_name_substitutions = os.environ.get(ENVIRON_SUBSCRIPTION_NAME_SUBSTITUTIONS, '{}')
        try:
            subscription_name_substitutions = json.loads(subscription_name_substitutions)
        except json.decoder.JSONDecodeError as exc:
            raise ApplicationExit(f"cannot parse {ENVIRON_SUBSCRIPTION_NAME_SUBSTITUTIONS}: {exc!r}") from exc
        if not (isinstance(subscription_name_substitutions, dict) and all(isinstance(key, str) for key in subscription_name_substitutions.keys())):
            raise ApplicationExit(f"invalid {ENVIRON_SUBSCRIPTION_NAME_SUBSTITUTIONS}")
        data_sns = data.setdefault('subscription_name_substitutions', dict())
        if not (isinstance(data_sns, dict) and all(isinstance(key, str) for key in data_sns.keys())):
            raise ApplicationExit(f"cannot parse {filename}: invalid subscription_name_substitutions")
        data_sns.update(subscription_name_substitutions)
        if not data_sns:
            data.pop('subscription_name_substitutions')

    def _subscription_config_data_set(self, data:dict):
        '''
        Use the provided data as the subscription config.
        Caller holds self._repo_root_lock.
        '''
        assert isinstance(data, dict)
        with self._repo_root_lock:
            assert self._subscription_config_path
            self._subscription_config_data = data

    ######################################################################
    # executables

    @staticmethod
    def is_executable_file(path):
        '''
        Return whether the given path is an executable file.
        '''
        # We ignore executable bits and declare victory if we find the file.
        # This is "good enough" at the moment. Permission checks can
        # be added later if needed.
        return os.path.isfile(path)

    @classmethod
    def exe_search(cls, name):
        '''
        Search $PATH for a file with the given name.
        Returns None if not found.
        '''
        assert os.path.sep not in name
        for directory in os.environ.get('PATH', '').split(':'):
            if directory:
                path = os.path.join(directory, name)
                if cls.is_executable_file(path):
                    return path
        return None

    @classmethod
    def exe_effective(cls, name):
        '''
        Given name (filename), return what a caller should use
        when executing a subprocess. When ONBOX, this first looks
        in the venv bin directory. In all cases, searches $PATH.
        Returns None for not found.
        '''
        if laaso.onbox.ONBOX:
            # Do not use self.venv / $VIRTUAL_ENV here - that's not set in the
            # case where we are executing a script and getting the virtualenv
            # via the shebang.
            path = os.path.join(laaso.base_defaults.LAASO_VENV_PATH, 'bin', name)
            if cls.is_executable_file(path):
                return path
        if cls.exe_search(name):
            # It's in $PATH, so we don't need to return an absolute path.
            return name
        return None

    @property
    def ansible_playbook_exe(self):
        '''
        Getter: path for ansible-playbook
        '''
        return self.exe_effective('ansible-playbook')

    ######################################################################
    # other paths

    CLUSTER_SKUS_DIR_ONBOX = '/usr/laaso/lib/amlfilesystem_skus'
    CLUSTER_SKUS_TUPLE_REPO = ('src', 'deploy_config', 'skus')

    @property
    def cluster_skus_dir(self) -> str:
        '''
        Path of directory containing cluster SKUs
        '''
        if laaso.onbox.ONBOX:
            return self.CLUSTER_SKUS_DIR_ONBOX
        return self.repo_root_path(*self.CLUSTER_SKUS_TUPLE_REPO)

    ######################################################################
    # helpers

    def subscription_config_dict_from_default_data(self, key, exc_value=EXC_VALUE_DEFAULT) -> dict:
        '''
        Wrapper for subscription_config_dict_from_data that uses
        the default file and data.
        '''
        with self._repo_root_lock:
            return self.subscription_config_dict_from_data(self.subscription_config_filename,
                                                           self.subscription_config_data,
                                                           key,
                                                           exc_value=exc_value)
    @staticmethod
    def subscription_config_dict_from_data(filename, data, key, exc_value=EXC_VALUE_DEFAULT) -> dict:
        '''
        Helper for things that build on subscription_config.
        filename is the name of the file from which data is loaded.
        data is subscription_config_data.
        data is assumed to be a dict.
        key is a key in the data dict that is expected to be a dict.
        Returns this dict, or an empty dict if not found.
        '''
        assert isinstance(data, dict)
        ret = data.get(key, dict())
        if not isinstance(ret, dict):
            raise exc_value(f"{key} in {filename} has type {type(ret)}; expected dict")
        return ret

    def subscription_config_list_from_default_data(self, key, exc_value=EXC_VALUE_DEFAULT) -> list:
        '''
        Wrapper for subscription_config_list_from_data that uses
        the default file and data.
        '''
        with self._repo_root_lock:
            return self.subscription_config_list_from_data(self.subscription_config_filename,
                                                           self.subscription_config_data,
                                                           key,
                                                           exc_value=exc_value)

    @staticmethod
    def subscription_config_list_from_data(filename, data, key, exc_value=EXC_VALUE_DEFAULT) -> list:
        '''
        Helper for things that build on subscription_config.
        filename is the name of the file from which data is loaded.
        data is subscription_config_data.
        data is assumed to be a dict.
        key is a key in the data dict that is expected to be a list.
        Returns this list, or an empty list if not found.
        '''
        assert isinstance(data, dict)
        lst = data.get(key, list())
        if not isinstance(lst, list):
            raise exc_value(f"{key} in {filename} has type {type(lst)}; expected list")
        return lst

    @property
    def managed_subscription_ids(self):
        '''
        Generate and return a tuple of managed subscription_ids.
        '''
        subscriptions = self.subscription_config_list_from_default_data('subscriptions')
        # explicitly generate a list and return a tuple to avoid returning a generator
        return tuple(x.get('subscription_id', '') for x in subscriptions if x)

    def subscription_config_data_for_one_subscription(self, subscription_id, exc_value=EXC_VALUE_DEFAULT) -> dict:
        '''
        Return the config for one subscription_id from the config section.
        '''
        normalized_id = laaso.util.uuid_normalize(subscription_id, key='subscription_id', exc_value=None)
        if not normalized_id:
            raise exc_value(f"invalid subscription_id {subscription_id}")
        subscriptions_data = self.subscription_config_list_from_default_data('subscriptions', exc_value=exc_value)
        for subscription_data in subscriptions_data:
            if isinstance(subscription_data, dict):
                sd_subscription_id = laaso.util.uuid_normalize(subscription_data.get('subscription_id', ''), exc_value=None)
                if sd_subscription_id == normalized_id:
                    return subscription_data
        return dict()

paths = Paths()
