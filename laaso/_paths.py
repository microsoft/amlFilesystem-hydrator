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
'''
import os
import sys
import threading

import yaml

from laaso.base_defaults import EXC_VALUE_DEFAULT
import laaso.onbox
from laaso.exceptions import (ApplicationExit,
                              RepoRootNotFoundError,
                             )
import laaso.hydratorapp
import laaso.util

# Enabling _REPO_ROOT_SEARCH_SYSPATH tells repo_root_search
# to consider sys.path when looking for the root. This is typically
# disabled, but it is enabled by unit tests because they may
# be running in a pipeline.
_REPO_ROOT_SEARCH_PYTHONPATH = False

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
        in_venv = bool(os.environ.get('VIRTUAL_ENV', ''))
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

    CONFIG_DEFAULT_TUPLE = ('src', 'config', 'testing_subscriptions.yaml')
    CONFIG_DEFAULT_PATH = os.path.join(*CONFIG_DEFAULT_TUPLE)

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
            path = '/usr/laaso/etc/laaso_config.yaml'
            if os.path.isfile(path):
                return path
        try:
            path = self.repo_root_path(*self.CONFIG_DEFAULT_TUPLE)
        except RepoRootNotFoundError:
            path = None
        if path and os.path.isfile(path):
            return path
        raise ApplicationExit("cannot locate subscription configuration; try setting LAASO_SUBSCRIPTION_CONFIG")

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

    @property
    def subscription_config_data(self):
        '''
        Read, parse, and cache the subscription config file.
        '''
        with self._repo_root_lock:
            if self._subscription_config_data is not None:
                assert isinstance(self._subscription_config_data, dict)
                return self._subscription_config_data
            try:
                with open(self.subscription_config_filename, 'r') as f:
                    contents = f.read()
            except FileNotFoundError as exc:
                raise ApplicationExit("subscription config file %r not found" % self.subscription_config_filename) from exc
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
            self._subscription_config_data_set(data)
            return self._subscription_config_data

    def _subscription_config_data_set(self, data):
        '''
        Use the provided data as the subscription config.
        Caller holds self._repo_root_lock.
        '''
        with self._repo_root_lock:
            assert self._subscription_config_path
            if not isinstance(data, dict):
                raise ApplicationExit("content of subscription config file %r is not a dict" % self.subscription_config_filename)
            self._subscription_config_data = data

    ######################################################################
    # helpers

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
        Generate and return a set of managed subscription_ids.
        '''
        subscriptions = self.subscription_config_list_from_default_data('subscriptions')
        ret = {x.get('subscription_id', '') for x in subscriptions}
        ret.discard('')
        return frozenset(ret)

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

if __name__ == "__main__":
    print("subscription_config_data:\n%s" % laaso.util.indent_pformat(paths.subscription_config_data))
    print("repo_root=%r" % paths.repo_root)
    print("subscription_config_filename=%r" % paths.subscription_config_filename)
    raise SystemExit(0)
