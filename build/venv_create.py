#
# build/venv_create.py
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
'''
This script creates a Python virtualenv.
The project Python code expects to execute in a virtualenv
created by this script. Because this bootstraps the
virtualenv, it must not rely on importing other project modules.

The Python interpreter executing this script is installed in the virtualenv.
To control the version installed in the venv, specify the interpreter
explicitly when running this script. As a reminder to do that,
this script is not executable and does not have a shebang.
'''
import argparse
import errno
import glob
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

class VenvCreate():
    '''
    Encapsulate the functionality of building the virtualenv
    '''

    def __init__(self, venv_directory, requirements, exclude):
        self.venv_directory = os.path.abspath(venv_directory)
        self.requirements = os.path.abspath(requirements)
        self.exclude = exclude

        self.exclude_compiled = [re.compile(x) for x in self.exclude] if self.exclude else list()
        self.python_exe = sys.executable
        self.python_name = "python%s.%s" % (sys.version_info.major, sys.version_info.minor)
        self.pip_exe = None
        self.site_packages = None

    def requirement_is_excluded(self, req):
        '''
        Return whether the given requirement is excluded.
        req might be something like any of these:
            some-package
            some-package==1.0.0
            some_package>=9.0.0,<=11.0.0
        '''
        for ex in self.exclude_compiled:
            if ex.search(req):
                return True
        return False

    @classmethod
    def main(cls, cmd_args):
        '''
        Command-line entrypoint
        '''
        ap_parser = argparse.ArgumentParser(allow_abbrev=False)
        ap_parser.add_argument('venv_directory', type=str,
                               help='directory for virtualenv')
        ap_parser.add_argument('requirements', type=str,
                               help='path to requirements file')
        ap_parser.add_argument('--exclude', type=str, nargs='*',
                               help='exclude packages matching these regexps')
        ap_args = ap_parser.parse_args(args=cmd_args)
        app = cls(ap_args.venv_directory, ap_args.requirements, ap_args.exclude)
        app.main_execute()

    def main_execute(self):
        '''
        Do the real work
        '''
        if os.path.exists(self.venv_directory):
            raise Exception("self.venv_directory %r exists" % self.venv_directory)

        if not os.path.isfile(self.requirements):
            raise Exception("self.requirements %r does not exist or is not a file" % self.requirements)

        ############################################################
        # Generate the venv

        self.run_cmd([self.python_exe, '-B', '-m', 'venv', self.venv_directory])

        self.python_exe = os.path.join(self.venv_directory, 'bin', 'python')
        self.pip_exe = os.path.join(self.venv_directory, 'bin', 'pip')
        self.site_packages = os.path.join(self.venv_directory, 'lib', self.python_name, 'site-packages')

        ############################################################
        # Install requirements

        self.run_cmd([self.python_exe, '-m', 'pip', 'install', '--upgrade', 'pip', 'wheel'])

        if self.exclude_compiled:
            with tempfile.TemporaryDirectory() as tmpdir:
                req_path = os.path.join(tmpdir, os.path.split(self.requirements)[1])
                with open(req_path, 'w') as req_out:
                    with open(self.requirements, 'r') as req_in:
                        for line in req_in:
                            if line.lstrip().startswith('#'):
                                # ignore comment
                                continue
                            if self.requirement_is_excluded(line.rstrip()):
                                continue
                            req_out.write(line)
                self.run_cmd([self.pip_exe, '--no-color', '--use-feature=2020-resolver', 'install', '-r', req_path])
        else:
            self.run_cmd([self.pip_exe, '--no-color', '--use-feature=2020-resolver', 'install', '-r', self.requirements])

        if not os.path.isdir(self.site_packages):
            raise Exception("self.site_packages %r does not exist or is not a directory" % self.site_packages)

        ansible_collections = os.path.join(self.site_packages, 'ansible_collections')

        ############################################################
        # Remove unused subdirs in ansible_collections

        # collkeep: collections to keep; others are removed
        collkeep = {'ansible',
                    'community',
                   }
        for path in glob.iglob("%s/**" % ansible_collections, recursive=False):
            if os.path.split(path)[1] in collkeep:
                continue
            self.remove(path)

        ############################################################
        # Remove unused requirements.txt

        for path in glob.iglob("%s/**/requirements.txt" % ansible_collections, recursive=True):
            self.remove(path)

        ############################################################
        # All done

        raise SystemExit(0)

    @staticmethod
    def remove(path):
        '''
        Remove the target path
        '''
        if not os.path.exists(path):
            return
        if os.path.isdir(path):
            shutil.rmtree(path)
            return
        try:
            os.unlink(path)
        except OSError as exc:
            if exc.errno != errno.ENOENT:
                raise

    @staticmethod
    def run_cmd(cmdargs):
        '''
        Run the given command
        '''
        print("command: %s" % ' '.join([shlex.quote(x) for x in cmdargs]))
        subprocess.check_call(cmdargs, stdin=subprocess.DEVNULL, shell=False)

if __name__ == "__main__":
    VenvCreate.main(sys.argv[1:])
    raise SystemExit(1)
