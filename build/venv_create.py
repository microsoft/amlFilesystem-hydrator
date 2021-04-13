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

    def __init__(self,
                 venv_directory,
                 requirements,
                 ansible_galaxy_requirements,
                 exclude,
                 force):
        self.venv_directory = os.path.abspath(venv_directory)
        self.requirements = os.path.abspath(requirements)
        self.exclude = exclude
        self.force = bool(force)

        self.ansible_galaxy_requirements = ''
        if ansible_galaxy_requirements:
            if ansible_galaxy_requirements.startswith(os.path.sep):
                self.ansible_galaxy_requirements = ansible_galaxy_requirements
            else:
                pd = os.path.split(self.requirements)[0]
                self.ansible_galaxy_requirements = os.path.join(pd, ansible_galaxy_requirements)

        self.ansible_collections_directory = ''
        self.ansible_collections_exe = ''
        self.ansible_galaxy_exe = ''
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

    ANSIBLE_GALAXY_REQUIREMENTS_DEFAULT = os.environ.get('LAASO_VENV_CREATE_ANSIBLE_GALAXY_REQUIREMENTS', os.path.join('..', 'src', 'ansible', 'requirements', 'requirements.yaml'),)

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
        ap_parser.add_argument('--ansible_galaxy_requirements', type=str, default=cls.ANSIBLE_GALAXY_REQUIREMENTS_DEFAULT,
                               help='path relative to requirements file')
        ap_parser.add_argument('--exclude', type=str, nargs='*',
                               help='exclude packages matching these regexps')
        ap_parser.add_argument('--force', action='store_true',
                               help='remove venv directory if it exists')
        ap_args = ap_parser.parse_args(args=cmd_args)
        app = cls(ap_args.venv_directory,
                  ap_args.requirements,
                  # optional args
                  ap_args.ansible_galaxy_requirements,
                  ap_args.exclude,
                  ap_args.force)
        app.main_execute()

    def main_execute(self):
        '''
        Do the real work
        '''
        if self.force:
            if os.path.islink(self.venv_directory):
                os.unlink(self.venv_directory)
            elif os.path.isdir(self.venv_directory):
                shutil.rmtree(self.venv_directory)
            elif os.path.exists(self.venv_directory):
                raise Exception(f"self.venv_directory {self.venv_directory!r} exists as a non-directory; not removing it")

        if os.path.exists(self.venv_directory):
            raise Exception(f"self.venv_directory {self.venv_directory!r} exists")

        if not os.path.isfile(self.requirements):
            raise Exception(f"self.requirements {self.requirements!r} does not exist or is not a file")

        if self.ansible_galaxy_requirements and (not os.path.isfile(self.ansible_galaxy_requirements)):
            raise Exception(f"ansible_galaxy_requirements {self.ansible_galaxy_requirements!r} does not exist or is not a file")

        ############################################################
        # Generate the venv

        self.run_cmd([self.python_exe, '-B', '-m', 'venv', self.venv_directory])

        self.python_exe = os.path.join(self.venv_directory, 'bin', 'python')
        self.pip_exe = os.path.join(self.venv_directory, 'bin', 'pip')
        self.site_packages = os.path.join(self.venv_directory, 'lib', self.python_name, 'site-packages')

        if self.ansible_galaxy_requirements:
            self.ansible_galaxy_exe = os.path.join(self.venv_directory, 'bin', 'ansible-galaxy')
            self.ansible_collections_directory = os.path.join(self.venv_directory, 'ansible-collections')

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
                self.run_cmd([self.pip_exe, '--no-color', 'install', '-r', req_path])
        else:
            self.run_cmd([self.pip_exe, '--no-color', 'install', '-r', self.requirements])

        if not os.path.isdir(self.site_packages):
            raise Exception("self.site_packages %r does not exist or is not a directory" % self.site_packages)

        ansible_collections_site_packages = os.path.join(self.site_packages, 'ansible_collections')

        ############################################################
        # Install ansible-galaxy collections

        if self.ansible_galaxy_requirements:
            add_env = {'ANSIBLE_COLLECTIONS_PATHS' : self.ansible_collections_directory}
            self.run_cmd([self.ansible_galaxy_exe, 'collection', 'install', '-p', self.ansible_collections_directory, '-r', self.ansible_galaxy_requirements], add_env=add_env)

        ############################################################
        # Create links to dbus-related modules.
        # We can't add /usr/lib/python3/dist-packages directly to our path
        # because several packages shadow versions in our virtualenv.
        dist_packages = '/usr/lib/python3/dist-packages'
        lnk_base = f'{self.venv_directory}/lib/python3.7/site-packages'
        links = ['_dbus_bindings.cpython-37m-x86_64-linux-gnu.so',
                 '_dbus_glib_bindings.cpython-37m-x86_64-linux-gnu.so',
                 'dbus',
                 'gi']
        for link in links:
            os.symlink(f'{dist_packages}/{link}', f'{lnk_base}/{link}')

        ############################################################
        # Remove unused subdirs in ansible_collections_site_packages -- needed when
        # we install all of ansible and not just ansible-base

        # collkeep: collections to keep; others are removed
        collkeep = {'ansible',
                    'community',
                   }
        for path in glob.iglob("%s/**" % ansible_collections_site_packages, recursive=False):
            if os.path.split(path)[1] in collkeep:
                continue
            self.remove(path)

        ############################################################
        # Remove unused requirements.txt

        self.remove_matching_iglob(f"{ansible_collections_site_packages}/**/*requirements.txt", recursive=True)
        if self.ansible_collections_directory:
            self.remove_matching_iglob(f"{self.ansible_collections_directory}/**/*requirements.txt", recursive=True)

        ############################################################
        # All done

        raise SystemExit(0)

    def remove_matching_iglob(self, pathname, **kwargs):
        '''
        Remove entries matching glob.iglob(pathname)
        '''
        if pathname:
            for path in glob.iglob(pathname, **kwargs):
                self.remove(path)

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
    def run_cmd(cmdargs, add_env=None):
        '''
        Run the given command
        '''
        print("command: %s" % ' '.join([shlex.quote(x) for x in cmdargs]))
        env = dict(os.environ)
        if add_env:
            env.update(add_env)
        subprocess.check_call(cmdargs, stdin=subprocess.DEVNULL, shell=False, env=env)

if __name__ == "__main__":
    VenvCreate.main(sys.argv[1:])
    raise SystemExit(1)
