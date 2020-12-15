#!/usr/bin/env python3
#
# laaso/hsmimport.py
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
'''
Wrapper to import a file into Lustre HSM that just exposes the
necessary fields.
'''

import ctypes
import sys
import time

import laaso.common
from laaso.exceptions import ApplicationExit
from laaso.lustre_ctypes import (CTimespec,
                                 CStat,
                                 CLustreFid,
                                 LibLustreApi)

class HSMDefaults():
    '''
    Specify defaults for import.
    '''
    MODE = 0o666
    UID = 0
    GID = 0
    SIZE = 0
    ARCHIVEID = 1

    NOT_INIT = 1

class HSMImport():
    '''
    Wrapper for Lustre's hsm_import for importing a file.
    This assumes that the entire path up to the file's parent already exists.
    '''

    def __init__(self,
                 abspath,
                 mode=HSMDefaults.MODE,
                 uid=HSMDefaults.UID,
                 gid=HSMDefaults.GID,
                 size=HSMDefaults.SIZE,
                 mtime=CTimespec(int(time.time()), 0),
                 archiveid=HSMDefaults.ARCHIVEID):
        '''
        Init function.  Allows setting the attributes, or take the defaults.
        '''
        self.abspath = abspath
        self.stat = CStat()
        self.stat.st_mode = mode
        self.stat.st_uid = uid
        self.stat.st_gid = gid
        self.stat.st_size = size
        self.stat.st_atim = mtime
        self.stat.st_mtim = mtime
        self.stat.st_ctim = mtime
        self.archiveid = archiveid

        self.liblustreapi = LibLustreApi.liblustreapi

    def do_it(self, fid):
        '''
        Do the import.
        fid: out parameter of type CLustreFid
        Returns an int.
        '''
        if not self.liblustreapi:
            return HSMDefaults.NOT_INIT
        return self.liblustreapi.llapi_hsm_import(ctypes.c_char_p(self.abspath.encode('utf-8')),
                                                  self.archiveid,
                                                  ctypes.pointer(self.stat),
                                                  0, 0, 0, 0,        # striping parameters: not implemented
                                                  ctypes.c_char_p(), # pool_name: none for LaaSO (NULL)
                                                  ctypes.pointer(fid))

TEST_DESCRIPTION = """
Test program to import a single file into the Lustre namespace.
The entire path up to the parent directory of the file must already exist.
"""

class HSMImportFile(laaso.common.Application):
    '''
    Test application to import a single file.
    '''
    def __init__(self,
                 abspath,
                 mode=oct(HSMDefaults.MODE),
                 uid=HSMDefaults.UID,
                 gid=HSMDefaults.GID,
                 size=HSMDefaults.SIZE,
                 mtime=time.time(),
                 test=False,
                 **kwargs):
        '''
        Constructor.
        '''
        super().__init__(**kwargs)
        if not test:
            LibLustreApi.init_once()
        self.abspath = abspath
        self.mode = int(mode, 8)
        self.uid = uid
        self.gid = gid
        self.size = size
        self.mtime = CTimespec(int(mtime), 0)

        self.hsmimport = HSMImport(abspath=self.abspath,
                                   mode=self.mode,
                                   uid=self.uid,
                                   gid=self.gid,
                                   size=self.size,
                                   mtime=self.mtime)

    @classmethod
    def main_add_parser_args(cls, ap_parser):
        '''
        Inherited from Application class.  Add parser args.
        '''
        super().main_add_parser_args(ap_parser)
        ap_parser.description = TEST_DESCRIPTION

        ap_parser.add_argument('abspath', type=str, help='absolute path of the file to import')

        ap_parser.add_argument("-m", "--mode", type=str, default=oct(HSMDefaults.MODE),
                               help="mode bits to set for the file in octal format (ex: 644)")
        ap_parser.add_argument("-u", "--uid", type=int, default=HSMDefaults.UID, help="uid for the new file")
        ap_parser.add_argument("-g", "--gid", type=int, default=HSMDefaults.GID, help="guid for the new file")
        ap_parser.add_argument("-s", "--size", type=int, default=HSMDefaults.SIZE, help="size for the new file")
        ap_parser.add_argument("-t", "--mtime", type=int, default=time.time(), help="mtime seconds-since-epoch for the new file")
        ap_parser.add_argument("--test", action="store_true", help="testing mode, don't call Lustre library")

    def main_execute(self):
        '''
        Main routine for HSMImportFile.
        '''
        fid_out = CLustreFid()
        rc = self.hsmimport.do_it(fid_out)
        if rc != 0:
            self.logger.error("Error importing %s, rc=%d", self.abspath, rc)
            raise ApplicationExit(rc)
        self.logger.info("Imported %s, fid=[0x%x:0x%x:0x%x], rc=%d",
                         self.abspath, fid_out.f_seq, fid_out.f_oid, fid_out.f_ver, rc)
        raise ApplicationExit(0)

if __name__ == "__main__":
    HSMImportFile.main(sys.argv[1:])
    raise ApplicationExit(1)
