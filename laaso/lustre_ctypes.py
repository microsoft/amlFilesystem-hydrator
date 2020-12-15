#!/usr/bin/env python3
#
# laaso/lustre_ctypes.py
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
'''
Implement various liblustreapi calls in Python.
'''

import ctypes

class CTimespec(ctypes.Structure):
    '''
    Encapsulate a C timespec struct.
    '''
    _fields_ = [('tv_sec', ctypes.c_long),
                ('tv_nsec', ctypes.c_long)]

class CStat(ctypes.Structure):
    '''
    Encapsulate a C stat struct.
    '''
    _fields_ = [('st_dev', ctypes.c_ulong),
                ('st_ino', ctypes.c_ulong),
                ('st_nlink', ctypes.c_ulong),
                ('st_mode', ctypes.c_uint),
                ('st_uid', ctypes.c_uint),
                ('st_gid', ctypes.c_uint),
                ('__pad0', ctypes.c_int),
                ('st_rdev', ctypes.c_ulong),
                ('st_size', ctypes.c_long),
                ('st_blksize', ctypes.c_long),
                ('st_blocks', ctypes.c_long),
                ('st_atim', CTimespec),
                ('st_mtim', CTimespec),
                ('st_ctim', CTimespec),
                ('__glibcreserved', ctypes.c_long)]

class CLustreFid(ctypes.Structure):
    '''
    Encapsulate a Lustre fid.
    '''
    _fields_ = [('f_seq', ctypes.c_ulong),
                ('f_oid', ctypes.c_uint),
                ('f_ver', ctypes.c_uint)]

class LibLustreApi():
    '''
    Encapsulate liblustreapi.
    '''
    liblustreapi = None

    @staticmethod
    def init_once():
        '''
        Initialize liblustreapi calls.
        Must call this to load the C library before using it.
        '''
        if LibLustreApi.liblustreapi:
            return
        LibLustreApi.liblustreapi = ctypes.CDLL("liblustreapi.so")

        # hsm_import: used by hydrator
        LibLustreApi.liblustreapi.llapi_hsm_import.argtypes = [ctypes.c_char_p,              # dst abspath
                                                               ctypes.c_int,                 # archiveid
                                                               ctypes.POINTER(CStat),        # stat struct for settings attrs
                                                               ctypes.c_ulonglong,           # stripe_size
                                                               ctypes.c_int,                 # stripe_offset
                                                               ctypes.c_int,                 # stripe_count
                                                               ctypes.c_int,                 # stripe_pattern
                                                               ctypes.c_char_p,              # pool_name
                                                               ctypes.POINTER(CLustreFid)]   # newfid (lu_fid struct)

        # fid2path: can convert a Lustre fid to a path
        LibLustreApi.liblustreapi.llapi_fid2path.argtypes = [ctypes.c_char_p,                     # device
                                                             ctypes.c_char_p,                     # fidstr
                                                             ctypes.c_char_p,                     # path (out)
                                                             ctypes.c_int,                        # pathlen
                                                             ctypes.POINTER(ctypes.c_ulonglong),  # recno
                                                             ctypes.POINTER(ctypes.c_int)]        # linkno
