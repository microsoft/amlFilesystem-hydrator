#!/usr/bin/env python3
#
# laaso/hydratorstats.py
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
'''
Stats implementation for the Hydrator.
'''

import datetime
import json
import os
import threading
import time
import yaml

from filelock import FileLock

from laaso.blobcache import BlobAttributes
from laaso.exceptions import ApplicationExit

HYDRATOR_METRICS_FILE_PATH="/var/tmp/hydrator_stats.yaml"
HYDRATOR_METRICS_LOCKFILE_PATH="/var/lock/hydrator_stats.lock"

class Stat():
    '''
    Basic stat format.  Supports numerical stats.
    '''
    def __init__(self, friendly, val):
        '''
        friendly - human friendly name of the stat for printing
        val - initial value of the stat
        '''
        self.friendly = friendly
        self.val = val

    def inc(self):
        '''
        Add one to the stat.
        '''
        self.set(self.val + 1)

    def dec(self):
        '''
        Add one to the stat.
        '''
        self.set(self.val - 1)

    def set(self, new_val):
        '''
        Set the stat to a specific value.
        '''
        self.val = new_val

    def add(self, val):
        '''
        Add a value to a stat.
        '''
        self.set(self.val + val)

    def get(self):
        '''
        Return the contents of the stat.
        '''
        return self.val

    def __str__(self):
        '''
        Return value as a string.
        '''
        return "%s(%s)" % (self.friendly, str(self.val))

class StatMax(Stat):
    '''
    Basic stat, but add tracking of max value.
    '''
    def __init__(self, friendly, val):
        '''
        Init.
        '''
        super().__init__(friendly, val)
        self.max = val

    def set(self, new_val):
        '''
        set func that tracks max historical value.
        '''
        self.val = new_val
        self.max = max(self.max, self.val)

    def get_max(self):
        '''
        return the max historical value
        '''
        return self.max

    def __str__(self):
        '''
        max stat as a string
        '''
        return "%s(%s/%s)" % (self.friendly, str(self.val), str(self.max))

class StatFloat(Stat):
    '''
    Overrides basic stat to print floating point numbers more neatly as a string.
    '''
    def __str__(self):
        '''
        print float to 2 decimals
        '''
        return "%s(%.2f)" % (self.friendly, self.val)

class StatStr(Stat):
    '''
    Special handler for stats that are strings.
    '''
    def inc(self):
        '''
        Not supported for a string.
        '''
        raise ValueError("Cannot perform inc() on a string stat")

    def dec(self):
        '''
        Not supported for a string.
        '''
        raise ValueError("Cannot perform dec() on a string stat")

    def add(self, val):
        '''
        Not supported for a string.
        '''
        raise ValueError("Cannot perform add() on a string stat")

class StatMB(Stat):
    '''
    Special handler to return a stat that represents data in MB.
    '''
    def __str__(self):
        '''
        Return contents as MB.
        '''
        return "%s(%sMB)" % (self.friendly, str(int(self.val / (1024.0*1024.0))))

class StatTime(Stat):
    '''
    Special handler to return a stat that represents data in MB.
    '''
    def __str__(self):
        '''
        Return contents as a datetime string.
        '''
        return "%s(%s)" % (self.friendly, datetime.datetime.fromtimestamp(self.val))

class HydratorStats():
    '''
    Encapsulate various statistics to track the hydration process.
    '''
    def __init__(self,
                 geneva_enable=False):
        '''
        Init.
        '''
        self.geneva_enable = geneva_enable
        self.general = {
            'errors': Stat('errors', 0),
            'blobs': Stat('blobs', 0),
            'dirs': Stat('dirs', 0),
            'files': Stat('files', 0),
            'symlinks': Stat('symlinks', 0),
            'size': StatMB('size', 0)
        }

        self.progress = {
            'last_file': StatStr('last_file', ''),
            'last_dir': StatStr('last_dir', ''),
            'resume_blob': StatStr('resume_blob', '')
        }

        # The timing stats are mostly used for computing progress updates and not directly printed
        self.timing = {
            'start': StatTime('start', time.time()),
            'start_mono': Stat('start_mono', time.monotonic()),
            'last_print_mono': Stat('print_mono', time.monotonic()),
            'last_blobs': Stat('last_blobs', 0),
            'end': StatTime('end', 0),
            'blobcache_latency': StatFloat('qwait', 0),
            'blobcache_latency_recent': StatFloat('qwait_recent', 0),
            'batch_count_recent': Stat('batch_count_recent', 0),
            'batch_latency': StatFloat('batch_time', 0),
            'batch_latency_recent': StatFloat('batch_latency_recent', 0)
        }

        self.threading = {
            'active': StatMax('active', 0),
            'throttled': Stat('throttled', 0),
            'blobcache_qsize': StatMax('qsize', 0),
            'blobcache_qempty': Stat('qempty', 0),
            'batch_count': Stat('batches', 0)
        }

        self.extended = {
            'stat_existing_dir': Stat('edir', 0),
            'stat_existing_file': Stat('efile', 0),
            'stat_existing_symlink': Stat('elnk', 0),
            'eexist_symlink': Stat('eexistl', 0),
            'wrong_ftype': Stat('eftype', 0),
            'mkdir_exists': Stat('eexistd', 0),
            'mkdir_fexists': Stat('fexistd', 0),
            'chown': Stat('chown', 0),
            'chmod': Stat('chmod', 0),
            'xattr': Stat('xattr', 0),
            'xattr_retry': Stat('xattr_retry', 0),
            'xattr_fail': Stat('xattr_fail', 0)
        }

    def set_resume_point(self, logger, resume_file_name, account, container, prefix):
        '''
        Persist the resume point to a file. Log a message if we don't succeed.
        '''
        if not self.progress['resume_blob'].get():
            return
        if not resume_file_name:
            return
        try:
            with open(resume_file_name, 'w') as f:
                resume_data = dict()
                resume_data['account'] = account
                resume_data['container'] = container
                resume_data['prefix'] = prefix
                resume_data['resume_blob'] = self.progress['resume_blob'].get()
                resume_data['error_count'] = self.general['errors'].get()
                f.write(json.dumps(resume_data))
        except OSError as exc:
            err_str = "Exception writing resume file %r: %r" % (resume_file_name, exc)
            if logger:
                logger.warning("%s", err_str)
            else:
                print(err_str)

    def get_resume_point(self, resume_file_name, account, container, prefix):
        '''
        Read the resume point from a file back into the corresponding stats.
        Raises ApplicatinExit if the resume file exists but we can't read the file or its contents.
        '''
        if resume_file_name:
            if not os.path.exists(resume_file_name):
                return # file may not have been written, or this is a new deployment.
            try:
                with open(resume_file_name, 'r') as f:
                    try:
                        # The file should contain a path, plus some other smallish data.
                        # Read at most PATH_MAX*4 bytes as a safety in case the file is inadvertently large.
                        resume_data = json.loads(f.read(BlobAttributes.PATH_MAX*4))
                        account_resume = resume_data.get('account', '')
                        container_resume = resume_data.get('container', '')
                        prefix_resume = resume_data.get('prefix', '')
                        # account, container, and prefix should all match if this is a resume from the
                        # same hydration process.
                        if account != account_resume or container != container_resume or prefix != prefix_resume:
                            return
                        self.general['errors'].set(resume_data.get('error_count', 0))
                        self.progress['resume_blob'].set(resume_data.get('resume_blob', ''))
                    except ValueError as exc:
                        raise ApplicationExit("Hydration resume file %r exists, but is malformatted. "
                                              "Try repairing or removing the file, then restarting.\n%r" % (resume_file_name, exc)) from exc
            except OSError as exc:
                raise ApplicationExit("Hydration resume file %r exists, but could not be read: %r" % (resume_file_name, exc)) from exc

    def print_stats(self, logger, resume_file_name, account, container, prefix):
        '''
        Iterate over the stat groups and print them.
        Return these stats in dict form to caller, to publish to Geneva via the Metrics daemon.
        '''
        # collect these stats into a dict to publish to Geneva metrics
        publish_dict = dict()
        publish_dict['timestamp'] = datetime.datetime.now().isoformat()
        # Compute some dynamic stats based on cumulative and recent data
        now_mono = time.monotonic()
        elapsed_cumulative = now_mono - self.timing['start_mono'].get()
        elapsed_recent = now_mono - self.timing['last_print_mono'].get()
        blobs_recent = self.general['blobs'].get() - self.timing['last_blobs'].get()
        self.timing['last_print_mono'].set(now_mono)
        self.timing['last_blobs'].set(self.general['blobs'].get())

        blob_latency_recent = self.timing['blobcache_latency'].get() - self.timing['blobcache_latency_recent'].get()
        self.timing['blobcache_latency_recent'].set(self.timing['blobcache_latency'].get())

        batch_latency_recent = self.timing['batch_latency'].get() - self.timing['batch_latency_recent'].get()
        self.timing['batch_latency_recent'].set(self.timing['batch_latency'].get())

        batch_count_recent = self.threading['batch_count'].get() - self.timing['batch_count_recent'].get()
        self.timing['batch_count_recent'].set(self.threading['batch_count'].get())
        if batch_count_recent <= 0 or batch_latency_recent <= 0:
            per_batch_latency_recent_ms = 0
        else:
            per_batch_latency_recent_ms = 1000.0 * batch_count_recent / batch_latency_recent

        # General Stats
        general_stats_dict = dict()
        general_stats = "Stats: "
        for obj in self.general.values():
            general_stats += "%s " % obj
            general_stats_dict[getattr(obj, 'friendly')] = getattr(obj, 'val')

        rate_aggregate =  self.general['blobs'].get()/elapsed_cumulative
        rate_recent = blobs_recent//elapsed_recent
        general_stats += "elapsed(%.2fs) rate_cumul/recent(%.2f/%.2f)" % (elapsed_cumulative, rate_aggregate, rate_recent)
        general_stats_dict['elapsed_secs'] = elapsed_cumulative
        general_stats_dict['rate_aggregate'] = rate_aggregate
        general_stats_dict['rate_recent'] = rate_recent

        logger.info("%r", general_stats)
        publish_dict['general_stats'] = general_stats_dict

        ## Progress Stats
        progress_stats_dict = dict()
        progress_stats = "FileStats: "
        for obj in self.progress.values():
            progress_stats += "%s " % obj
            progress_stats_dict[getattr(obj, 'friendly')] = getattr(obj, 'val')

        logger.info("%r", progress_stats)
        publish_dict['progress_stats'] = progress_stats_dict

        # Threading Stats
        threading_stats_dict = dict()
        threading_stats = "Thread: "
        for obj in self.threading.values():
            threading_stats += "%s " % obj
            threading_stats_dict[getattr(obj, 'friendly')] = getattr(obj, 'val')
        blobwait_latency_cumul = self.timing['blobcache_latency'].get()
        blobwait_latency_recent = blob_latency_recent
        threading_stats += "blobwait_cumul/recent(%.2f/%.2f) " % (blobwait_latency_cumul, blobwait_latency_recent)
        threading_stats += "batch_latency_recent(%dms) " % per_batch_latency_recent_ms
        threading_stats_dict['blobwait_latency_cumul'] = blobwait_latency_cumul
        threading_stats_dict['blobwait_latency_recent'] = blobwait_latency_recent
        threading_stats_dict['per_batch_latency_recent_ms'] = per_batch_latency_recent_ms

        logger.info("%r", threading_stats)
        publish_dict['threading_stats'] = threading_stats_dict

        # Extended Stats
        extended_stats_dict = dict()
        extended_stats = "ExtStats: "
        for obj in self.extended.values():
            extended_stats += "%s " % obj
            extended_stats_dict[getattr(obj, 'friendly')] = getattr(obj, 'val')
        logger.info("%r", extended_stats)
        publish_dict['extended_stats'] = extended_stats_dict
        self.set_resume_point(logger, resume_file_name, account, container, prefix)
        return publish_dict

class PeriodicStatsPrinter():
    '''
    Periodically print all of the stats.
    '''
    def __init__(self, stats, logger, freq_sec, resume_file_name, account, container, prefix, geneva_enable):
        '''
        stats - set of stats to print, derived from BaseStats
        logger - the logging object to print to
        freq - how often
        resume_file_name - name of file to save information for resuming an interrupted transfer
        account - storage account name
        container - container name
        prefix - prefix name being used to populate from the container
        '''
        self.lock = threading.Lock()
        self.stats = stats
        self.logger = logger
        self.freq_sec = freq_sec
        self.resume_file_name = resume_file_name
        self.account = account
        self.container = container
        self.prefix = prefix
        self.geneva_enable = geneva_enable
        self.stats_timer = None

        self.last_stats_time_sec = 0

    def start(self):
        '''
        Start the periodic timer to print stats.
        '''
        self.last_stats_time_sec = time.monotonic()
        with self.lock:
            self.set_timer(self.freq_sec)

    def set_timer(self, length_sec):
        '''
        Set the stats timer.
        '''
        assert self.lock.locked()
        self.stats_timer = threading.Timer(length_sec, self.do_print)
        self.stats_timer.start()

    def stop(self):
        '''
        Stop printing the stats.
        '''
        with self.lock:
            if self.stats_timer:
                self.stats_timer.cancel()
                self.stats_timer = None

    def print_now(self):
        '''
        Print the stats right now.
        '''
        stats_dict = self.stats.print_stats(self.logger, self.resume_file_name, self.account, self.container, self.prefix)
        if self.geneva_enable:
            self.publish_metrics(stats_dict)

    @staticmethod
    def publish_metrics(stats_dict):
        '''
        Grab a file lock and write out to file in local FS
        '''
        with FileLock(HYDRATOR_METRICS_LOCKFILE_PATH):
            with open(HYDRATOR_METRICS_FILE_PATH, "w") as fp:
                yaml.safe_dump(stats_dict, fp)

    def do_print(self):
        '''
        Called periodically to print the stats.
        If we were in the process of printing the stats while stop() is called,
        the stats may print one extra time.
        '''
        self.print_now()
        now = time.monotonic()
        variance = now - self.last_stats_time_sec - self.freq_sec
        next_stats_time_sec = max(self.freq_sec + variance, 0.5)
        self.last_stats_time_sec = now
        with self.lock:
            if self.stats_timer:
                self.set_timer(next_stats_time_sec)
