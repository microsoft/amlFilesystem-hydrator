#
# laaso/cacher.py
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
'''
Provide generic caching functionality.
When possible, use what functools provides. What is here either
has semantics not available through functools or the corresponding
functools operations are not available in all of the Python
versions we support.
'''
import threading

class Cache():
    '''
    Generic key/value cache. Locking prevents concurrent loads.
    The intended use is cases where the corresponding value
    can be expensive to load.
    '''
    def __init__(self):
        self._c_cond = threading.Condition()
        self._c_data = dict()
        self._c_busy = dict()

    def reset(self):
        '''
        Discard cache contents.
        '''
        with self._c_cond:
            assert not self._c_busy
            self._c_data.clear()

    def get(self, key, loader, *args, **kwargs):
        '''
        Fetch the value associated with key. If the value
        is not already cached, invoke loader(*args, **kwargs)
        to populate the cache entry. If loader completes
        without raising an exception, the value is cached and
        returned. If loader raises an exception, that exception
        is raised to the caller and the cache contents are
        not modified. If more than one thread misses in the
        cache at the same time, the first thread performs
        the load, and the second thread waits for the first to
        complete. If the first thread populates the cache,
        the second thread uses that value. If the first thread
        raises an exception, the second thread will then
        attempt the load. In the case of more than two threads,
        the semantics are the same, but there is no defined
        ordering for which thread is next to attempt the load
        when the previous loader fails.
        '''
        sid = id(threading.current_thread())
        assert sid

        maybe_busy = False

        try:
            with self._c_cond:
                while True:
                    try:
                        return self._c_data[key]
                    except KeyError:
                        pass

                    # The entry is not cached.

                    # If another thread is trying to load this entry, wait
                    # for that load attempt to complete.
                    if not self._c_busy.get(key, False):
                        # Not in the cache and no one else is loading.
                        break
                    self._c_cond.wait()

                # Mark it maybe_busy. Set maybe_busy before updating _c_busy
                # so we are sure to do the cleanup even if we
                # get something like a KeyboardInterrupt with
                # pessimal timing. The cleanup handles the case
                # where maybe_busy is set but this thread does not
                # have the entry marked busy. It does not handle
                # the reverse. Think of this maybe_busy flag as an
                # optimization.
                maybe_busy = True
                p = self._c_busy.setdefault(key, sid)
                assert p == sid

            # We have dropped the lock. Perform the load.
            val = loader(*args, **kwargs)

            with self._c_cond:
                self._c_data[key] = val
                p = self._c_busy.get(key, None)
                assert p == sid
                self._c_busy.pop(key)
                maybe_busy = False
                self._c_cond.notify_all()

            return val
        finally:
            if maybe_busy:
                with self._c_cond:
                    p = self._c_busy.get(key, None)
                    if p == sid:
                        self._c_busy.pop(key)
                        self._c_cond.notify_all()

class CacheIndexer():
    '''
    Cache-of-caches - for example, caching per-subscription data.
    Use the subscription_id as key1, and the data key as key2.
    This gives a cache for each subscription.
    '''
    def __init__(self):
        self._ci_lock = threading.Lock()
        self._ci_data = dict()

    def reset(self):
        '''
        Reset all caches.
        '''
        with self._ci_lock:
            for cache in self._ci_data.values():
                cache.reset()

    def get(self, key1, key2, loader, *args, **kwargs):
        '''
        Get a Cache for key2, and get key2 from it.
        '''
        with self._ci_lock:
            try:
                cache = self._ci_data[key1]
            except KeyError:
                cache = Cache()
                self._ci_data[key1] = cache
        return cache.get(key2, loader, *args, **kwargs)
