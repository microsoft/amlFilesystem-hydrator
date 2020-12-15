#
# laaso/msapicall.py
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
'''
Provide wrappers for retrying Azure calls.

Some notes about polling object wrapping:
  msrestazure (older SDKs):
    op = msrest.polling.poller.LROPoller
    op._polling_method = msrestazure.polling.arm_polling.ARMPolling
    op._polling_method._operation = msrestazure.polling.arm_polling.LongRunningOperation

  msrestazure (older SDKs) wrapped:
    op = laaso.msapicall.LaaSO_LROPoller_msrest
    op._polling_method = laaso.msapicall.LaaSO_ARMPolling_msrestazure
    op._polling_method._operation = laaso.msapicall.LaaSO_LongRunningOperation_msrestazure

  track2 SDKs:
    op = azure.core.polling._poller.LROPoller
    op._polling_method = azure.mgmt.core.polling.arm_polling.ARMPolling
    op._polling_method._operation = some subclass of azure.core.polling.base_polling.LongRunningOperation such as azure.core.polling.base_polling.StatusCheckPolling

  track2 SDKs wrapped:
    op = azure.core.polling._poller.LROPoller
    op._polling_method = LaaSO_ARMPolling_mgmt_core
    op._polling_method._operation = some subclass of azure.core.polling.base_polling.LongRunningOperation such as azure.core.polling.base_polling.StatusCheckPolling
      Note that op._polling_method._operation is not wrapped - too much fuzzing with the ABC stuff there.
      Instead we DTRT for operation_id in the next level up (op._polling_method).
'''
import functools
import http.client
import logging
import random
import time
import urllib.parse

import azure.common
import azure.core.exceptions
import azure.core.pipeline
import azure.core.polling
import azure.graphrbac
import azure.identity
import azure.identity._credentials
import azure.mgmt.core.polling.arm_polling
import azure.mgmt.msi
import azure.profiles.multiapiclient
import azure.storage.blob._generated._azure_blob_storage
import azure.storage.blob._generated.operations
import azure.storage.blob._shared.base_client
import azure.storage.filedatalake
import azure.storage.filedatalake._generated.models
import azure.storage.filedatalake._shared.base_client
from defusedxml import ElementTree
import knack.util
import msrest.exceptions
import msrest.paging
import msrest.polling
import msrest.service_client
import msrestazure.polling.arm_polling
import urllib3.exceptions

from laaso.exceptions import ApplicationException
from laaso.util import (elapsed,
                        indent_exc,
                        indent_pformat,
                        getframe,
                        getframename,
                       )

LOGGER_NAME_DEFAULT = 'laaso'

URLLIB3_SDK_EXCEPTIONS = (urllib3.exceptions.HTTPError,
                          urllib3.exceptions.HTTPWarning,
                         )

AZURE_SDK_EXCEPTIONS = (azure.core.exceptions.HttpResponseError,
                        knack.util.CLIError,
                        msrestazure.azure_exceptions.CloudError,
                       ) + URLLIB3_SDK_EXCEPTIONS

class CallPolicy():
    '''
    Call retry policy
    '''
    def __init__(self,
                 max_attempts_other=5,
                 max_attempts_throttle=100,
                 no_retry_classes=None):
        self.max_attempts_other = max_attempts_other
        self.max_attempts_throttle = max_attempts_throttle
        self.no_retry_classes = no_retry_classes or set()

class Caught():
    '''
    Capture an exception. Called from the exception context.
    '''
    def __init__(self, exc, callpolicy=None):
        # Because we insert msapicall in the low-level call stack, we can get
        # exceptions that are not yet mapped to what API callers expect.
        # Force mapping here.
        if isinstance(exc, azure.storage.filedatalake._generated.models.StorageErrorException):
            try:
                azure.storage.filedatalake._deserialize.process_storage_error(exc)
            except Exception as exc2:
                exc = exc2

        self.callpolicy = callpolicy or CallPolicy()
        assert isinstance(self.callpolicy, CallPolicy)
        self.exc = exc
        self.status_code = getattr(self.exc, 'status_code', None)
        try:
            self.status_code_int = int(self.status_code)
        except Exception:
            self.status_code_int = -1
        self.error_code = None
        self.error_target = None
        self.exc_data_error = None

        if isinstance(self.exc, URLLIB3_SDK_EXCEPTIONS):
            return

        if hasattr(exc, 'error_code') and exc.error_code:
            self.error_code = str(exc.error_code)
        elif hasattr(exc, 'error') and hasattr(exc.error, 'code') and exc.error.code:
            self.error_code = str(exc.error.code)
        else:
            # pre-track2
            try:
                self.error_code = str(exc.error.error)
            except Exception:
                self.error_code = None
            idx = str(exc).find('<?xml')
            if idx >= 0:
                try:
                    xmltxt = ''.join(str(exc)[idx:].strip().splitlines())
                    et_root = ElementTree.fromstring(xmltxt)
                    et_code_list = et_root.findall('Code')
                    self.error_code = str(et_code_list[0].text)
                except Exception:
                    pass

        try:
            self.error_target = exc.error.target
        except Exception:
            pass

        try:
            self.exc_data_error = str(exc.error.error)
        except Exception:
            pass

    def is_conflict(self):
        '''
        Return whether this is a "conflict" error.
        '''
        return (self.status_code_int == http.client.CONFLICT) \
          or isinstance(self.exc, azure.common.AzureConflictHttpError)

    def is_missing(self):
        '''
        Return whether this exception is caused by a missing resource
        '''
        if self.status_code_int == http.client.NOT_FOUND:
            return True
        if self.status_code == http.client.NOT_FOUND:
            return True
        if isinstance(self.exc, (azure.common.AzureMissingResourceHttpError,
                                 azure.core.exceptions.ResourceNotFoundError,
                                )):
            return True
        if self.exc_data_error == 'BlobNotFound':
            return True
        if isinstance(self.exc, msrest.exceptions.HttpOperationError) and (self.exc.response.status_code == http.client.NOT_FOUND):
            return True
        try:
            if self.exc.error.code == 'Request_ResourceNotFound':
                return True
        except AttributeError:
            pass
        return False

    def is_urllib3(self):
        '''
        Return whether this exception originates with urllib3
        '''
        return isinstance(self.exc, URLLIB3_SDK_EXCEPTIONS)

    _no_retry_classes = (azure.common.AzureException,
                         azure.common.AzureHttpError,
                         azure.common.AzureMissingResourceHttpError,
                         azure.core.exceptions.ResourceExistsError,
                         azure.core.exceptions.ResourceNotFoundError,
                         msrest.exceptions.SerializationError,
                         msrest.exceptions.ValidationError,
                        )

    # Do not include 'AuthorizationFailed' here. A common failure we see
    # is AAD blipping and claiming no authorization. It goes away on retry.
    # The cost is that when we have a real failure, we must try a few times
    # before giving up.
    _no_retry_codes = ('BlobNotFound',
                       'ExpiredAuthenticationToken',
                       'HierarchicalNamespaceNotEnabled',
                       'InvalidParameter',
                       'InvalidResourceReference',
                       'LinkedInvalidPropertyId',
                       'MaxStorageAccountsCountPerSubscriptionExceeded',
                       'OSProvisioningTimedOut',
                       'PropertyChangeNotAllowed',
                       'ResourceGroupNotFound',
                       'SubnetHasServiceEndpointWithInvalidServiceName',
                       'VaultNameNotValid',
                      )

    def any_code_matches(self, *args):
        '''
        Return whether any code in args (strings)
        matches either self.exc_data_error or self.error_code.
        '''
        for code in args:
            if self.exc_data_error and (self.exc_data_error.lower() == code.lower()):
                return True
            if self.error_code and (self.error_code.lower() == code.lower()):
                return True
        return False

    def is_server_rejected_auth(self):
        '''
        Return whether this error is server rejected authentication
        '''
        return self.any_code_matches('AuthenticationFailed', 'ExpiredAuthenticationToken')

    def is_throttle(self):
        '''
        Endpoint wants us to throttle
        '''
        return self.status_code_int == http.client.TOO_MANY_REQUESTS

    def is_hns_not_enabled(self):
        '''
        Return True iff this exception is caused by an attempt to apply a hierarchical namespace
        operation to a non-HNS target.
        '''
        return self.error_code and (self.error_code.lower() == 'HierarchicalNamespaceNotEnabled'.lower())

    def retry_time(self):
        '''
        Return None if the operation should not retry
        Return 0.0 if the operations should retry immediately
        Return > 0.0 for an amount of time the operation should sleep before retrying
        '''
        # AzureException is part of no_retry_classes, so _ERROR_DECRYPTION_FAILURE
        # is never retried.
        if isinstance(self.exc, self._no_retry_classes) or self.any_code_matches(*self._no_retry_codes):
            return None
        if isinstance(self.exc, (ApplicationException, KeyboardInterrupt, SystemExit, TypeError)) \
          or self.is_server_rejected_auth() \
          or self.is_missing() \
          :
            return None
        if self.is_hns_not_enabled():
            return None
        if self.is_urllib3():
            # typically an Azure network problem of some sort - give it a little extra time to sort out
            return random.uniform(5, 10)
        if self.is_throttle() or self.is_conflict():
            # Do a longer sleep to let things cool down.
            # Jitter the sleep to break up convoys.
            return random.uniform(28, 32)
        return random.uniform(1, 3)

    def reason(self):
        '''
        Bucket failure reasons into a human-readable string.
        '''
        # The ordering here matches the bucketing in retry_time()
        for checker in ('is_server_rejected_auth',
                        'is_missing',
                        'is_hns_not_enabled',
                        'is_urllib3',
                        'is_throttle',
                        'is_conflict',
                       ):
            proc = getattr(self, checker)
            if proc():
                return checker
        return None

def msapicall(logger, op, *args, laaso_callpolicy=None, **kwargs):
    '''
    execute op(*args, **kwargs) and return the result.
    Internally, do some amount of retry on errors.
    '''
    callpolicy = laaso_callpolicy or CallPolicy()
    last_reason = None
    attempt_all = 0
    attempt_this_reason = 0
    while True:
        try:
            ret = op(*args, **kwargs)
            break
        except AZURE_SDK_EXCEPTIONS as exc:
            caught = Caught(exc, callpolicy=callpolicy)
            sleep_secs = caught.retry_time()
            if sleep_secs is None:
                raise
            reason = caught.reason()
            attempt_all += 1
            if reason == last_reason:
                attempt_this_reason += 1
            else:
                attempt_this_reason = 1
            last_reason = reason
            if caught.is_throttle():
                max_attempts = callpolicy.max_attempts_throttle
            else:
                max_attempts = callpolicy.max_attempts_other
            if attempt_this_reason >= max_attempts:
                raise
            reason_str = reason or 'other'
            if (not reason) and (logger.level <= logging.DEBUG):
                logger.warning("%s op=%r count=%s,%s/%s will retry after %s [%s] %r [WILL RETRY]\n%s", getframe(0), op, attempt_all, attempt_this_reason, max_attempts, sleep_secs, reason_str, exc, indent_pformat(vars(exc)))
            else:
                logger.warning("%s op=%r count=%s,%s/%s will retry after %s [%s] %r [WILL RETRY]", getframe(0), op, attempt_all, attempt_this_reason, max_attempts, sleep_secs, reason_str, exc)
            time.sleep(sleep_secs)
    return msapiwrap(logger, ret)

def msapiwrap(logger, ret):
    '''
    Given a return from some SDK op, rewrap it if necessary to ensure
    that subsequent SDK ops are directed through msapicall.
    '''
    if isinstance(ret, (AzLoginCredential,
                        GeneratedStorageClientWrapper,
                        LaaSO_ARMPolling_mgmt_core,
                        LaaSO_ARMPolling_msrestazure,
                        LaaSO_AzureIdentityCredentialAdapter,
                        LaaSO_LROPoller_azure_core,
                        LaaSO_LROPoller_msrest,
                        LaaSO_LongRunningOperation_msrestazure,
                        LaaSO_OperationsWrapper,
                        MSApiSDKClientMultiWrapper,
                       )):
        # already wrapped
        pass
    elif isinstance(ret, msrest.paging.Paged):
        # wrap for retries
        ret._get_next = msapiwrapcall(ret._get_next, logger) # pylint: disable=protected-access
    elif isinstance(ret, (azure.graphrbac.operations.applications_operations.ApplicationsOperations,
                          azure.graphrbac.operations.deleted_applications_operations.DeletedApplicationsOperations,
                          azure.graphrbac.operations.groups_operations.GroupsOperations,
                          azure.graphrbac.operations.service_principals_operations.ServicePrincipalsOperations,
                          azure.graphrbac.operations.users_operations.UsersOperations,
                          azure.graphrbac.operations.objects_operations.ObjectsOperations,
                          azure.graphrbac.operations.domains_operations.DomainsOperations,
                          azure.mgmt.msi.operations.user_assigned_identities_operations.UserAssignedIdentitiesOperations,
                         )):
        ret = LaaSO_OperationsWrapper(ret, logger)
    elif isinstance(ret, azure.graphrbac.graph_rbac_management_client.GraphRbacManagementClient):
        for a in ('applications',
                  'deleted_applications',
                  'groups',
                  'service_principals',
                  'users',
                  'objects',
                  'domains'):
            setattr(ret, a, msapiwrap(logger, getattr(ret, a)))
        ret = LaaSO_OperationsWrapper(ret, logger)
    elif isinstance(ret, azure.mgmt.msi.managed_service_identity_client.ManagedServiceIdentityClient):
        for a in ('operations',
                  'user_assigned_identities'):
            setattr(ret, a, msapiwrap(logger, getattr(ret, a)))
        ret = LaaSO_OperationsWrapper(ret, logger)
    elif isinstance(ret, azure.profiles.multiapiclient.MultiApiClientMixin):
        ret = MSApiSDKClientMultiWrapper(ret, logger)
    elif isinstance(ret, msrest.service_client.SDKClient):
        ret = LaaSO_OperationsWrapper(ret, logger)
    elif isinstance(ret, azure.graphrbac.operations.users_operations.UsersOperations):
        ret = LaaSO_OperationsWrapper(ret, logger)
    elif isinstance(ret, azure.storage.filedatalake.DataLakeServiceClient):
        ret._blob_service_client = GeneratedStorageClientWrapper(ret._blob_service_client, logger) # pylint: disable=protected-access
        ret = GeneratedStorageClientWrapper(ret, logger)
    elif isinstance(ret, azure.storage.blob._generated._azure_blob_storage.AzureBlobStorage): # pylint: disable=protected-access
        for k in ('_client',
                  'service',
                  'container',
                  'directory',
                  'blob',
                  'page_blob',
                  'append_blob',
                  'block_blob',
                 ):
            # ret.k = GeneratedStorageClientWrapper(ret.k, logger)
            v = getattr(ret, k)
            if not isinstance(v, GeneratedStorageClientWrapper):
                setattr(ret, k, GeneratedStorageClientWrapper(v, logger))
    elif isinstance(ret, (azure.storage.blob._generated.operations.AppendBlobOperations, # pylint: disable=protected-access
                          azure.storage.blob._generated.operations.BlobOperations, # pylint: disable=protected-access
                          azure.storage.blob._generated.operations.BlockBlobOperations, # pylint: disable=protected-access
                          azure.storage.blob._generated.operations.PageBlobOperations, # pylint: disable=protected-access
                          azure.storage.blob._shared.base_client.StorageAccountHostsMixin, # pylint: disable=protected-access
                          azure.storage.filedatalake._shared.base_client.StorageAccountHostsMixin, # pylint: disable=protected-access
                         )):
        # This includes things like BlobServiceClient._client, ContainerClient._client, BlobClient._client, FileSystemClient._client.
        ret._client = GeneratedStorageClientWrapper(ret._client, logger) # pylint: disable=protected-access
    elif isinstance(ret, msrestazure.polling.arm_polling.LongRunningOperation):
        LaaSO_LongRunningOperation_msrestazure.add_to_obj(ret, logger)
    elif isinstance(ret, msrestazure.polling.arm_polling.ARMPolling):
        LaaSO_ARMPolling_msrestazure.add_to_obj(ret, logger)
    elif isinstance(ret, azure.mgmt.core.polling.arm_polling.ARMPolling):
        LaaSO_ARMPolling_mgmt_core.add_to_obj(ret, logger)
    elif isinstance(ret, azure.core.polling._poller.LROPoller): # pylint: disable=protected-access
        LaaSO_LROPoller_topmixin.add_to_obj(ret, LaaSO_LROPoller_azure_core, logger)
    elif isinstance(ret, msrest.polling.LROPoller):
        LaaSO_LROPoller_topmixin.add_to_obj(ret, LaaSO_LROPoller_msrest, logger)
    # No special handling for ItemPaged (azure/core/paging.py) -- the underlying calls go through the already-wrapped client
    return ret

def msapiwrapcall(call, logger):
    '''
    Given callable call, wrap it with msapicall unless it is already wrapped.
    '''
    if not callable(call):
        return call
    if isinstance(call, functools.partial) and (call.func == msapicall): # pylint: disable=comparison-with-callable
        # already wrapped
        return call
    return functools.partial(msapicall, logger, call)

class LaaSO_LROPoller_topmixin():
    '''
    This class contains methods that are inserted into top-level polling op types:
      LaaSO_LROPoller_azure_core
      LaaSO_LROPoller_msrest
    Those classes are used by flipping obj.__class__ on existing instances
    of the parent class, so inheriting this class as a mixin
    does not work. Instead, invoke add_to_obj() on a target object
    to simulate inheritance.
    '''
    @classmethod
    def add_to_obj(cls, obj, new_class, logger):
        '''
        Simulate obj inheriting from new_class
        '''
        obj._polling_method = msapiwrap(logger, obj._polling_method) # pylint: disable=protected-access
        if not hasattr(obj, 'operation_id_get'):
            obj.operation_id_get = functools.partial(cls.operation_id_get, obj)
        if not hasattr(obj, 'thread_get'):
            obj.thread_get = functools.partial(cls.thread_get, obj)
        setattr(obj, '_laaso_logger', logger)
        obj.__class__ = new_class

    def operation_id_get(self):
        '''
        Return the operation_id or None
        '''
        try:
            return self._polling_method.operation_id_get() or None
        except AttributeError:
            return None

    def thread_get(self):
        '''
        Return the threading object for the backgrounded operation
        '''
        try:
            return self._thread
        except AttributeError:
            return None

    def wait(self, *args, **kwargs):
        '''
        Wrap wait to log extra diagnostics
        '''
        try:
            super().wait(*args, **kwargs)
        except Exception as exc:
            logger = _logger_for_obj(self)
            logger.warning("%s.%s wait failed (thread=%r) (operation_id=%s): %s\n%s",
                           type(self).__name__, getframename(0), self.thread_get(), self.operation_id_get(), exc,
                           indent_exc())
            raise

class LaaSO_LROPoller_azure_core(azure.core.polling._poller.LROPoller): # pylint: disable=protected-access
    '''
    Wrapper around msrest.polling.LROPoller to add an accessor for the operation ID.
    '''
    # All extensions handled by LaaSO_LROPoller_topmixin.add_to_obj()

class LaaSO_LROPoller_msrest(msrest.polling.LROPoller):
    '''
    Wrapper around msrest.polling.LROPoller to add an accessor for the operation ID.
    '''
    # All extensions handled by LaaSO_LROPoller_topmixin.add_to_obj()

def _operation_id_from_url(url, logger=None):
    '''
    Given a URL, such as used by a polling object to query LRO status,
    extract and return the operation ID. Return None if it cannot
    be determined.
    '''
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception as exc:
        logger = logger or logging.getLogger(LOGGER_NAME_DEFAULT)
        logger.warning("%s cannot parse url=%r: %r", getframe(0), url, exc)
        return None
    pathtoks = parsed.path.split('/')
    if (len(pathtoks) >= 2) and (pathtoks[-2].lower() in ('operations', 'operationstatuses')):
        return pathtoks[-1]
    # Possibly the operation completed synchronously, such as a no-op PATCH.
    return None

def _logger_for_obj(obj):
    '''
    Given an object that might have a logger or _logger attribute,
    return that attribute or a reasonable default logger.
    '''
    for attr in ('logger',
                 '_logger',
                 '_laaso_logger',
                ):
        try:
            return getattr(obj, attr)
        except AttributeError:
            pass
    return logging.getLogger(LOGGER_NAME_DEFAULT)

class LaaSO_LongRunningOperation_msrestazure(msrestazure.polling.arm_polling.LongRunningOperation):
    '''
    Wrapper around msrestazure.polling.arm_polling.LongRunningOperation that
    adds an accessor for the operation ID and overloads methods to fix bugs.
    '''
    def get_status_link(self):
        '''
        msrestazure.polling.arm_polling.LongRunningOperation.get_status_link() is missing
        handling for PATCH. Attempt to detect and handle that case.
        '''
        try:
            return super().get_status_link()
        except msrestazure.polling.arm_polling.BadResponse:
            if self.method == 'PATCH':
                return self.initial_response.request.url
            raise

    @classmethod
    def add_to_obj(cls, obj, logger):
        '''
        Simulate obj inheriting from cls by explicitly inserting things that are not overloads
        '''
        obj.logger = logger
        obj.operation_id_get = functools.partial(cls.operation_id_get, obj)
        obj.__class__ = cls

    def operation_id_get(self):
        '''
        Retrieve the operation_id for this LRO.
        '''
        logger = _logger_for_obj(self)
        try:
            url = self.get_status_link()
        except Exception as exc:
            logger.warning("%s.%s: cannot get_status_link(): %r", type(self).__name__, getframe(0), exc)
            return None
        return _operation_id_from_url(url, logger=logger)

def _delay_time_for_polling(time0, default):
    '''
    time0 is the beginning of the operation, or the best
    approximation thereof, as sampled from time.time().
    Use that to determine how long an operation should
    delay before polling again.

    default is the delay time the poller would use without
    our tampering.

    Early on, poll more aggressively to avoid sleeping
    unnecessarily long. Later, back off to reduce the number
    of polling ops in the sub in an attempt to avoid
    getting throttled.
    '''
    el = elapsed(time0)
    if el <= 0.2:
        return 0.1
    if el < 3:
        return 1
    if el < 10:
        return min(default, 5)
    if el < 60:
        return min(default, 10)
    if el < 180:
        return min(default, 15)
    # From here on, ignore default.
    # If we do too much polling, we'll hit throttling errors.
    if el < 360:
        return 30
    if el < 900:
        return 60
    return 90

class LaaSO_ARMPolling_mgmt_core(azure.mgmt.core.polling.arm_polling.ARMPolling):
    '''
    Wrapper around azure.mgmt.core.polling.arm_polling.ARMPolling that
    adds an accessor for the operation ID and overloads methods to fix bugs.
    '''
    def _poll(self):
        '''
        Overload is to force an update_status() before entering the
        polling loop to avoid sleeping to wait for an already-completed operation.
        '''
        if not self.finished():
            self.update_status()
        return super()._poll()

    def _extract_delay(self):
        '''
        Overload to apply _delay_time_for_polling() so we get
        more aggressive polling up front and less aggressive polling
        on the back-end
        '''
        try:
            time0 = self._laaso_time0
        except AttributeError:
            time0 = time.time()
            self._laaso_time0 = time0 # pylint: disable=attribute-defined-outside-init
        default = super()._extract_delay()
        return _delay_time_for_polling(time0, default)

    @classmethod
    def add_to_obj(cls, obj, logger):
        '''
        Simulate obj inheriting from cls by explicitly inserting things that are not overloads
        '''
        obj._laaso_wrapped_operation = msapiwrap(logger, obj._operation) # pylint: disable=protected-access
        obj._laaso_time0 = time.time() # pylint: disable=protected-access
        obj.logger = logger
        obj.operation_id_get = functools.partial(cls.operation_id_get, obj)
        obj.__class__ = cls

    def operation_id_get(self):
        '''
        Extract the operation_id from the _operation object.
        '''
        logger = _logger_for_obj(self)
        try:
            url = self._operation.get_polling_url()
        except (AttributeError, NotImplementedError, ValueError):
            # All various forms of "not implemented".
            # StatusCheckPolling raises ValueError, so we include that.
            return None
        return _operation_id_from_url(url, logger=logger)

class LaaSO_ARMPolling_msrestazure(msrestazure.polling.arm_polling.ARMPolling):
    '''
    Wrapper around msrestazure.polling.arm_polling.ARMPolling that
    adds an accessor for the operation ID and overloads methods to fix bugs.
    We use this by adjusting __class__ on an already-constructed object,
    so we may not rely on overloading __init__ or __new__.
    '''
    @property
    def _operation(self):
        '''
        Getter
        '''
        return self._laaso_wrapped_operation

    @_operation.setter
    def _operation(self, value):
        self._laaso_wrapped_operation = msapiwrap(getattr(self, '_logger', None), value)

    def operation_id_get(self):
        '''
        Extract operation_id
        '''
        try:
            ret = self._laaso_wrapped_operation.operation_id_get()
        except AttributeError:
            return None
        return ret or None

    def update_status(self):
        '''
        Wrapper to handle the PATCH case.
        '''
        try:
            super().update_status()
        except msrestazure.polling.arm_polling.BadResponse:
            if self._operation.method == 'PATCH':
                initial_url = self._operation.initial_response.request.url
                self._response = self.request_status(initial_url)
                self._operation.set_async_url_if_present(self._response)
                self._operation.get_status_from_resource(self._response)
                return
            raise

    def _delay(self):
        '''
        Overload _delay to use shorter times at the beginning
        '''
        if self._response is None:
            return
        time.sleep(self._delay_time())

    def _delay_time_from_header(self):
        '''
        Extract the delay time from the response header.
        If that is not available, fall gack to the default timeout.
        If there is no default timeout, use 1.
        At this time, the real ARMPolling object assumes that
        self._timeout is always valid, so that last fallback
        is just trying to future-proof.
        '''
        try:
            ret = int(self._response.headers['retry-after'])
        except (AttributeError, KeyError):
            ret = 0
        return ret or self._timeout or 1

    def _delay_time(self):
        '''
        Be aggressive about polling early to avoid waiting 30 seconds for an op
        that completes in milliseconds or that finished synchronously.
        '''
        try:
            time0 = self._laaso_time0
        except AttributeError:
            time0 = time.time()
            self._laaso_time0 = time0 # pylint: disable=attribute-defined-outside-init
            try:
                operation_id = self._laaso_wrapped_operation.operation_id_get()
                if not operation_id:
                    # This is the first call to _delay since reconstructing
                    # and there is no operation_id. This could be an operation
                    # that completed synchronously. Return a delay of 0
                    # just this once.
                    return 0
            except AttributeError:
                pass
        default = self._delay_time_from_header()
        return _delay_time_for_polling(time0, default)

    def _poll(self):
        '''
        Overload _poll() to avoid an unnecessary delay when an operation is already completed.
        '''
        # Do an update_status() to see if the response has already completed
        # the operation. With that done, the super poll will avoid the
        # unnecessary delay.
        if (not self.finished()) and self._operation.method in ('PATCH', 'PUT'):
            self.update_status()
        return super()._poll()

    @classmethod
    def add_to_obj(cls, obj, logger):
        '''
        Simulate obj inheriting from cls by explicitly inserting things that are not overloads
        '''
        obj._laaso_wrapped_operation = msapiwrap(logger, obj._operation) # pylint: disable=protected-access
        obj._laaso_wrapped_operation.logger = logger # pylint: disable=protected-access
        obj._laaso_time0 = time.time() # pylint: disable=protected-access
        obj.logger = logger
        obj.operation_id_get = functools.partial(cls.operation_id_get, obj)
        obj.__class__ = cls

def armpolling_obj_for_operations(operations, logger=None):
    '''
    Given an SDK operations object, return the appropriate class of LRO ARM polling object to use.
    '''
    # If operations has attr config, then it's old SDK (pre-track2), and we use LaaSO_ARMPolling_msrestazure.
    # If there is no config attr, it is track2 and we use LaaSO_ARMPolling_mgmt_core.

    if hasattr(operations, 'config'):
        # pre-track2
        return LaaSO_ARMPolling_msrestazure(timeout=operations.config.long_running_operation_timeout)

    # track2 or later
    if hasattr(operations, '_config'):
        return LaaSO_ARMPolling_mgmt_core(timeout=operations._config.polling_interval) # pylint: disable=protected-access

    logger = logger or logging.getLogger(LOGGER_NAME_DEFAULT)
    logger.warning("%s: cannot determine vintage of operations %r", getframe(0), operations)
    return True

class LaaSO_OperationsWrapper():
    '''
    Wraps Operation objects. Adds retries around calls.
    These objects have no common ancestor. They are auto-generated.
    There are typically multiple classes with the same name but
    no common ancestor - one for each version of the API. They
    are not necessarily isomorphic - different API versions may have
    different operations, and the schema for the various types may
    vary from version to version.
    Arbitrary example: ImagesOperations (azure.mgmt.compute.v2019_12_01.operations._images_operations.ImagesOperations)

    This object exposes all attributes of the thing it wraps.
    All local attribute names are prefixed with '_laaso'.

    When a callable exposed attribute is read, the return is
    wrapped by msapicall.
    '''
    def __init__(self, wrapped, logger):
        self._laaso_logger = logger
        self._laaso_wrapped = wrapped

    def __repr__(self):
        return "<%s,%s,%r>" % (type(self).__name__, hex(id(self)), self._laaso_wrapped)

    def __getattribute__(self, name):
        if name.startswith('_laaso_'):
            return super().__getattribute__(name)
        try:
            return msapiwrapcall(self._laaso_wrapped.__getattribute__(name), self._laaso_logger)
        except AttributeError:
            btk = 'begin_'
            if name.startswith(btk):
                # If we are sitting on a downrev SDK operations object,
                # then instead of begin_X (eg begin_update()) it has
                # X (eg update()). See if that is the case here.
                oname = name[len(btk):]
                # These operations are known as X pre-track2 and begin_X in track2.
                # We accept all begin_X forms. If the caller asks for begin_X
                # and we do not have that but we do have X, we return X.
                if oname in ('create_or_update',
                             'delete',
                             'power_off',
                             'update',
                            ):
                    try:
                        return msapiwrapcall(self._laaso_wrapped.__getattribute__(oname), self._laaso_logger)
                    except AttributeError:
                        # ignore this and fall down to raise the original AttributeError
                        pass
            raise

    def __setattr__(self, name, value):
        if name.startswith('_laaso_'):
            return super().__setattr__(name, value)
        return self._laaso_wrapped.__setattr__(name, value)

    def __delattr__(self, name):
        if name.startswith('_laaso_'):
            return super().__delattr__(name)
        return self._laaso_wrapped.__delattr__(name)

class GeneratedStorageClientWrapper():
    '''
    This is used to wrap things like BlobServiceClient._client, ContainerClient._client, and BlobClient._client.
    It wraps externally-visible attributes that are not callables and not prefixed with an underscore.
    These are presumed to be generated operations objects (example: azure.storage.blob._generated.operations._container_operations.ContainerOperations)
    and those are wrapped using LaaSO_OperationsWrapper.
    '''
    def __init__(self, wrapped, logger):
        self._laaso_logger = logger
        self._laaso_wrapped = wrapped

    def __getattribute__(self, name):
        if name.startswith('_laaso_'):
            return super().__getattribute__(name)
        ret = self._laaso_wrapped.__getattribute__(name)
        if (not name) or name.startswith('_') or callable(ret):
            return ret
        return LaaSO_OperationsWrapper(ret, self._laaso_logger)

    def __setattr__(self, name, value):
        if name.startswith('_laaso_'):
            return super().__setattr__(name, value)
        return self._laaso_wrapped.__setattr__(name, value)

    def __delattr__(self, name):
        if name.startswith('_laaso_'):
            return super().__delattr__(name)
        return self._laaso_wrapped.__delattr__(name)

class MSApiSDKClientMultiWrapper():
    '''
    Wraps msrest.service_client.SDKClient. Adds retries around calls.
    '''
    def __init__(self, wrapped, logger):
        self._laaso_logger = logger
        self._laaso_wrapped = wrapped

    def __getattribute__(self, name):
        if name.startswith('_laaso_'):
            return super().__getattribute__(name)
        ret = self._laaso_wrapped.__getattribute__(name)
        if isinstance(ret, LaaSO_OperationsWrapper):
            return ret
        return LaaSO_OperationsWrapper(ret, self._laaso_logger)

    def __setattr__(self, name, value):
        if name.startswith('_laaso_'):
            return super().__setattr__(name, value)
        if isinstance(value, LaaSO_OperationsWrapper):
            return self._laaso_wrapped.__setattr__(name, value)
        return self._laaso_wrapped.__setattr__(name, LaaSO_OperationsWrapper(value, self._laaso_logger))

    def __delattr__(self, name):
        if name.startswith('_laaso_'):
            return super().__delattr__(name)
        return self._laaso_wrapped.__delattr__(name)

def client_is_track2(client_class):
    '''
    Return whether this client is track2 (autorestv3)
    '''
    # Possible alternative:
    #return "credential" in inspect.getfullargspec(client_class.__init__).args
    return not issubclass(client_class, msrest.service_client.SDKClient)

def op_thread_get(op):
    '''
    Make a best effort to extract the thread from an LRO op.
    Returns None if it cannot be figured out.
    Intended for use in logging errors; do not rely on this for manipulating the thread.
    '''
    try:
        return op.thread_get()
    except AttributeError:
        pass
    try:
        return getattr(op, '_thread')
    except AttributeError:
        pass
    return None

class LaaSO_AzureIdentityCredentialAdapter(msrest.authentication.BasicTokenAuthentication):
    '''
    Adapt any azure-identity credential to work with SDK that needs azure.common.credentials or msrestazure.
    This is only used to use azure.identity credentials with pre-track2 SDK clients.
    track2+ SDK clients must not get this wrapper.
    Derived from: https://github.com/jongio/azidext/blob/master/python/azure_identity_credential_adapter.py
    resource_id is something like 'https://management.azure.com/.default'
    '''
    def __init__(self, logger, credential, resource_id, **kwargs):
        super().__init__(None)
        self.logger = logger
        self._laaso_credential = credential
        self._laaso_resource_id = resource_id
        self._policy = azure.core.pipeline.policies.BearerTokenCredentialPolicy(self._laaso_credential, self._laaso_resource_id, **kwargs)

    def __repr__(self):
        return "<%s,%s,%r,%r>" % (type(self).__name__, hex(id(self)), self._laaso_credential, self._laaso_resource_id)

    def get_token(self, *args, **kwargs):
        '''
        Trivial wrapper to expose get_token() from the real credential
        '''
        return self._laaso_credential.get_token(*args, **kwargs)

    def set_token(self):
        '''
        Wrapper around set_token() to handle retries
        '''
        msapicall(self.logger, self._set_token)

    def _set_token(self):
        '''
        Ask the azure-core BearerTokenCredentialPolicy policy to get a token.
        Using the policy gives us for free the caching system of azure-core.
        We could make this code simpler by using private method, but by definition
        I can't assure they will be there forever, so mocking a fake call to the policy
        to extract the token, using 100% public API.
        '''
        request = azure.core.pipeline.PipelineRequest(azure.core.pipeline.transport.HttpRequest('AzureIdentityCredentialAdapter', "https://fakeurl"),
                                                      azure.core.pipeline.PipelineContext(None))
        self._policy.on_request(request)
        # Read Authorization, and get the second part after Bearer
        token = request.http_request.headers["Authorization"].split(" ", 1)[1]
        self.token = {'access_token' : token}

    def signed_session(self, session=None):
        '''
        Wrapper to set_token() before doing the signed_session() work.
        '''
        self.set_token()
        return super().signed_session(session)

class AzLoginCredential(azure.identity._credentials.azure_cli.AzureCliCredential): # pylint: disable=protected-access
    '''
    azure.identity.azure_cli._credentials.AzureCliCredential with retries to harden
    behavior in the face of transient errors, slow responses, etc.
    TODO: https://msazure.visualstudio.com/One/_workitems/edit/8816973
          When available, use azure-identity>=1.6.0 and DeviceCodeCredential
          (chained credential can be the multi-purpose wrapper if that helps)
    '''
    def __init__(self, logger, *args, **kwargs):
        self._laaso_logger = logger
        super().__init__(*args, **kwargs)

    # Set this really long. This gives the user a chance to notice
    # that there is a problem and redo "az login --use-device-code"
    # (or whatever) without having the application terminate.
    LAASO_GET_TOKEN_MAX_SECONDS = 3600

    def get_token(self, *args, **kwargs):
        '''
        Wrap super-get_token() with retries.
        This is fine for handling expired auth; it will retry for LAASO_GET_TOKEN_MAX_SECONDS seconds,
        then give up. During that time the user has the opportunity to notice and re-auth,
        but the application won't get stuck running forever.
        This is less than perfect for the usual problem, which is that AzureCliCredential
        shells out to az to query the token. That strategy maintains the abstraction boundary
        between az-cli and azure-identity. That boundary is important because the two have
        incompatible requirements and cannot be installed in the same virtualenv.
        Unfortunately, azure-identity has no hooks to let us control the 10-second timeout
        calling az, so the best we can do is just keep hammering and hoping.
        '''
        logger = _logger_for_obj(self)
        deadline = time.time() + self.LAASO_GET_TOKEN_MAX_SECONDS
        while True:
            try:
                return super().get_token(*args, **kwargs)
            except Exception as exc:
                if time.time() >= deadline:
                    logger.error("%s.%s giving up", type(self).__name__, getframename(0))
                    raise
                logger.warning("%s.%s did not succeed; will retry after %r", type(self).__name__, getframename(0), exc)
                time.sleep(0.5)
