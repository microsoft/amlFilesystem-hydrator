# amlFilesystem-hydrator

This file describes how to install and run hydrator.py.

hydrator.py is a Python-based program for importing a Lustre
namespace from an Azure storage account.  Imported files are
left in the 'released'/'exist' Lustre HSM state once imported into
Lustre so they can later be hydrated on-demand by a compatible
copytool.  A copytool is required to hydrate the file contents
from the Azure storage account.

## Supported platforms

This program requires python3.7.  It also requires the Lustre
client to be properly installed, running, and mounted.
Files can only be imported into a mounted Lustre file system.

hydrator.py supports most block blob and append blob storage
account types in Azure, and it supports accounts with and
without the Hierarchical Namespace feature enabled.

## Installing the virtualenv

You must create and install a Python virtual environment
before running hydrator.py.  This environment ensures that
all of the required packages and depdencies are properly
installed and downloaded before using the tool.

Create the virtual environment by running this script
from the root of the repo.  Replace "hydrator_venv" with
the direcory where you would like the virtual env to be installed.

```bash
#!/bin/bash
#
VENV=~/hydrator_venv
REPO_DIR=.
rm -rf $VENV
python3.7 $REPO_DIR/build/venv_create.py $VENV $REPO_DIR/laaso/requirements.txt
```

## Activating the virtualenv

After running the above script, activate the virtualenv using
the following command:

```bash
source  $VENV/bin/activate
```

## Running hydrator.py

Once the virtualenv is activated, you can run hydrator.py
as follows when sitting in the root of the repo with the virtualenv
active.

You must run hydrator.py as the root user since it may need to perform
several operations that require root privileges, such as chown.

The examples provided use the following variables:
* *``mystorageacct``*  refers the the name that you chose for
the storage account when creating it.
* *``mycontainer``* refers to the container that you wish to import within
``mystorageacct``.
* *``mysas``* is a shared access signature (SAS) token generated for
``mystorageacct`` (starting with the ? character) that includes at least
read and list permissions on the blobs and containers.

You must place quotes around the SAS token to ensure that it is
interpreted properly by the command-line parser.

To import an entire storage account container into a Lustre mount at /mnt/lustre:
```bash
(hydrator_venv)# PYTHONPATH=. laaso/hydrator.py "mystorageacct" "mycontainer" "mysas" -a /mnt/lustre --lemur
```

To do the same as the above, but only import blobs whose names start with 
prefix "some/prefix":
```bash
(hydrator_venv)# PYTHONPATH=. laaso/hydrator.py "mystorageacct" "mycontainer" "mysas" -a /mnt/lustre -p "some/prefix" --lemur
```

Note: the --lemur flag is typically required for compatibility with copytools
that are based off of the Lustre [lemur project](https://github.com/edwardsp/lemur).

## Metadata attributes

hydrator.py is capable of setting ownership and permission bits on Lustre
files when they are specified in blob metadata, or when used with the
Hierarchical Namespace (HNS) feature.

For storage accounts that have the Hierarchical Namespace feature enabled (HNS),
the ownership and permission bits are read right out of each object's metadata as
specified in [Data Lake Storage Gen2 | Path - Update](https://docs.microsoft.com/en-us/rest/api/storageservices/datalakestoragegen2/path/update).  Here is an abbreviated reference to the key attributes:
* ``x-ms-owner``: uid
* ``x-ms-group``: gid
* ``x-ms-permissions``: permissions

For non-HNS accounts, you may manually or programatically set these fields in
the metadata for individual blobs and hydrator.py will apply them to the
corresponding files in the Lustre namespace.  If applying them manually via the portal,
use the fields as specified above, minus the 'x-ms-' prefix:
* ``owner``: uid
* ``group``: gid
* ``permissions``: permissions

If applying blob metadata attributes using REST or SDK calls, apply blob
metadata attributes prepended with 'x-ms-meta-': 
* ``x-ms-meta-owner``: uid
* ``x-ms-meta-group``: gid
* ``x-ms-meta-permissions``: permissions

For owner and group, only a numeric uid or gid is supported.

For permissions, both symbolic ``rw-r--r--`` and 4-digit octal ``0644`` notations
are supported.  The sticky bit is also supported using both notations.
Examples which include the sticky bit: ``rwxrwxrwxt`` or ``1777``.

## Microsoft open source code of conduct

This project has adopted the [Microsoft Open Source Code of
Conduct](https://opensource.microsoft.com/codeofconduct/).

For more information see the [Code of Conduct
FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact
[opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional
questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services.
Authorized use of Microsoft trademarks or logos is subject to and must follow
Microsoft's Trademark & Brand Guidelines. Use of Microsoft trademarks or logos
in modified versions of this project must not cause confusion or imply Microsoft
sponsorship. Any use of third-party trademarks or logos are subject to those
third-party's policies.
