# ftp-sync

Simple script for synchronizing files over FTPS and SFTP. In addition to the files themselves, the script uploads an index file containing hashes of all uploaded files. This index file is then used to skip unchanged files during the next synchronization.

This strategy was designed specifically for uploading the files of a static website from a continuous integration system. It avoids some drawbacks of similar tools in this scenario.

* `lftp`'s `mirror` command only checks the modification dates of the files. This is useless for files produced by a CI system, which might often be the same but get a new modification date for each run.
* `rsync` needs to be installed on both machines, which is usually not possible if the target machine is a web hosting space.
* `rclone` can skip files based on checksums, but only when connected through SFTP. On web hosting spaces, you probably don't get SSH access. Even if you do, the checksums get computed remotely and expensive computations on the web server are often not accepted by the providers.

## Requirements

- An FTPS or SFTP connection.
- Python 3 on the uploading machine.
- The Python package `paramiko` when using SFTP.

That's it. In particular, the script doesn't require or compute anything on the target machine.

## Usage

For the most simple use, run

```bash
ftp_sync.py --host HOST --user FTP_USER --password PASSWORD some/directory
```

This will upload all files from `some/directory` to the root of the FTP user. Note that files that were uploaded previously, but don't exist locally anymore, will not be deleted by default. If you want to delete these files, specify the `--delete-files` parameter.

These are the complete parameters of the script:

```
usage: ftp_sync.py [-h] --host HOST --user USER --password PASSWORD [--sftp]
                   [--allow-any-host-key] [--delete-files] [--dry-run]
                   [--index-file FILE]
                   LOCAL_PATH [REMOTE_PATH]

positional arguments:
  LOCAL_PATH            directory on the local machine to synchronize
  REMOTE_PATH           path on the remote machine where files get uploaded
                        (default: /)

optional arguments:
  -h, --help            show this help message and exit
  --host HOST           FTP host
  --user USER           FTP user
  --password PASSWORD   FTP password
  --sftp                Connect using SFTP instead of FTPS
  --allow-any-host-key  Allow any host key when connecting to SFTP
  --delete-files        delete files that were uploaded but do not exist
                        locally anymore
  --dry-run             print output only, do not modify any files
  --index-file FILE     filename for the index file (default:
                        ftp_sync.json.gz)
```
