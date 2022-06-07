#!/usr/bin/env python3

import argparse
import ftplib
import gzip
import hashlib
import io
import json
import os

from typing import List


def hash_file(filename: str) -> str:
    BLOCK_SIZE = 65536

    file_hash = hashlib.sha256()
    with open(filename, "rb") as f:
        block = f.read(BLOCK_SIZE)
        while len(block) > 0:
            file_hash.update(block)
            block = f.read(BLOCK_SIZE)

    return file_hash.hexdigest()


def split_path(path: str) -> List[str]:
    parts = []
    while True:
        path, last = os.path.split(path)
        if last:
            parts.append(last)
        elif path:
            parts.append(path)
            break
        else:
            break

    parts.reverse()
    return parts


class FtpsConnection:
    def __init__(self, host: str, user: str, password: str):
        self._connect_ftp(host, user, password)

    def _connect_ftp(self, host: str, user: str, password: str):
        self._ftp_client = ftplib.FTP_TLS(host)

        # Secure connection.
        self._ftp_client.auth()
        self._ftp_client.prot_p()

        self._ftp_client.login(user, password)

    def download_file(self, filename: str) -> bytes:
        buffer = io.BytesIO()
        self._ftp_client.retrbinary("RETR " + filename, buffer.write)
        return buffer.getvalue()

    def ensure_directory_exists(self, directory):
        path = ""
        for path_part in split_path(directory):
            path = os.path.join(path, path_part)
            if not path:
                continue

            try:
                self._ftp_client.mkd(path)
            except ftplib.error_perm as e:
                if str(e)[:3] != "550":
                    # Error 550 means action not taken. Probably, because the directory already
                    # exists.
                    raise

    def upload_file(self, filename: str, remote_filename: str):
        self.ensure_directory_exists(os.path.dirname(remote_filename))

        with open(filename, "rb") as f:
            self._ftp_client.storbinary("STOR " + remote_filename, f)

    def upload_data(self, data: bytes, remote_filename: str):
        self.ensure_directory_exists(os.path.dirname(remote_filename))

        buffer = io.BytesIO(data)
        self._ftp_client.storbinary("STOR " + remote_filename, buffer)

    def delete_file(self, filename: str):
        self._ftp_client.delete(filename)


class IndexFile:
    def __init__(self, data: bytes = None):
        self._file_hashes = {}

        if data is not None:
            self._file_hashes = json.loads(gzip.decompress(data).decode())

    def set_hash(self, filename: str, file_hash: str):
        self._file_hashes[filename] = file_hash

    def get_hash(self, filename: str) -> str:
        return self._file_hashes[filename]

    def file_changed(self, filename: str, file_hash: str) -> bool:
        if filename not in self._file_hashes:
            return True
        return self._file_hashes[filename] != file_hash

    def uploaded_files(self) -> List[str]:
        return self._file_hashes.keys()

    def dump(self) -> bytes:
        return gzip.compress(json.dumps(self._file_hashes).encode())

    def __eq__(self, other: "IndexFile") -> bool:
        return self._file_hashes == other._file_hashes

    def __ne__(self, other: "IndexFile") -> bool:
        return not (self == other)


def synchronize(
    connection: FtpsConnection,
    sync_directory: str,
    remote_directory: str,
    index_file: str,
    delete_files: bool,
    dry_run: bool,
):
    index_file_path = os.path.join(remote_directory, index_file)

    print("Download index file...")
    try:
        index_data = connection.download_file(index_file_path)
    except ftplib.error_perm:
        index_data = None
        print("Downloading index failed. Using an empty index.")

    uploaded_index = IndexFile(index_data)
    new_index = IndexFile()

    # Delete files that don't exist locally anymore.
    # Note that this is done first in case paths are not unique and we want to upload a file with
    # a different path than it had before. This can happen, e.g. when using '' and '/' as the
    # remote base directory.
    num_files_deleted = 0
    for relative_filename in uploaded_index.uploaded_files():
        local_filename = os.path.join(sync_directory, relative_filename)
        if not os.path.exists(local_filename):
            if delete_files:
                print("Delete file '{}'...".format(relative_filename))
                if not dry_run:
                    remote_filename = os.path.join(remote_directory, relative_filename)
                    connection.delete_file(remote_filename)
                num_files_deleted += 1
            else:
                # Add the file to the new index to keep track of the file even if it doesn't exist
                # locally anymore. We might want to delete it next time when the script is allowed
                # to delete files.
                new_index.set_hash(
                    relative_filename, uploaded_index.get_hash(relative_filename)
                )

    # Upload new files and files that changed compared to when they were uploaded the last time.
    num_files_uploaded = 0
    for base_directory, _, files in os.walk(sync_directory):
        for file in files:
            local_filename = os.path.join(base_directory, file)
            relative_filename = os.path.relpath(local_filename, sync_directory)
            remote_filename = os.path.join(remote_directory, relative_filename)

            file_hash = hash_file(local_filename)
            new_index.set_hash(relative_filename, file_hash)

            if uploaded_index.file_changed(relative_filename, file_hash):
                print("Upload '{}'...".format(relative_filename))
                if not dry_run:
                    connection.upload_file(local_filename, remote_filename)
                num_files_uploaded += 1

    if new_index != uploaded_index and not dry_run:
        print("Upload index file...")
        connection.upload_data(new_index.dump(), index_file_path)

    if num_files_uploaded == 0 and num_files_deleted == 0:
        print("Nothing to do.")
    else:
        if num_files_deleted != 0:
            print("Deleted {} files.".format(num_files_deleted))
        if num_files_uploaded != 0:
            print("Uploaded {} files.".format(num_files_uploaded))
        print("Done.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True, help="FTP host")
    parser.add_argument("--user", required=True, help="FTP user")
    parser.add_argument("--password", required=True, help="FTP password")
    parser.add_argument(
        "--delete-files",
        action="store_true",
        help="delete files that were uploaded but do not exist locally anymore",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print output only, do not modify any files",
    )
    parser.add_argument(
        "--index-file",
        metavar="FILE",
        default="ftp_sync.json.gz",
        help="filename for the index file (default: %(default)s)",
    )
    parser.add_argument(
        "local_path",
        metavar="LOCAL_PATH",
        help="directory on the local machine to synchronize",
    )
    parser.add_argument(
        "remote_path",
        metavar="REMOTE_PATH",
        nargs="?",
        default="/",
        help="path on the remote machine where files get uploaded (default: %(default)s)",
    )

    args = parser.parse_args()

    connection = FtpsConnection(args.host, args.user, args.password)
    synchronize(
        connection,
        args.local_path,
        args.remote_path,
        args.index_file,
        args.delete_files,
        args.dry_run,
    )


if __name__ == "__main__":
    main()
