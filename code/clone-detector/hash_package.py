#! /usr/bin/env python

import hashlib
import json
import os
import sys
import csv


def hash_package(root):
    """
    Compute an md5 hash of all files under root, visiting them in deterministic order.
    `package.json` files are stripped of their `name` and `version` fields.
    """
    m = hashlib.md5()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for filename in sorted(filenames):
            path = os.path.join(dirpath, filename)
            m.update(f"{os.path.relpath(path, root)}\n".encode("utf-8"))
            if filename == "package.json":
                pkg = json.load(open(path))
                pkg["name"] = ""
                pkg["version"] = ""
                m.update(json.dumps(pkg, sort_keys=True).encode("utf-8"))
            else:
                try:
                    with open(path, "rb") as f:
                        m.update(f.read())
                except:
                    print(f'ERROR: path {path}')
    return m.hexdigest()


def add_hash_to_file(root_dir) -> None:
    """
    This function calculates the hash of the packages and saves it to a CSV file named malicious_hash.csv.

    Args:
        root_dir: The full path to the directory that contains the packages

    Returns:
        None
    """
    full_path = "/Users/mdsiam/Desktop/Projects/amalfi-artifact/data"
    file_name = "malicious_hash.csv"
    hash_path = full_path + "/" + file_name

    # Load the existing hashes into a list
    hashes = []
    if os.path.exists(hash_path):
        with open(hash_path, "r") as file:
            for line in file:
                hashes.append(line.strip())

    # Write new hashes to the file
    with open(hash_path, "a") as file:
        for folder in os.listdir(root_dir):
            folder_path = os.path.join(root_dir, folder)
            if os.path.isdir(folder_path):
                hash = hash_package(folder_path)
                if hash not in hashes:
                    file.write(f"{hash}\n")
                    hashes.append(hash)
  
def is_hash_in_csv(root: str, csv_file: str) -> int:
    """
    This function calculates the hash of a package and returns 1 if the hash is in the given CSV file, and 0 otherwise.

    Args:
        root: The root directory of the package to calculate the hash
        csv_file: The path to the CSV file.

    Returns:
        1 if the hash of the directory is in the CSV file, 0 otherwise.
    """
    hash = hash_package(root)
    with open(csv_file, 'r') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            if row[0] == hash:
                return 1
    return 0

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <package directory>", file=sys.stderr)
        print(f"  Prints an md5 hash of all files in the given package directory, ignoring package name and version.", file=sys.stderr)
        sys.exit(1)
    print(hash_package(sys.argv[1]))