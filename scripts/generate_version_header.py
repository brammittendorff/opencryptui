#!/usr/bin/env python3

# generate_version_header.py
import subprocess

def get_git_tag():
    try:
        return subprocess.check_output(["git", "describe", "--tags", "--abbrev=0"]).strip().decode()
    except subprocess.CalledProcessError:
        return "unknown"

def get_git_commit_hash():
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"]).strip().decode()
    except subprocess.CalledProcessError:
        return "unknown"

def main():
    tag = get_git_tag()
    commit_hash = get_git_commit_hash()

    with open("version.h", "w") as f:
        f.write("#ifndef VERSION_H\n")
        f.write("#define VERSION_H\n")
        f.write(f'#define GIT_TAG "{tag}"\n')
        f.write(f'#define GIT_COMMIT_HASH "{commit_hash}"\n')
        f.write("#endif // VERSION_H\n")

if __name__ == "__main__":
    main()
