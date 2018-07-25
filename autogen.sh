#!/bin/sh -x

set -e

if test -d ".git" ; then
    force=$(if git submodule usage 2>&1 |grep --quiet 'update.*--force'; then echo --force; fi)
    if ! git submodule sync || ! git submodule update $force --init --recursive; then
	echo "Error: could not initialize submodule projects"
	echo "Network connectivity might be required."
	exit 1
    fi
fi
