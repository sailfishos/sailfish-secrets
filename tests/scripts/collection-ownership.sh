#!/bin/sh

# This script must be run within a devel-su -p shell
# The daemon must be running in autotest mode (with --test option)

# TODO: this script should fork, the child should drop privileges
# then the script should test that collections created by one process
# cannot be accessed by collections created by the other, due to the
# access contraints (OwnerOnly).
