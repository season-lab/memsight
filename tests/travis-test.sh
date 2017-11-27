#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
VIRTUALENV_NAME="memsight"

source /usr/local/bin/virtualenvwrapper.sh
workon $VIRTUALENV_NAME
python $DIR/run_all_tests.py

exit 0