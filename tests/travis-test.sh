#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
VIRTUALENV_NAME="memsight"

source /usr/local/bin/virtualenvwrapper.sh
workon $VIRTUALENV_NAME

# angr
python $DIR/run_all_tests.py 0

# memsight
python $DIR/run_all_tests.py 1

exit 0