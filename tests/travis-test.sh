#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
VIRTUALENV_NAME="memsight"

source /usr/local/bin/virtualenvwrapper.sh
workon $VIRTUALENV_NAME

# memsight
python $DIR/run-all-tests.py