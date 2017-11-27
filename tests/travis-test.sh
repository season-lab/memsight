#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
VIRTUALENV_NAME="memsight"

export WORKON_HOME=$HOME/.virtualenvs
source /usr/local/bin/virtualenvwrapper.sh
workon $VIRTUALENV_NAME

# memsight
python $DIR/run-all-tests.py