#!/bin/bash

source ~/.bashrc

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
export VIRTUALENV_NAME="memsight"

export WORKON_HOME=$HOME/.virtualenvs
source /usr/local/bin/virtualenvwrapper.sh
workon $VIRTUALENV_NAME

# memsight
python $DIR/run-all-tests.py

# pitree
python $DIR/pitree/test_pitree.py
python $DIR/pitree/test_intervaltree.py
