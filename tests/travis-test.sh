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

# angr examples
python $DIR/angr-examples/ais3_crackme/solve.py
python $DIR/angr-examples/asisctffinals2015_license/solve.py
python $DIR/angr-examples/CADET_00001/solve.py
python $DIR/angr-examples/cmu_binary_bomb/solve.py
python $DIR/angr-examples/codegate_2017-angrybird/solve.py