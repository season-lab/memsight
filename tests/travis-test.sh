#!/bin/bash

source ~/.bashrc

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
export VIRTUALENV_NAME="memsight"

export WORKON_HOME=$HOME/.virtualenvs
source /usr/local/bin/virtualenvwrapper.sh
workon $VIRTUALENV_NAME

# memsight
echo "Test: regression"
time python $DIR/run-all-tests.py

# pitree
echo "Test: pitree"
time python $DIR/pitree/test_pitree.py

echo "Test: intervaltree"
time python $DIR/pitree/test_intervaltree.py

# angr examples
echo "Test: ais3_crackme"
time python $DIR/angr-examples/ais3_crackme/solve.py
echo "Test: asisctffinals2015_license"
time python $DIR/angr-examples/asisctffinals2015_license/solve.py
echo "Test: CADET_00001"
time python $DIR/angr-examples/CADET_00001/solve.py
echo "Test: cmu_binary_bomb"
time python $DIR/angr-examples/cmu_binary_bomb/solve.py
echo "Test: codegate_2017-angrybird"
time python $DIR/angr-examples/codegate_2017-angrybird/solve.py