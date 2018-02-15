#!/bin/bash

source ~/.bashrc

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
export VIRTUALENV_NAME="memsight"

export WORKON_HOME=$HOME/.virtualenvs
source /usr/local/bin/virtualenvwrapper.sh
workon $VIRTUALENV_NAME

# memsight
echo -e "\n\nTest: regression"
python $DIR/run-all-tests.py

# pitree
echo -e "\n\nTest: pitree"
python $DIR/pitree/test_pitree.py

echo -e "\n\nTest: intervaltree"
python $DIR/pitree/test_intervaltree.py

# angr examples
echo -e "\n\nTest: ais3_crackme"
python $DIR/angr-examples/ais3_crackme/solve.py
echo -e "\n\nTest: asisctffinals2015_license"
python $DIR/angr-examples/asisctffinals2015_license/solve.py
echo -e "\n\nTest: CADET_00001"
python $DIR/angr-examples/CADET_00001/solve.py
echo -e "\n\nTest: codegate_2017-angrybird"
python $DIR/angr-examples/codegate_2017-angrybird/solve.py
echo -e "\n\nTest: defcamp_r100"
python $DIR/angr-examples/defcamp_r100/solve.py
echo -e "\n\nTest: cmu_binary_bomb"
travis_wait 60 python $DIR/angr-examples/cmu_binary_bomb/solve.py
