#!/bin/bash -e

VIRTUALENV_NAME="memsight"

# update apt
echo "Updating apt..."
sudo apt-get update >/dev/null || true

# dependencies
echo "Installing dependencies..."
sudo apt-get install -y sudo nano python-pip time git python-dev build-essential
sudo pip install -U pip

# virtualenv
echo "Creating virtualenv"
sudo pip install virtualenv virtualenvwrapper
export WORKON_HOME=$HOME/.virtualenvs
source /usr/local/bin/virtualenvwrapper.sh
mkvirtualenv $VIRTUALENV_NAME || true
# workon memsight

# clone
echo "Cloning..."
if [ ! -d "memsight" ]; then
    git clone git@github.com:season-lab/fully-symbolic-memory.git memsight
fi

# angr stuff
echo "Installing angr..."
pip install -r memsight/requirements.txt

# patches
echo "Applying patches"
ls ~/.virtualenvs/
cd ~/.virtualenvs/$VIRTUALENV_NAME/lib/python2.7/site-packages/angr
patch -p1 < ~/memsight/build/0001-Fix-wrong-ancestry-in-path-merging-issue-761-772.patch
cd ~

exit 0