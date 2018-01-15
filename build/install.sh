#!/bin/bash -e

VIRTUALENV_NAME="memsight"

# update apt
echo "Updating apt..."
sudo apt-get update >/dev/null || true

# dependencies
echo "Installing dependencies..."
sudo apt-get install -y sudo nano python-pip time git python-dev build-essential
sudo -H pip install -U pip

# virtualenv
echo "Creating virtualenv"
sudo -H pip install virtualenv virtualenvwrapper
pip install virtualenvwrapper
export WORKON_HOME=$HOME/.virtualenvs
source /usr/local/bin/virtualenvwrapper.sh
mkvirtualenv $VIRTUALENV_NAME || true
echo "export WORKON_HOME=$HOME/.virtualenvs" >> ~/.bashrc
echo "source /usr/local/bin/virtualenvwrapper.sh" >> ~/.bashrc
echo "workon memsight" >> ~/.bashrc || true
# workon memsight

# clone
echo "Cloning..."
if [ ! -d "memsight" ]; then
    cd ~
    git clone git@github.com:season-lab/fully-symbolic-memory.git memsight
fi

# angr stuff
echo "Installing angr..."
pip install -r memsight/requirements.txt
pip install -I --no-use-wheel capstone==3.0.4 # fix error import

# patches
echo "Applying patches"
cd ~/.virtualenvs/$VIRTUALENV_NAME/lib/python2.7/site-packages/
patch -p1 < ~/memsight/build/0001-Fix-endianness.patch
patch -p1 < ~/memsight/build/0001-Errored-isn-t-a-real-stash-anymore-paths-don-t-exist.patch

exit 0
