#!/bin/bash -e

VIRTUALENV_NAME="memsight"

# update apt
echo "Updating apt..."
sudo apt-get update >/dev/null || true

# dependencies
echo "Installing dependencies..."
sudo apt-get install -y sudo nano python-pip time git python-dev build-essential

# virtualenv
echo "Creating virtualenv"
sudo pip install virtualenv virtualenvwrapper
export WORKON_HOME=$HOME/.virtualenvs
source /usr/local/bin/virtualenvwrapper.sh
mkvirtualenv $VIRTUALENV_NAME
workon memsight

# angr stuff
echo "Installing angr..."
sudo pip install -r requirements.txt

# patches
echo "Applying patches"
cd ~/.virtualenvs/$VIRTUALENV_NAME/lib/python2.7/site-packages/
patch -p1 < build/0001-Fix-wrong-ancestry-in-path-merging-issue-761-772.patch
cd ~
