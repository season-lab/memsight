#!/bin/bash -e

VIRTUALENV_NAME="memsight"
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

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

source build/local-pip-install.sh

exit 0
