#!/bin/bash
echo "alias update='sudo apt update && sudo apt upgrade -y && sudo apt autoremove -y && sudo snap refresh'" > "$HOME/.bash_aliases"
# Update APT
sudo apt-get update
sudo apt update && sudo apt upgrade -y && sudo snap refresh
# NodeJS
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.3/install.sh | bash
nvm install --lts
nvm use --lts
sudo npm install --global yarn
# Chrome
wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
sudo dpkg -i google-chrome-stable_current_amd64.deb
rm google-chrome-stable_current_amd64.deb
# OpenSSL
wget http://archive.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.1f-1ubuntu2_amd64.deb
sudo dpkg -i libssl1.1_1.1.1f-1ubuntu2_amd64.deb
rm libssl1.1_1.1.1f-1ubuntu2_amd64.deb
# Remove LibreOffice
sudo apt remove -y libreoffice*
# Git
sudo apt install -y git
git config --global submodule.recurse true
git config --global user.email "arya@zayalim.xyz"
git config --global user.name "atypdev"
echo "Updates" > ~/.gitmessage
git config --global commit.template ~/.gitmessage
# Python
sudo apt install -y python3
sudo apt install -y python3-pip
pip install --upgrade pip
sudo pip install jupyter && pip install jupyter
sudo pip install matplotlib && pip install matplotlib
# APT Packages
sudo apt install -y libpq-dev
sudo apt install -y docker-compose
sudo apt install -y gnome-boxes 
sudo apt install -y apt-transport-https
sudo apt install -y code
sudo apt install -y software-properties-common
# Snap
sudo apt install -y snapd
sudo snap install discord
sudo snap install onlyoffice-desktopeditors
# Cleanup
sudo apt update && sudo apt upgrade -y && sudo apt autoremove -y && sudo snap refresh
