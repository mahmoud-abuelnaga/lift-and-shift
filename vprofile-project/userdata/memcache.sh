#!/bin/bash
sudo dnf upgrade -y
sudo dnf install memcached -y
sudo systemctl enable --now memcached
sed -i 's/127.0.0.1/0.0.0.0/g' /etc/sysconfig/memcached
sudo systemctl restart memcached
