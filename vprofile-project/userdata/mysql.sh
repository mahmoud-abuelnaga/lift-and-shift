#!/bin/bash
database_user='admin'
database_pass='admin123'

sudo dnf upgrade -y
sudo dnf install git zip unzip -y
sudo dnf install mariadb105-server -y
# starting & enabling mariadb-server
sudo systemctl enable --now mariadb
cd /tmp/
git clone -b main https://github.com/hkhcoder/vprofile-project.git
#restore the dump file for the application
sudo mysqladmin -u root password "$database_pass"
sudo mysql -u root -p"$database_pass" -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '$database_pass'"
sudo mysql -u root -p"$database_pass" -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1')"
sudo mysql -u root -p"$database_pass" -e "DELETE FROM mysql.user WHERE User=''"
sudo mysql -u root -p"$database_pass" -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\_%'"
sudo mysql -u root -p"$database_pass" -e "FLUSH PRIVILEGES"
sudo mysql -u root -p"$database_pass" -e "create database accounts"
sudo mysql -u root -p"$database_pass" -e "grant all privileges on accounts.* TO '$database_user'@'localhost' identified by 'admin123'"
sudo mysql -u root -p"$database_pass" -e "grant all privileges on accounts.* TO '$database_user'@'%' identified by 'admin123'"
sudo mysql -u root -p"$database_pass" accounts < /tmp/vprofile-project/src/main/resources/db_backup.sql
sudo mysql -u root -p"$database_pass" -e "FLUSH PRIVILEGES"
sudo rm -rf /tmp/vprofile-project
sudo dnf remove git -y
