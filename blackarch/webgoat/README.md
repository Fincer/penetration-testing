## OWASP WebGoat for BlackArch Linux

This folder has files for installing OWASP WebGoat on BlackArch Linux. 

-----------------------

### CONTENTS

- PKGBUILD

  - Original source: [Arch Linux AUR database - webgoat/PKGBUILD](https://aur.archlinux.org/cgit/aur.git/tree/PKGBUILD?h=webgoat)
  
  - An Arch Linux PKGBUILD script file for OWASP WebGoat

- webgoat.sh

  - Original source: [Arch Linux AUR database - webgoat/webgoat.sh](https://aur.archlinux.org/cgit/aur.git/tree/webgoat.sh?h=webgoat)

  - A simple shell script executable for webgoat.service, installed as /usr/bin/webgoat

- webgoat.service

  - Systemd unit service file to start OWASP WebGoat as a *user* service

-----------------------

### HOW-TO
  
1. Download these files
  
2. Run `updpkgsums && makepkg` on Arch Linux

3. (a) Start WebGoat automatically during boot by issuing:

`sudo systemctl enable webgoat@myuser.service`

3. (b) Start WebGoat manually:

`sudo systemctl start webgoat@myuser.service`

where myuser is your username (non-root)

4. Open WebGoat login page URL after a while:

`http://localhost:1234/WebGoat/login`


  
  
