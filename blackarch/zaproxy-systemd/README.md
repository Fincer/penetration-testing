## ZAP Proxy as a Systemd user service for BlackArch Linux

Automate ZAP Proxy start-up with this systemd unit 

-----------------------

### CONTENTS

- PKGBUILD

  - An Arch Linux PKGBUILD script file for ZAP Proxy Systemd service

- zaproxy.service

  - Systemd unit service file to start ZAP Proxy as a *user* service

-----------------------

### HOW-TO
  
1. Download these files
  
2. Run `updpkgsums && makepkg` on Arch Linux

3. (a) Start ZAP Proxy automatically during boot by issuing:

`sudo systemctl enable zaproxy@myuser.service`

3. (b) Start ZAP Proxy manually:

`sudo systemctl start zaproxy@myuser.service`

where myuser is your username (non-root)

  
  
