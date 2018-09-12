## OWASP Zed Attack Proxy (ZAP) as a Systemd user service for BlackArch Linux

Automate OWASP ZAP start-up with this systemd unit 

-----------------------

### CONTENTS

- PKGBUILD

  - An Arch Linux PKGBUILD script file for OWASP ZAP Systemd service

- zaproxy.service

  - Systemd unit service file to start OWASP ZAP as a *user* service

-----------------------

### HOW-TO
  
1. Download these files
  
2. Run `updpkgsums && makepkg` on Arch Linux

3. (a) Start OWASP ZAP automatically during boot by issuing:

`sudo systemctl enable zaproxy@myuser.service`

3. (b) Start OWASP ZAP manually:

`sudo systemctl start zaproxy@myuser.service`

where myuser is your username (non-root)

  
  
