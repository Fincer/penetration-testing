# Various settings & tools for BlackArch Linux

-------------------

## CONTENTS

### mate-desktop

-  BlackArch penetration tools configuration for [MATE desktop](mate-desktop.org)


### webgoat

- Installs [OWASP WebGoat](https://www.owasp.org/index.php/WebGoat_Installation) on BlackArch Linux with the official package manager `pacman`. 

- Adds WebGoat as a new Systemd user service which can be started during system boot-up.


### zaproxy-systemd

- Adds [OWASP Zed Attack Proxy (ZAP)](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project) as a new Systemd user service which can be started during system boot-up.

-------------------

## MISCELLANEOUS

Start OpenVPN automatically during system boot-up:

```
sudo systemctl enable openvpn-client@myuser.service
```
