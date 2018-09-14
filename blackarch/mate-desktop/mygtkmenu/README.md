# BlackArch - Openbox menu items for other desktops

## About

Files in this directory aim to offer all BlackArch penetration tools for users who use unsupported desktop environments such as MATE, KDE/Plasma or Gnome.

Normally, BlackArch penetration and hacking tools are available only for users of simple desktops (Openbox, i3, ... etc.)

-----------------------

## myGtkmenu

[myGtkmenu](https://sites.google.com/site/jvinla/mygtkmenu) provides a simple application launcher menu for user-defined commands. The menu can be used on multiple Linux desktop environments.

### mygtkitems.sh

This script file aims to parse all Openbox XML menu entries to myGtkmenu compatible format. By default, it creates a valid `$HOME/blackarch.items` menu file for myGtkmenu.

### blackarch.items

A sample menu/command list, parsed from default BlackArch Openbox menu.xml file (you can generate this file yourself by running `bash mygtkitems.sh`)

### blackarch-tools.desktop

A sample desktop entry file for opening myGtkmenu program

-----------------------

## Notes

### Not all Openbox menu entries are visible in myGtkmenu!

As BlackArch Openbox menu.xml contains over 50 submenus, it seems that myGtkmenu has a limitation which limits visible submenu entries to around 20. Therefore, please be aware that not all Openbox menu entries are visible in myGtkmenu launcher!
