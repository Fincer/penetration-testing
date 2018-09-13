#!/bin/env bash

#    Simple Openbox to myGtkmenu menu items parser
#    Copyright (C) 2018  Pekka Helenius
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.

####################################################

# Obenbox menu file
# Default: /etc/xdg/openbox/menu.xml

OB_MENUFILE="/etc/xdg/openbox/menu.xml"

# myGtkMenu output menu file
# Default: ${HOME}/mygtkmenu.items

GTK_MENUFILE="${HOME}/mygtkmenu.items"

# Icon for menu categories
ICON_MENU="/usr/share/icons/Humanity/actions/24/stock_right.svg"

# Icon for menu items
ICON_CMD="/usr/share/icons/Humanity/apps/24/terminal.svg"

##########################

# Slash conversion for sed stream:

ICON_MENU=$(printf "${ICON_MENU}" | sed 's|/|\\/|g')
ICON_CMD=$(printf "${ICON_CMD}" | sed 's|/|\\/|g')

##########################

echo -e "\niconsize = 25\n" > "${GTK_MENUFILE}"

[ $? -ne 0 ] && exit 1

##########################

# Line count
i_all=$(grep -E "<command>|<item label|<menu id" "${OB_MENUFILE}" | wc -l)

i=1
IFS=$'\n'
for item in $(
grep -oE "<menu id=\"*.*\" label|
<item label=\"*.*\">$|
<command>*.*<\/command>$" "${OB_MENUFILE}"
); 
do
echo -en "Writing item line parameter $i of $i_all ( $(( (100 * $i / $i_all) ))% ) \r"
echo $item | sed -E \
"
s/\"//g; 
s/=/ = /g; 
s/^<command>(.*)/    cmd = \1\n    icon = ${ICON_CMD}\n/g; 
s/<\/command>//g; 
s/<item label/    item/g; 
s/>//g;
s/^<menu id = (blackarch\-?)+?([a-z])(.*)(\-.*)/\nSEPARATOR\nSubmenu = \U\2\L\3\E\n    icon = ${ICON_MENU}\n/g;
" \
>> "${GTK_MENUFILE}"; let i++;
done

# https://www.gnu.org/software/sed/manual/html_node/The-_0022s_0022-Command.html

##########################

[ $? -ne 0 ] && exit 1

# If the line contains 'item = ' and is followed by an empty line, delete item.
#
sed -i '/item = /{$!N;/\n\n*$/!P;D}' "${GTK_MENUFILE}"

# If the last line does not have 'icon =', delete it:
sed -i '${/icon = /!d;}' "${GTK_MENUFILE}"

##########################

echo -e "Success! Use the generated menu file with myGtkmenu. A sample desktop file for myGtkmenu is found at \n\n\
https://github.com/Fincer/penetration-testing/blob/master/blackarch/mate-desktop/mygtkmenu/blackarch-tools.desktop \
\n"

exit 0
