# Linux Omgewingsveranderlikes

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kontroleer die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

**Try Hard Security Group**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## Globale veranderlikes

Die globale veranderlikes **sal** geërf word deur **kindprosesse**.

Jy kan 'n globale veranderlike vir jou huidige sessie skep deur te doen:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Hierdie veranderlike sal toeganklik wees vir jou huidige sessies en sy kinderprosesse.

Jy kan 'n veranderlike **verwyder** deur:
```bash
unset MYGLOBAL
```
## Plaaslike veranderlikes

Die **plaaslike veranderlikes** kan slegs deur die **huidige skil/skripsie** **benader** word.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Lys huidige veranderlikes
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
## Algemene veranderlikes

Van: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

* **DISPLAY** – die vertoning wat deur **X** gebruik word. Hierdie veranderlike is gewoonlik ingestel op **:0.0**, wat die eerste vertoning op die huidige rekenaar beteken.
* **EDITOR** – die gebruiker se voorkeur teksredigeerder.
* **HISTFILESIZE** – die maksimum aantal lyne wat in die geskiedenis lêer bevat word.
* **HISTSIZE** – Aantal lyne wat by die geskiedenis lêer gevoeg word wanneer die gebruiker sy sessie afsluit.
* **HOME** – jou tuisgids.
* **HOSTNAME** – die rekenaar se gasnaam.
* **LANG** – jou huidige taal.
* **MAIL** – die ligging van die gebruiker se posbus. Gewoonlik **/var/spool/mail/USER**.
* **MANPATH** – die lys van gids om vir handleidingsbladsye te soek.
* **OSTYPE** – die tipe bedryfstelsel.
* **PS1** – die verstek aanduiding in bash.
* **PATH** – stoor die pad van al die gids waarin binêre lêers gehou word wat jy wil uitvoer deur net die naam van die lêer te spesifiseer en nie deur relatiewe of absolute pad nie.
* **PWD** – die huidige werksgids.
* **SHELL** – die pad na die huidige opdragskil (byvoorbeeld, **/bin/bash**).
* **TERM** – die huidige terminaal tipe (byvoorbeeld, **xterm**).
* **TZ** – jou tydsone.
* **USER** – jou huidige gebruikersnaam.

## Interessante veranderlikes vir hak

### **HISTFILESIZE**

Verander die **waarde van hierdie veranderlike na 0**, sodat wanneer jy **jou sessie afsluit** die **geskiedenis lêer** (\~/.bash\_history) **verwyder sal word**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Verander die **waarde van hierdie veranderlike na 0**, sodat wanneer jy **jou sessie beëindig** enige opdrag by die **geskiedenis lêer** (\~/.bash\_history) toegevoeg sal word.
```bash
export HISTSIZE=0
```
### http\_proxy & https\_proxy

Die prosesse sal die **proxy** wat hier verklaar is, gebruik om aan die internet te koppel deur **http of https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### SSL_CERT_FILE & SSL_CERT_DIR

Die prosesse sal die sertifikate vertrou wat in **hierdie omgewingsveranderlikes** aangedui word.
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### PS1

Verander hoe jou aanduiding lyk.

[**Hierdie is 'n voorbeeld**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![](<../.gitbook/assets/image (897).png>)

Gewone gebruiker:

![](<../.gitbook/assets/image (740).png>)

Een, twee en drie agtergrondtake:

![](<../.gitbook/assets/image (145).png>)

Een agtergrondtaak, een gestop en laaste bevel het nie korrek afgehandel nie:

![](<../.gitbook/assets/image (715).png>)

**Probeer Hard Security Group**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>Leer AWS hak vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien jou **maatskappy geadverteer in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PRs in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
