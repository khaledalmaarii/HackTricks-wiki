# Linux Omgewingsveranderlikes

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## Globale veranderlikes

Die globale veranderlikes **sal geërf word deur kinderprosesse**.

Jy kan 'n globale veranderlike skep vir jou huidige sessie deur die volgende te doen:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Hierdie veranderlike sal toeganklik wees deur jou huidige sessies en sy kinderprosesse.

Jy kan 'n veranderlike **verwyder** deur die volgende te doen:
```bash
unset MYGLOBAL
```
## Plaaslike veranderlikes

Die **plaaslike veranderlikes** kan slegs deur die **huidige skil/skripsie** **toegang** word.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Lys huidige veranderlikes

Om die huidige veranderlikes in die Linux-omgewing te lys, kan jy die volgende opdrag gebruik:

```bash
$ env
```

Hierdie opdrag sal 'n lys van alle huidige veranderlikes vertoon, insluitend die omgewingsveranderlikes wat deur die stelsel en gebruiker gedefinieer is.
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
## Algemene veranderlikes

Vanaf: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

* **DISPLAY** - die vertoning wat deur **X** gebruik word. Hierdie veranderlike is gewoonlik ingestel op **:0.0**, wat die eerste vertoning op die huidige rekenaar beteken.
* **EDITOR** - die voorkeur teksredakteur van die gebruiker.
* **HISTFILESIZE** - die maksimum aantal lyne wat in die geskiedenis-lêer voorkom.
* **HISTSIZE** - Aantal lyne wat by die geskiedenis-lêer gevoeg word wanneer die gebruiker sy sessie voltooi.
* **HOME** - jou tuisgids.
* **HOSTNAME** - die rekenaar se gasheernaam.
* **LANG** - jou huidige taal.
* **MAIL** - die ligging van die gebruiker se posbus. Gewoonlik **/var/spool/mail/USER**.
* **MANPATH** - die lys van gidsbladsy-direktorieë om te soek.
* **OSTYPE** - die tipe bedryfstelsel.
* **PS1** - die verstek-prompt in bash.
* **PATH** - stoor die pad van al die gidsbladsy-direktorieë wat binneruimte lêers bevat wat jy wil uitvoer deur net die naam van die lêer te spesifiseer en nie deur relatiewe of absolute pad nie.
* **PWD** - die huidige werksgids.
* **SHELL** - die pad na die huidige opdragskulp (byvoorbeeld **/bin/bash**).
* **TERM** - die huidige terminaal-tipe (byvoorbeeld **xterm**).
* **TZ** - jou tydsone.
* **USER** - jou huidige gebruikersnaam.

## Interessante veranderlikes vir hakwerk

### **HISTFILESIZE**

Verander die **waarde van hierdie veranderlike na 0**, sodat wanneer jy **jou sessie beëindig**, die **geskiedenis-lêer** (\~/.bash\_history) **verwyder sal word**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Verander die **waarde van hierdie veranderlike na 0**, sodat wanneer jy **jou sessie beëindig**, enige opdrag nie by die **geskiedenis lêer** (\~/.bash\_history) gevoeg sal word nie.
```bash
export HISTSIZE=0
```
### http\_proxy & https\_proxy

Die prosesse sal die hier verklaarde **proxy** gebruik om via **http of https** met die internet te verbind.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### SSL\_CERT\_FILE & SSL\_CERT\_DIR

Die prosesse sal die sertifikate vertrou wat in **hierdie omgewingsveranderlikes** aangedui word.
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### PS1

Verander hoe jou prompt lyk.

[**Hier is 'n voorbeeld**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![](<../.gitbook/assets/image (87).png>)

Gewone gebruiker:

![](<../.gitbook/assets/image (88).png>)

Een, twee en drie agtergrondwerk:

![](<../.gitbook/assets/image (89).png>)

Een agtergrondwerk, een gestop en laaste opdrag het nie korrek geëindig nie:

![](<../.gitbook/assets/image (90).png>)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>
