# euid, ruid, suid

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersecurity-maatskappy**? Wil jy jou **maatskappy adverteer in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of laai HackTricks in PDF af**? Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die [hacktricks repo](https://github.com/carlospolop/hacktricks) en [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

### Gebruikersidentifikasie Veranderlikes

- **`ruid`**: Die **werklike gebruikers-ID** dui die gebruiker aan wat die proses geïnisieer het.
- **`euid`**: Bekend as die **effektiewe gebruikers-ID**, verteenwoordig dit die gebruikersidentiteit wat deur die stelsel gebruik word om prosesbevoegdhede te bepaal. Gewoonlik weerspieël `euid` `ruid`, behalwe in gevalle soos 'n SetUID-binêre uitvoering, waar `euid` die identiteit van die lêereienaar aanneem en dus spesifieke bedryfsbevoegdhede verleen.
- **`suid`**: Hierdie **gebergde gebruikers-ID** is van kardinale belang wanneer 'n hoë-bevoegdheidsproses (gewoonlik as root uitgevoer) tydelik sy bevoegdhede moet opgee om sekere take uit te voer, slegs om later sy oorspronklike verhoogde status te herwin.

#### Belangrike Nota
'n Proses wat nie as root werk nie, kan slegs sy `euid` wysig om ooreen te stem met die huidige `ruid`, `euid` of `suid`.

### Begrip van set*uid Funksies

- **`setuid`**: In teenstelling met aanvanklike aannames, wysig `setuid` hoofsaaklik `euid` eerder as `ruid`. Spesifiek vir bevoorregte prosesse stem dit `ruid`, `euid` en `suid` af op die gespesifiseerde gebruiker, dikwels root, en versterk sodoende hierdie ID's as gevolg van die oorskrywing van `suid`. Gedetailleerde insigte is beskikbaar in die [setuid man-bladsy](https://man7.org/linux/man-pages/man2/setuid.2.html).
- **`setreuid`** en **`setresuid`**: Hierdie funksies maak die fynafstelling van `ruid`, `euid` en `suid` moontlik. Hul vermoëns is egter afhanklik van die bevoorregtingsvlak van die proses. Vir nie-root prosesse is wysigings beperk tot die huidige waardes van `ruid`, `euid` en `suid`. Daarenteen kan rootprosesse of dié met die `CAP_SETUID`-vermoë arbitêre waardes aan hierdie ID's toewys. Meer inligting is beskikbaar in die [setresuid man-bladsy](https://man7.org/linux/man-pages/man2/setresuid.2.html) en die [setreuid man-bladsy](https://man7.org/linux/man-pages/man2/setreuid.2.html).

Hierdie funksionaliteite is nie ontwerp as 'n sekuriteitsmeganisme nie, maar om die bedoelde bedryfsvloei te fasiliteer, soos wanneer 'n program 'n ander gebruiker se identiteit aanneem deur sy effektiewe gebruikers-ID te verander.

Dit is veral belangrik om te onderskei tussen hierdie funksies om gebruikers-ID-gedrag in verskillende scenario's te verstaan en te manipuleer, alhoewel `setuid` dikwels gebruik word vir bevoorregte verhoging na root (aangesien dit alle ID's op root afstem).

### Programuitvoeringsmeganismes in Linux

#### **`execve`-Stelseloproep**
- **Funksionaliteit**: `execve` inisieer 'n program wat bepaal word deur die eerste argument. Dit neem twee reeksargumente, `argv` vir argumente en `envp` vir die omgewing.
- **Gedrag**: Dit behou die geheue van die oproeper, maar verfris die stapel, heap en data-segmente. Die kode van die program word vervang deur die nuwe program.
- **Behoud van Gebruikers-ID**:
- `ruid`, `euid` en aanvullende groep-ID's bly onveranderd.
- `euid` kan subtiel verander as die nuwe program die SetUID-bit ingestel het.
- `suid` word na uitvoering van `euid` opgedateer.
- **Dokumentasie**: Gedetailleerde inligting is beskikbaar op die [`execve` man-bladsy](https://man7.org/linux/man-pages/man2/execve.2.html).

#### **`system`-Funksie**
- **Funksionaliteit**: In teenstelling met `execve` skep `system` 'n kinderproses deur `fork` te gebruik en voer 'n opdrag binne daardie kinderproses uit met behulp van `execl`.
- **Opdraguitvoering**: Voer die opdrag uit via `sh` met `execl("/bin/sh", "sh", "-c", opdrag, (char *) NULL);`.
- **Gedrag**: Aangesien `execl` 'n vorm van `execve` is, werk dit op 'n soortgelyke manier, maar in die konteks van 'n nuwe kinderproses.
- **Dokumentasie**: Verdere insigte kan verkry word uit die [`system` man-bladsy](https://man7.org/linux/man-pages/man3/system.3.html).

#### **Gedrag van `bash` en `sh` met SUID**
- **`bash`**:
- Het 'n `-p`-opsie wat beïnvloed hoe `euid` en `ruid` hanteer word.
- Sonder `-p` stel `bash` `euid` in op `ruid` as hulle aanvanklik verskil.
- Met `-p` word die aanvanklike `euid` behou.
- Meer besonderhede is beskikbaar op die [`bash` man-bladsy](https://linux.die.net/man/1/bash).
- **`sh`**:
- Besit nie 'n meganisme soortgelyk aan `-p` in `bash` nie.
- Die gedrag met betrekking tot gebruikers-ID's word nie uitdruklik genoem nie, behalwe onder die `-i`-opsie, wat beklemtoon dat `euid` en `ruid` gelyk bly.
- Addisionele inligting is beskikbaar op die [`sh` man-bladsy](https://man7.org/linux/man-pages/man1/sh.1p.html).

Hierdie meganismes, wat verskil in hul werking, bied 'n veelsydige reeks opsies vir die uitvoering en oorgang tussen programme, met spesifieke subtiliteite in hoe gebruikers-ID's bestuur en behou word.

### Toetsing van Gebruikers-ID-Gedrag in Uitvoerings

Voorbeelde geneem vanaf https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail, kyk dit vir verdere inligting

#### Geval 1: Gebruik van `setuid` met `system`

**Doel**: Begrip van die effek van `setuid` in kombinasie met `system` en `bash` as `sh`.

**C-kode**:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
system("id");
return 0;
}
```
**Samelewing en Toestemmings:**

Wanneer jy 'n program op Linux samestel, word 'n uitvoerbare lêer geskep wat die program se kode bevat. Hierdie uitvoerbare lêer het spesifieke toestemmings wat bepaal wie die program kan uitvoer, wysig of lees.

Die toestemmings van 'n lêer kan gesien word deur die `ls -l` opdrag uit te voer. Die uitset sal iets soos die volgende wees:

```
-rwxr-xr-x 1 user group 12345 Jan 1 00:00 program
```

Die eerste karakter in die uitset (`-` in hierdie geval) dui aan dat dit 'n lêer is. As dit 'n `d` was, sou dit 'n gids wees. Die volgende drie karakters (`rwx`) dui die toestemmings van die eienaar van die lêer aan, die volgende drie karakters (`r-x`) dui die toestemmings van die groep aan, en die laaste drie karakters (`r-x`) dui die toestemmings van ander gebruikers aan.

Elke karakter in die toestemmingsreeks verteenwoordig 'n spesifieke toestemming:

- `r` dui aan dat die lêer gelees kan word.
- `w` dui aan dat die lêer gewysig kan word.
- `x` dui aan dat die lêer uitgevoer kan word.

Om die toestemmings van 'n lêer te verander, kan die `chmod` opdrag gebruik word. Byvoorbeeld, `chmod +x program` sal die uitvoerbare toestemming aan die lêer toevoeg.

Dit is belangrik om die toestemmings van jou lêers korrek te konfigureer om die veiligheid van jou Linux-stelsel te verseker.
```bash
oxdf@hacky$ gcc a.c -o /mnt/nfsshare/a;
oxdf@hacky$ chmod 4755 /mnt/nfsshare/a
```

```bash
bash-4.2$ $ ./a
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Ontleding:**

* `ruid` en `euid` begin as 99 (niemand) en 1000 (frank) onderskeidelik.
* `setuid` pas beide aan na 1000.
* `system` voer `/bin/bash -c id` uit as gevolg van die simboliese skakel van sh na bash.
* `bash`, sonder `-p`, pas `euid` aan om ooreen te stem met `ruid`, wat beteken dat beide 99 (niemand) is.

#### Geval 2: Gebruik van setreuid met system

**C-kode**:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setreuid(1000, 1000);
system("id");
return 0;
}
```
**Samelewing en Toestemmings:**

Wanneer jy 'n program op Linux samestel, word 'n uitvoerbare lêer geskep wat die program se kode bevat. Hierdie uitvoerbare lêer het spesifieke toestemmings wat bepaal wie die program kan uitvoer, wysig of lees.

Die toestemmings van 'n lêer kan gesien word deur die `ls -l` opdrag uit te voer. Die uitset sal iets soos die volgende wees:

```
-rwxr-xr-x 1 user group 12345 Jan 1 00:00 program
```

Die eerste karakter in die uitset (`-` in hierdie geval) dui aan dat dit 'n lêer is. As dit 'n `d` was, sou dit 'n gids wees. Die volgende drie karakters (`rwx`) dui die toestemmings van die eienaar van die lêer aan, die volgende drie karakters (`r-x`) dui die toestemmings van die groep aan, en die laaste drie karakters (`r-x`) dui die toestemmings van ander gebruikers aan.

Elke karakter in die toestemmingsreeks verteenwoordig 'n spesifieke toestemming:

- `r` dui aan dat die lêer gelees kan word.
- `w` dui aan dat die lêer gewysig kan word.
- `x` dui aan dat die lêer uitgevoer kan word.

Om die toestemmings van 'n lêer te verander, kan die `chmod` opdrag gebruik word. Byvoorbeeld, `chmod +x program` sal die uitvoerbare toestemming aan die lêer toevoeg.

Dit is belangrik om die toestemmings van jou lêers korrek te konfigureer om die veiligheid van jou Linux-stelsel te verseker.
```bash
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
**Uitvoering en Resultaat:**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Ontleding:**

* `setreuid` stel beide ruid en euid in op 1000.
* `system` roep bash aan, wat de gebruikers-ID's behoudt vanwege hun gelijkheid, waardoor het effectief werkt als frank.

#### Geval 3: Gebruik van setuid met execve
Doel: Verkenning van de interactie tussen setuid en execve.
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/usr/bin/id", NULL, NULL);
return 0;
}
```
**Uitvoering en Resultaat:**
```bash
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Ontleding:**

* `ruid` bly 99, maar `euid` word ingestel op 1000, in lyn met die effek van `setuid`.

**C-kode-voorbeeld 2 (Bash aanroep):**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/bin/bash", NULL, NULL);
return 0;
}
```
**Uitvoering en Resultaat:**
```bash
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Ontleding:**

* Alhoewel `euid` deur `setuid` na 1000 ingestel word, stel `bash` `euid` terug na `ruid` (99) as gevolg van die afwesigheid van `-p`.

**C-kode-voorbeeld 3 (Met behulp van bash -p):**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
char *const paramList[10] = {"/bin/bash", "-p", NULL};
setuid(1000);
execve(paramList[0], paramList, NULL);
return 0;
}
```
**Uitvoering en Resultaat:**
```bash
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=100
```
## Verwysings
* [https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)


<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersecurity-maatskappy**? Wil jy jou **maatskappy adverteer in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of laai HackTricks af in PDF-formaat**? Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die [hacktricks repo](https://github.com/carlospolop/hacktricks) en [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
