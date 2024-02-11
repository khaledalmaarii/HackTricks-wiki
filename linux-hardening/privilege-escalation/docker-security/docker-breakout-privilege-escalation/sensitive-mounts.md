<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy in HackTricks wil adverteer** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>


Die blootstelling van `/proc` en `/sys` sonder behoorlike naamsruimte-isolasie stel beduidende sekuriteitsrisiko's in, insluitend vergroting van die aanvalsvlak en bekendmaking van inligting. Hierdie gids bevat sensitiewe lêers wat, as dit verkeerd gekonfigureer of deur 'n ongemagtigde gebruiker benader word, kan lei tot ontsnapping uit die houer, wysiging van die gasheer of die voorsiening van inligting wat verdere aanvalle ondersteun. Byvoorbeeld, as `-v /proc:/host/proc` verkeerd gemonteer word, kan dit AppArmor-beskerming omseil as gevolg van sy padgebaseerde aard, wat `/host/proc` onbeskerm laat.

**U kan verdere besonderhede van elke potensiële kwesbaarheid vind in [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts).**

# procfs-kwesbaarhede

## `/proc/sys`
Hierdie gids maak toegang tot die wysiging van kernel-veranderlikes moontlik, gewoonlik via `sysctl(2)`, en bevat verskeie subgidsies van belang:

### **`/proc/sys/kernel/core_pattern`**
- Beskryf in [core(5)](https://man7.org/linux/man-pages/man5/core.5.html).
- Maak dit moontlik om 'n program te definieer wat uitgevoer moet word wanneer 'n kernlêer gegenereer word, met die eerste 128 byte as argumente. Dit kan lei tot kodering van kode as die lêer begin met 'n pyp `|`.
- **Toets- en uitbuitingsvoorbeeld**:
```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Ja # Toets skryftoegang
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern # Stel aangepaste hanterer in
sleep 5 && ./crash & # Trigger hanterer
```

### **`/proc/sys/kernel/modprobe`**
- Uitvoerig beskryf in [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
- Bevat die pad na die kernel-modulelaaier wat aangeroep word vir die laai van kernel-modules.
- **Voorbeeld van toegangstoets**:
```bash
ls -l $(cat /proc/sys/kernel/modprobe) # Toets toegang tot modprobe
```

### **`/proc/sys/vm/panic_on_oom`**
- Verwys na [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
- 'n Globale vlag wat beheer of die kernel paniekerig word of die OOM-killer aanroep wanneer 'n OOM-toestand voorkom.

### **`/proc/sys/fs`**
- Volgens [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html), bevat dit opsies en inligting oor die lêersisteem.
- Skryftoegang kan verskeie denial-of-service-aanvalle teen die gasheer moontlik maak.

### **`/proc/sys/fs/binfmt_misc`**
- Maak die registrasie van tolke vir nie-inheemse binêre formate moontlik op grond van hul toorkodegetal.
- Dit kan lei tot bevoorregte eskalasie of toegang tot die wortelshell as `/proc/sys/fs/binfmt_misc/register` skryfbaar is.
- Relevant uitbuiting en verduideliking:
- [Poor man's rootkit via binfmt_misc](https://github.com/toffan/binfmt_misc)
- Diepgaande tutoriaal: [Video-skakel](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

## Ander in `/proc`

### **`/proc/config.gz`**
- Kan die kernel-konfigurasie bekend maak as `CONFIG_IKCONFIG_PROC` geaktiveer is.
- Nuttig vir aanvallers om kwesbaarhede in die lopende kernel te identifiseer.

### **`/proc/sysrq-trigger`**
- Maak dit moontlik om Sysrq-opdragte aan te roep, wat potensieel onmiddellike stelselherlaaiings of ander kritieke aksies kan veroorsaak.
- **Voorbeeld van gasheerherlaaiing**:
```bash
echo b > /proc/sysrq-trigger # Herlaai die gasheer
```

### **`/proc/kmsg`**
- Stel kernel-ringingbufferboodskappe bloot.
- Dit kan help met kernel-uitbuitings, adreslekke en die voorsiening van sensitiewe stelselinligting.

### **`/proc/kallsyms`**
- Lys kernel-uitgevoerde simbole en hul adresse op.
- Essensieel vir die ontwikkeling van kernel-uitbuitings, veral vir die oorkom van KASLR.
- Adresinligting is beperk met `kptr_restrict` wat op `1` of `2` ingestel is.
- Besonderhede in [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

### **`/proc/[pid]/mem`**
- Koppelvlak met die kernel-geheue-toestel `/dev/mem`.
- Histories vatbaar vir bevoorregte eskalasie-aanvalle.
- Meer inligting in [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

### **`/proc/kcore`**
- Verteenwoordig die fisiese geheue van die stelsel in ELF-kernformaat.
- Lees kan die inhoud van die gasheerstelsel en ander houers se geheue uitlek.
- 'n Groot lêergrootte kan lei tot leesprobleme of sagtewarefoutmeldings.
- Gedetailleerde gebruik in [Dumping /proc/kcore in 2019](https://schlafwandler.github.io/posts/dumping-/proc/kcore/).

### **`/proc/kmem`**
- Alternatiewe koppelvlak vir `/dev/kmem`, wat die virtuele geheue van die kernel verteenwoordig.
- Maak lees en skryf moontlik, dus direkte wysiging van die kernel-geheue.

### **`/proc/mem`**
- Alternatiewe koppelvlak vir `/dev/mem`, wat fisiese geheue verteenwoordig.
- Maak lees en skryf moontlik, wysiging van alle geheue vereis die oplossing van virtuele na fisiese adresse.

### **`/proc/sched_debug`**
- Gee prosesbeplanningsinligting terug, omseil PID-naamsruimtebeskerming.
- Stel prosesname, ID's en cgroup-identifiseerders bloot.

### **`/proc/[pid]/mountinfo`**
- Verskaf inligting oor koppelvlakpunte in die proses se koppelvlaknaamsruimte.
- Stel die ligging van die houer se `rootfs` of beeld bloot.

## `/sys`-kwesbaarhede

### **`/sys/kernel/uevent_helper`**
- Word gebruik vir die hanteer van kerneltoestel-`uevents`.
- Skryf na `/sys/kernel/uevent_helper` kan arbitrêre skripte uitvoer wanneer `uevent`-triggerings plaasvind.
- **Voorbeeld van uitbuiting**:
%%%bash
# Skep 'n vragstuk
echo "#!/bin/sh" > /evil-helper
echo "ps > /output" >> /evil-helper
chmod +x /evil-helper
# Vind gasheerpad vanaf OverlayFS-koppeling vir houer
### **`/sys/class/thermal`**
- Beheer temperatuurinstellings, moontlik veroorsaak DoS-aanvalle of fisiese skade.

### **`/sys/kernel/vmcoreinfo`**
- Lekker kernel-adresse, moontlik in gedrang KASLR.

### **`/sys/kernel/security`**
- Bevat `securityfs`-koppelvlak, wat konfigurasie van Linux Security Modules soos AppArmor moontlik maak.
- Toegang kan 'n houer in staat stel om sy MAC-stelsel uit te skakel.

### **`/sys/firmware/efi/vars` en `/sys/firmware/efi/efivars`**
- Blootstelling van koppelvlakke vir interaksie met EFI-variables in NVRAM.
- Foutiewe konfigurasie of uitbuiting kan lei tot gebreekte draagbare rekenaars of onopstartbare gasheer-masjiene.

### **`/sys/kernel/debug`**
- `debugfs` bied 'n "geen reëls" foutopsporingskoppelvlak na die kernel.
- Geskiedenis van sekuriteitsprobleme as gevolg van sy onbeperkte aard.


## Verwysings
* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)
* [Understanding and Hardening Linux Containers](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc\_group\_understanding\_hardening\_linux\_containers-1-1.pdf)
* [Abusing Privileged and Unprivileged Linux Containers](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container\_whitepaper.pdf)


<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien jou **maatskappy geadverteer in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>
