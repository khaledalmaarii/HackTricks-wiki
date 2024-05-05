# Kontrolelys - Linux Voorregskalering

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

<figure><img src="../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

Sluit aan by [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) bediener om met ervare hackers en foutbeloningsjagters te kommunikeer!

**Hakinsigte**\
Betrokkenheid by inhoud wat die opwinding en uitdagings van hak bevat

**Nuutste Haknuus**\
Bly op hoogte van die snelveranderende hakwêreld deur middel van nuus en insigte in werklikheid

**Nuutste Aankondigings**\
Bly ingelig met die nuutste foutbelonings wat bekendgestel word en kritieke platformopdaterings

**Sluit by ons aan op** [**Discord**](https://discord.com/invite/N3FrSbmwdy) en begin vandag saamwerk met top hackers!

### **Beste hulpmiddel om te soek na Linux plaaslike voorregskalering vektore:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Stelselinligting](privilege-escalation/#system-information)

* [ ] Kry **OS-inligting**
* [ ] Kontroleer die [**PAD**](privilege-escalation/#path), enige **skryfbare vouer**?
* [ ] Kontroleer [**omgewingsveranderlikes**](privilege-escalation/#env-info), enige sensitiewe besonderhede?
* [ ] Soek na [**kernel-uitbuitings**](privilege-escalation/#kernel-exploits) **deur skripte te gebruik** (DirtyCow?)
* [ ] **Kontroleer** of die [**sudo-weergawe** kwesbaar is](privilege-escalation/#sudo-version)
* [ ] [**Dmesg** handtekeningverifikasie het misluk](privilege-escalation/#dmesg-signature-verification-failed)
* [ ] Meer stelselenum ([datum, stelselstatistieke, CPU-inligting, drukkers](privilege-escalation/#more-system-enumeration))
* [ ] [Enumerate meer verdedigings](privilege-escalation/#enumerate-possible-defenses)

### [Skywe](privilege-escalation/#drives)

* [ ] **Lys aangeheg** skrywe
* [ ] **Enige onaangehegde skyf?**
* [ ] **Enige geloofsbriewe in fstab?**

### [**Geïnstalleerde sagteware**](privilege-escalation/#installed-software)

* [ ] **Kontroleer vir** [**nuttige sagteware**](privilege-escalation/#useful-software) **geïnstalleer**
* [ ] **Kontroleer vir** [**kwesbare sagteware**](privilege-escalation/#vulnerable-software-installed) **geïnstalleer**

### [Prosesse](privilege-escalation/#processes)

* [ ] Is enige **onbekende sagteware aan die hardloop**?
* [ ] Word enige sagteware aan die hardloop met **meer voorregte as wat dit behoort te hê**?
* [ ] Soek na **uitbuitings van aan die hardloop prosesse** (veral die weergawe wat aan die hardloop is).
* [ ] Kan jy die binêre kode van enige aan die hardloop proses **verander**?
* [ ] **Monitor prosesse** en kontroleer of enige interessante proses gereeld aan die hardloop is.
* [ ] Kan jy van enige interessante **prosesgeheue** lees (waar wagwoorde gestoor kan word)?

### [Geskeduleerde/Cron-take?](privilege-escalation/#scheduled-jobs)

* [ ] Word die [**PAD** ](privilege-escalation/#cron-path)gewysig deur 'n cron en kan jy daarin **skryf**?
* [ ] Enige [**wildkaart** ](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection)in 'n cron-taak?
* [ ] Word 'n [**veranderbare skripsie** ](privilege-escalation/#cron-script-overwriting-and-symlink)uitgevoer of is binne 'n **veranderbare vouer**?
* [ ] Het jy opgemerk dat 'n sekere **skripsie** dalk of gereeld [**uitgevoer word**](privilege-escalation/#frequent-cron-jobs)? (elke 1, 2 of 5 minute)

### [Dienste](privilege-escalation/#services)

* [ ] Enige **skryfbare .diens** lêer?
* [ ] Enige **skryfbare binêre** wat deur 'n **diens** uitgevoer word?
* [ ] Enige **skryfbare vouer in systemd PAD**?

### [Tydskakelaars](privilege-escalation/#timers)

* [ ] Enige **skryfbare tydskakelaar**?

### [Sockets](privilege-escalation/#sockets)

* [ ] Enige **skryfbare .socket** lêer?
* [ ] Kan jy met enige socket **kommunikeer**?
* [ ] **HTTP-sockets** met interessante inligting?

### [D-Bus](privilege-escalation/#d-bus)

* [ ] Kan jy met enige D-Bus **kommunikeer**?

### [Netwerk](privilege-escalation/#network)

* [ ] Enumereer die netwerk om te weet waar jy is
* [ ] **Oop poorte wat jy nie voorheen kon bereik nie** nadat jy 'n skaal binne die masjien gekry het?
* [ ] Kan jy verkeer **sniff** met behulp van `tcpdump`?

### [Gebruikers](privilege-escalation/#users)

* [ ] Generiese gebruikers/groepe **opsomming**
* [ ] Het jy 'n **baie groot UID**? Is die **masjien** **kwesbaar**?
* [ ] Kan jy [**voorregte opskerp**](privilege-escalation/interesting-groups-linux-pe/) danksy 'n groep waarvan jy deel is?
* [ ] **Knipbord** data?
* [ ] Wagwoordbeleid?
* [ ] Probeer om elke **bekende wagwoord** wat jy vantevore ontdek het te **gebruik** om in te teken **met elke** moontlike **gebruiker**. Probeer ook om sonder 'n wagwoord in te teken.

### [Skryfbare PAD](privilege-escalation/#writable-path-abuses)

* [ ] As jy **skryfregte oor 'n vouer in PAD** het, kan jy voorregte opskerp

### [SUDO en SUID-opdragte](privilege-escalation/#sudo-and-suid)

* [ ] Kan jy **enige opdrag met sudo uitvoer**? Kan jy dit gebruik om AS ROOT te LEES, SKRYF of UIT TE VOER? ([**GTFOBins**](https://gtfobins.github.io))
* [ ] Is enige **uitbuitbare SUID-binêre**? ([**GTFOBins**](https://gtfobins.github.io))
* [ ] Is [**sudo** opdragte **beperk** deur **pad**? kan jy die beperkings **verbygaan**](privilege-escalation/#sudo-execution-bypassing-paths)?
* [ ] [**Sudo/SUID-binêre sonder aangeduide pad**](privilege-escalation/#sudo-command-suid-binary-without-command-path)?
* [ ] [**SUID-binêre wat pad aandui**](privilege-escalation/#suid-binary-with-command-path)? Verbygaan
* [ ] [**LD\_PRELOAD kwesbaarheid**](privilege-escalation/#ld\_preload)
* [ ] [**Gebrek aan .so-biblioteek in SUID-binêre**](privilege-escalation/#suid-binary-so-injection) vanaf 'n skryfbare vouer?
* [ ] [**SUDO-tokens beskikbaar**](privilege-escalation/#reusing-sudo-tokens)? [**Kan jy 'n SUDO-token skep**](privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than)?
* [ ] Kan jy [**sudoers-lêers lees of wysig**](privilege-escalation/#etc-sudoers-etc-sudoers-d)?
* [ ] Kan jy [**/etc/ld.so.conf.d/** wysig](privilege-escalation/#etc-ld-so-conf-d)?
* [ ] [**OpenBSD DOAS**](privilege-escalation/#doas) opdrag
### [Vermoeëns](privilege-escalation/#capabilities)

* [ ] Het enige binêre enige **onverwagte vermoëns**?

### [ACL's](privilege-escalation/#acls)

* [ ] Het enige lêer enige **onverwagte ACL**?

### [Oop Skel-sessies](privilege-escalation/#open-shell-sessions)

* [ ] **screen**
* [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

* [ ] **Debian** [**OpenSSL Voorspelbare PRNG - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
* [ ] [**SSH Interessante konfigurasiewaardes**](privilege-escalation/#ssh-interesting-configuration-values)

### [Interessante Lêers](privilege-escalation/#interesting-files)

* [ ] **Profiellêers** - Lees sensitiewe data? Skryf na privesc?
* [ ] **passwd/shadow lêers** - Lees sensitiewe data? Skryf na privesc?
* [ ] **Kyk algemeen interessante vouers** vir sensitiewe data
* [ ] **Vreemde Ligging/Eienaarslêers,** jy mag toegang hê tot of uitvoerbare lêers verander
* [ ] **Gewysig** in laaste minute
* [ ] **Sqlite DB lêers**
* [ ] **Versteekte lêers**
* [ ] **Skripsie/Binêre lêers in PATH**
* [ ] **Web lêers** (wagwoorde?)
* [ ] **Rugsteun**?
* [ ] **Bekende lêers wat wagwoorde bevat**: Gebruik **Linpeas** en **LaZagne**
* [ ] **Generiese soektog**

### [**Skryfbare Lêers**](privilege-escalation/#writable-files)

* [ ] **Wysig python-biblioteek** om arbitrêre opdragte uit te voer?
* [ ] Kan jy **loglêers wysig**? **Logtotten** uitbuiting
* [ ] Kan jy **/etc/sysconfig/network-scripts/** wysig? Centos/Redhat uitbuiting
* [ ] Kan jy [**skryf in ini, int.d, systemd of rc.d lêers**](privilege-escalation/#init-init-d-systemd-and-rc-d)?

### [**Ander truuks**](privilege-escalation/#other-tricks)

* [ ] Kan jy [**NFS misbruik om voorregte te eskaleer**](privilege-escalation/#nfs-privilege-escalation)?
* [ ] Het jy nodig om te [**ontsnap uit 'n beperkende dop**](privilege-escalation/#escaping-from-restricted-shells)?
