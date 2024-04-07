# Kontrolelys - Linux Privilege Escalation

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

<figure><img src="../.gitbook/assets/image (377).png" alt=""><figcaption></figcaption></figure>

Sluit aan by [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) bediener om met ervare hackers en foutvinders vir belonings te kommunikeer!

**Hacking-insigte**\
Raak betrokke by inhoud wat die opwinding en uitdagings van hack bevat

**Hack Nuus in Werklikheid**\
Bly op hoogte van die vinnige hack-wêreld deur werklikheidsnuus en insigte

**Nuutste Aankondigings**\
Bly ingelig met die nuutste foutbelonings wat bekendgestel word en kritieke platformopdaterings

**Sluit by ons aan op** [**Discord**](https://discord.com/invite/N3FrSbmwdy) en begin vandag saamwerk met top hackers!

### **Beste hulpmiddel om te soek na Linux plaaslike privilege-escalatie vektore:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Stelselinligting](privilege-escalation/#system-information)

* [ ] Kry **OS-inligting**
* [ ] Kontroleer die [**PAD**](privilege-escalation/#path), enige **skryfbare vouer**?
* [ ] Kontroleer [**omgewingsveranderlikes**](privilege-escalation/#env-info), enige sensitiewe besonderhede?
* [ ] Soek na [**kernel-uitbuitings**](privilege-escalation/#kernel-exploits) **deur skripte te gebruik** (DirtyCow?)
* [ ] **Kontroleer** of die [**sudo-weergawe kwesbaar is**](privilege-escalation/#sudo-version)
* [ ] [**Dmesg** handtekeningverifikasie het misluk](privilege-escalation/#dmesg-signature-verification-failed)
* [ ] Meer stelselenum ([datum, stelselstatistieke, CPU-inligting, drukkers](privilege-escalation/#more-system-enumeration))
* [ ] [Enumerate meer verdedigings](privilege-escalation/#enumerate-possible-defenses)

### [Aandrywings](privilege-escalation/#drives)

* [ ] **Lys aangehegte** aandrywings
* [ ] **Enige onaangehegte aandrywing?**
* [ ] **Enige geloofsbriewe in fstab?**

### [**Geïnstalleerde sagteware**](privilege-escalation/#installed-software)

* [ ] **Kontroleer vir** [**nuttige sagteware**](privilege-escalation/#useful-software) **geïnstalleer**
* [ ] **Kontroleer vir** [**kwesbare sagteware**](privilege-escalation/#vulnerable-software-installed) **geïnstalleer**

### [Prosesse](privilege-escalation/#processes)

* [ ] Is enige **onbekende sagteware aan die gang**?
* [ ] Is enige sagteware aan die gang met **meer bevoegdhede as wat dit behoort te hê**?
* [ ] Soek na **uitbuitings van aan die gang prosesse** (veral die weergawe wat aan die gang is).
* [ ] Kan jy die binêre kode van enige aan die gang proses **verander**?
* [ ] **Monitor prosesse** en kontroleer of enige interessante proses gereeld aan die gang is.
* [ ] Kan jy van enige interessante **prosesgeheue** lees (waar wagwoorde gestoor kan word)?

### [Geskeduleerde/Cron-take?](privilege-escalation/#scheduled-jobs)

* [ ] Word die [**PAD** ](privilege-escalation/#cron-path)gewysig deur 'n cron en kan jy daarin **skryf**?
* [ ] Enige [**wildkaart** ](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection)in 'n cron-taak?
* [ ] Word 'n [**veranderbare skrip** ](privilege-escalation/#cron-script-overwriting-and-symlink)uitgevoer of is binne 'n **veranderbare vouer**?
* [ ] Het jy opgemerk dat 'n sekere **skrip** dalk of gereeld [**uitgevoer word**](privilege-escalation/#frequent-cron-jobs)? (elke 1, 2 of 5 minute)

### [Dienste](privilege-escalation/#services)

* [ ] Enige **skryfbare .diens** lêer?
* [ ] Enige **skryfbare binêre kode** wat deur 'n **diens** uitgevoer word?
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
* [ ] Kan jy [**bevoegdhede eskaleer as gevolg van 'n groep**](privilege-escalation/interesting-groups-linux-pe/) waarvan jy deel is?
* [ ] **Knipbord** data?
* [ ] Wagwoordbeleid?
* [ ] Probeer om elke **bekende wagwoord** wat jy voorheen ontdek het te **gebruik** om in te teken **met elke** moontlike **gebruiker**. Probeer ook om sonder 'n wagwoord in te teken.

### [Skryfbare PAD](privilege-escalation/#writable-path-abuses)

* [ ] As jy **skryfregte oor 'n vouer in PAD** het, kan jy bevoegdhede eskaleer

### [SUDO en SUID-opdragte](privilege-escalation/#sudo-and-suid)

* [ ] Kan jy **enige opdrag met sudo uitvoer**? Kan jy dit gebruik om AS ROOT te LEES, SKRYF of UIT TE VOER? ([**GTFOBins**](https://gtfobins.github.io))
* [ ] Is enige **uitbuitbare SUID-binêre kode**? ([**GTFOBins**](https://gtfobins.github.io))
* Word [**sudo**-opdragte **beperk** deur **pad**? kan jy die beperkings **verbygaan**](privilege-escalation/#sudo-execution-bypassing-paths)?
* [ ] [**Sudo/SUID-binêre kode sonder aangeduide pad**](privilege-escalation/#sudo-command-suid-binary-without-command-path)?
* [ ] [**SUID-binêre kode wat pad aandui**](privilege-escalation/#suid-binary-with-command-path)? Verbygaan
* [ ] [**LD\_PRELOAD kwesbaarheid**](privilege-escalation/#ld\_preload)
* [ ] [**Gebrek aan .so-biblioteek in SUID-binêre kode**](privilege-escalation/#suid-binary-so-injection) vanaf 'n skryfbare vouer?
* [ ] [**SUDO-tokens beskikbaar**](privilege-escalation/#reusing-sudo-tokens)? [**Kan jy 'n SUDO-token skep**](privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than)?
* Kan jy [**sudoers-lêers lees of wysig**](privilege-escalation/#etc-sudoers-etc-sudoers-d)?
* Kan jy [**/etc/ld.so.conf.d/** wysig](privilege-escalation/#etc-ld-so-conf-d)?
* [**OpenBSD DOAS**](privilege-escalation/#doas) opdrag
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

* [ ] **Profiellêers** - Lees sensitiewe data? Skryf vir privesc?
* [ ] **passwd/shadow lêers** - Lees sensitiewe data? Skryf vir privesc?
* [ ] **Kyk na algemeen interessante vouers** vir sensitiewe data
* [ ] **Vreemde Ligging/Eienaarslêers,** waar jy moontlik toegang tot het of uitvoerbare lêers kan verander
* [ ] **Gewysig** in laaste minute
* [ ] **Sqlite DB lêers**
* [ ] **Versteekte lêers**
* [ ] **Skripsie/Uitvoerbare lêers in PATH**
* [ ] **Web lêers** (wagwoorde?)
* [ ] **Rugsteun**?
* [ ] **Bekende lêers wat wagwoorde bevat**: Gebruik **Linpeas** en **LaZagne**
* [ ] **Generiese soektog**

### [**Skryfbare Lêers**](privilege-escalation/#writable-files)

* [ ] **Wysig Python-biblioteek** om arbitrêre bevele uit te voer?
* [ ] Kan jy **loglêers wysig**? **Logtotten** uitbuiting
* [ ] Kan jy **/etc/sysconfig/network-scripts/** wysig? Centos/Redhat uitbuiting
* [ ] Kan jy [**skryf in ini, int.d, systemd of rc.d lêers**](privilege-escalation/#init-init-d-systemd-and-rc-d)?

### [**Ander truuks**](privilege-escalation/#other-tricks)

* [ ] Kan jy [**NFS misbruik om vermoëns te eskaleer**](privilege-escalation/#nfs-privilege-escalation)?
* [ ] Het jy nodig om te [**ontsnapping van 'n beperkende skul**](privilege-escalation/#escaping-from-restricted-shells)?

<figure><img src="../.gitbook/assets/image (377).png" alt=""><figcaption></figcaption></figure>

Sluit aan by [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) bediener om te kommunikeer met ervare hackers en foutbeloningsjagters!

**Hacker-insigte**\
Betrokkenheid by inhoud wat die opwinding en uitdagings van hack bevat

**Hack Nuus in Werklikheid**\
Bly op hoogte van die vinnige hack-wêreld deur werklikheid nuus en insigte

**Nuutste Aankondigings**\
Bly ingelig met die nuutste foutbelonings wat bekendgestel word en kritieke platformopdaterings

Sluit aan by ons op [**Discord**](https://discord.com/invite/N3FrSbmwdy) en begin vandag saamwerk met top hackers!
