# Lys - Linux Voorregverhoging

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy in HackTricks wil adverteer** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Sluit aan by die [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) bediener om met ervare hackers en foutjagters te kommunikeer!

**Hacking-insigte**\
Raak betrokke by inhoud wat die opwinding en uitdagings van hackery ondersoek

**Hack-nuus in werklike tyd**\
Bly op hoogte van die vinnige hackery-wêreld deur werklike nuus en insigte

**Nuutste aankondigings**\
Bly ingelig met die nuutste foutjagbounties wat begin en belangrike platformopdaterings

**Sluit aan by ons op** [**Discord**](https://discord.com/invite/N3FrSbmwdy) en begin vandag saamwerk met top hackers!

### **Die beste hulpmiddel om te soek na Linux plaaslike voorregverhogingsvektore:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Stelselinligting](privilege-escalation/#system-information)

* [ ] Kry **bedryfstelselinligting**
* [ ] Kontroleer die [**PAD**](privilege-escalation/#path), enige **skryfbare vouer**?
* [ ] Kontroleer [**omgewingsveranderlikes**](privilege-escalation/#env-info), enige sensitiewe besonderhede?
* [ ] Soek na [**kernel-uitbuitings**](privilege-escalation/#kernel-exploits) **deur skripte te gebruik** (DirtyCow?)
* [ ] **Kontroleer** of die [**sudo-weergawe kwesbaar is**](privilege-escalation/#sudo-version)
* [ ] [**Dmesg-handtekeningverifikasie het misluk**](privilege-escalation/#dmesg-signature-verification-failed)
* [ ] Meer stelselenum (datum, stelselstatistieke, CPU-inligting, drukkers](privilege-escalation/#more-system-enumeration))
* [ ] [Meer verdedigings opnoem](privilege-escalation/#enumerate-possible-defenses)

### [Hardeskywe](privilege-escalation/#drives)

* [ ] Lys **gemoniteerde** hardeskywe
* [ ] Enige **ongemoniteerde hardeskyf**?
* [ ] Enige geloofsbriewe in fstab?

### [**Geïnstalleerde sagteware**](privilege-escalation/#installed-software)

* [ ] Kontroleer vir [**nuttige sagteware**](privilege-escalation/#useful-software) **geïnstalleer**
* [ ] Kontroleer vir [**kwesbare sagteware**](privilege-escalation/#vulnerable-software-installed) **geïnstalleer**

### [Prosesse](privilege-escalation/#processes)

* [ ] Word enige **onbekende sagteware uitgevoer**?
* [ ] Word enige sagteware uitgevoer met **meer voorregte as wat dit behoort te hê**?
* [ ] Soek na **uitbuitings van lopende prosesse** (veral die weergawe wat uitgevoer word).
* [ ] Kan jy die **binêre lêer wysig** van enige lopende proses?
* [ ] **Monitor prosesse** en kontroleer of enige interessante proses gereeld uitgevoer word.
* [ ] Kan jy enige interessante **prosesgeheue** lees (waar wagwoorde gestoor kan word)?

### [Geskeduleerde/Cron-take?](privilege-escalation/#scheduled-jobs)

* [ ] Word die [**PAD**](privilege-escalation/#cron-path) gewysig deur 'n cron en kan jy daarin **skryf**?
* [ ] Enige [**wildcard**](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection) in 'n cron-taak?
* [ ] Word 'n [**veranderbare skripsie**](privilege-escalation/#cron-script-overwriting-and-symlink) uitgevoer of is dit binne 'n **veranderbare vouer**?
* [ ] Het jy opgemerk dat 'n **skripsie** dalk of gereeld **uitgevoer word**](privilege-escalation/#frequent-cron-jobs)? (elke 1, 2 of 5 minute)

### [Dienste](privilege-escalation/#services)

* [ ] Enige **skryfbare .service**-lêer?
* [ ] Enige **skryfbare binêre lêer** wat deur 'n **diens** uitgevoer word?
* [ ] Enige **skryfbare vouer in systemd PAD**?

### [Tydsinstellers](privilege-escalation/#timers)

* [ ] Enige **skryfbare tydsinsteller**?

### [Sockets](privilege-escalation/#sockets)

* [ ] Enige **skryfbare .socket**-lêer?
* [ ] Kan jy **kommunikeer met enige socket**?
* [ ] **HTTP-sockets** met interessante inligting?

### [D-Bus](privilege-escalation/#d-bus)

* [ ] Kan jy **kommunikeer met enige D-Bus**?

### [Netwerk](privilege-escalation/#network)

* [ ] Enumereer die netwerk om te weet waar jy is
* [ ] **Oop poorte wat jy voorheen nie kon bereik nie** nadat jy 'n skaal binne die masjien gekry het?
* [ ] Kan jy verkeer **sniff** met behulp van `tcpdump`?

### [Gebruikers](privilege-escalation/#users)

* [ ] Algemene gebruikers/groepe **opnoem**
* [ ] Het jy 'n **baie groot UID**? Is die **masjien** **kwesbaar**?
* [ ] Kan jy [**voorregte verhoog as gevolg van 'n groep**](privilege-escalation/interesting-groups-linux-pe/) waarvan jy deel is?
* [ ] **Knipbord**-data?
* [ ] Wagwoordbeleid?
* [ ] Probeer om elke **bekende wagwoord** wat jy vantevore ontdek het, te gebruik om **met elke moontlike gebruiker** in te teken. Probeer ook om sonder 'n wagwoord in te teken.

### [Skryfbare PAD](privilege-escalation/#writable-path-abuses)

* [ ] As jy **skryfregte het oor 'n vouer in PAD**, kan jy voorregte verho
### [Vermoëns](privilege-escalation/#capabilities)

* [ ] Het enige binêre lêer enige **onverwagte vermoë**?

### [ACL's](privilege-escalation/#acls)

* [ ] Het enige lêer enige **onverwagte ACL**?

### [Oop Skul-sessies](privilege-escalation/#open-shell-sessions)

* [ ] **screen**
* [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

* [ ] **Debian** [**OpenSSL Voorspelbare PRNG - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
* [ ] [**SSH Interessante konfigurasiewaardes**](privilege-escalation/#ssh-interesting-configuration-values)

### [Interessante Lêers](privilege-escalation/#interesting-files)

* [ ] **Profiel lêers** - Lees sensitiewe data? Skryf na privesc?
* [ ] **passwd/shadow lêers** - Lees sensitiewe data? Skryf na privesc?
* [ ] **Kyk deur algemeen interessante lêerfoute** vir sensitiewe data
* [ ] **Vreemde Ligging/Eienaar lêers,** jy mag toegang hê tot of uitvoerbare lêers verander
* [ ] **Gewysig** in die laaste paar minute
* [ ] **Sqlite DB lêers**
* [ ] **Versteekte lêers**
* [ ] **Skripsie/Binêre lêers in PATH**
* [ ] **Web lêers** (wagwoorde?)
* [ ] **Rugsteun**?
* [ ] **Bekende lêers wat wagwoorde bevat**: Gebruik **Linpeas** en **LaZagne**
* [ ] **Generiese soektog**

### [**Skryfbare Lêers**](privilege-escalation/#writable-files)

* [ ] **Verander Python-biblioteek** om arbitrêre opdragte uit te voer?
* [ ] Kan jy **loglêers verander**? **Logtotten** uitbuiting
* [ ] Kan jy **/etc/sysconfig/network-scripts/** verander? Centos/Redhat uitbuiting
* [ ] Kan jy in **ini, int.d, systemd of rc.d lêers skryf**](privilege-escalation/#init-init-d-systemd-and-rc-d)?

### [**Ander truuks**](privilege-escalation/#other-tricks)

* [ ] Kan jy **NFS misbruik om voorregte te verhoog**](privilege-escalation/#nfs-privilege-escalation)?
* [ ] Moet jy **ontsnap uit 'n beperkende skul**](privilege-escalation/#escaping-from-restricted-shells)?

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Sluit aan by [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) bediener om met ervare hackers en foutjagters te kommunikeer!

**Hacking Insights**\
Betrokkenheid by inhoud wat die opwinding en uitdagings van hackering ondersoek

**Real-Time Hack Nuus**\
Bly op hoogte van die vinnige hackeringwêreld deur middel van real-time nuus en insigte

**Nuutste Aankondigings**\
Bly ingelig met die nuutste foutjagte wat begin en noodsaaklike platformopdaterings

**Sluit aan by ons op** [**Discord**](https://discord.com/invite/N3FrSbmwdy) en begin vandag saamwerk met top hackers!

<details>

<summary><strong>Leer AWS hackering van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hackeringtruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
