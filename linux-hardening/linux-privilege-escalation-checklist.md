# Lista za proveru eskalacije privilegija na Linuxu

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

<figure><img src="../.gitbook/assets/image (377).png" alt=""><figcaption></figcaption></figure>

Pridružite se [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) serveru kako biste komunicirali sa iskusnim hakerima i lovcima na bagove!

**Hakerski uvidi**\
Uključite se u sadržaj koji istražuje uzbuđenje i izazove hakovanja

**Vesti o hakovanju u realnom vremenu**\
Budite informisani o brzom svetu hakovanja kroz vesti i uvide u realnom vremenu

**Najnovije najave**\
Ostanite informisani o najnovijim nagradama za pronalaženje bagova i važnim ažuriranjima platformi

**Pridružite nam se na** [**Discord-u**](https://discord.com/invite/N3FrSbmwdy) i počnite da sarađujete sa vrhunskim hakerima danas!

### **Najbolji alat za traženje vektora eskalacije privilegija na lokalnom Linux sistemu:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Informacije o sistemu](privilege-escalation/#system-information)

* [ ] Dobiti **informacije o OS-u**
* [ ] Proveriti [**PATH**](privilege-escalation/#path), da li postoji **folder za pisanje**?
* [ ] Proveriti [**env promenljive**](privilege-escalation/#env-info), da li ima osetljivih detalja?
* [ ] Tražiti [**eksploate kernela**](privilege-escalation/#kernel-exploits) **korišćenjem skripti** (DirtyCow?)
* [ ] **Proveriti** da li je [**verzija sudo-a ranjiva**](privilege-escalation/#sudo-version)
* [ ] [**Dmesg** provera neuspelog potpisa](privilege-escalation/#dmesg-signature-verification-failed)
* [ ] Dodatna enumeracija sistema ([datum, statistika sistema, informacije o CPU-u, štampači](privilege-escalation/#more-system-enumeration))
* [ ] [Enumeracija dodatnih odbrana](privilege-escalation/#enumerate-possible-defenses)

### [Diskovi](privilege-escalation/#drives)

* [ ] **Lista montiranih** diskova
* [ ] **Postoje li ne montirani diskovi?**
* [ ] **Postoje li kredencijali u fstab-u?**

### [**Instalirani softver**](privilege-escalation/#installed-software)

* [ ] **Proveriti da li je** [**koristan softver**](privilege-escalation/#useful-software) **instaliran**
* [ ] **Proveriti da li je** [**ranjiv softver**](privilege-escalation/#vulnerable-software-installed) **instaliran**

### [Procesi](privilege-escalation/#processes)

* [ ] Da li se izvršava **nepoznat softver**?
* [ ] Da li se neki softver izvršava sa **više privilegija nego što bi trebalo**?
* [ ] Tražiti **eksploate pokrenutih procesa** (posebno verzije koje se izvršavaju).
* [ ] Možete li **modifikovati binarni fajl** nekog pokrenutog procesa?
* [ ] **Pratiti procese** i proveriti da li se neki zanimljiv proces često izvršava.
* [ ] Možete li **čitati** neku zanimljivu **memoriju procesa** (gde bi lozinke mogle biti sačuvane)?

### [Zakazani/Cron poslovi?](privilege-escalation/#scheduled-jobs)

* [ ] Da li je [**PATH** ](privilege-escalation/#cron-path)modifikovan od strane nekog cron-a i možete u njega **pisati**?
* [ ] Da li postoji [**zvezdica** ](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection)u cron poslu?
* [ ] Da li se neki [**modifikovani skript** ](privilege-escalation/#cron-script-overwriting-and-symlink)izvršava ili se nalazi u **modifikovanoj fascikli**?
* [ ] Da li ste primetili da se neka **skripta** može ili se često [**izvršava** veoma **često**](privilege-escalation/#frequent-cron-jobs)? (svakih 1, 2 ili 5 minuta)

### [Servisi](privilege-escalation/#services)

* [ ] Postoji li **.service** fajl za pisanje?
* [ ] Postoji li **izvršavanje binarnog fajla za pisanje** od strane **servisa**?
* [ ] Postoji li **fascikla za pisanje u systemd PATH-u**?

### [Tajmeri](privilege-escalation/#timers)

* [ ] Postoji li **tajmer za pisanje**?

### [Soketi](privilege-escalation/#sockets)

* [ ] Postoji li **.socket** fajl za pisanje?
* [ ] Možete li **komunicirati sa nekim soketom**?
* [ ] **HTTP soketi** sa zanimljivim informacijama?

### [D-Bus](privilege-escalation/#d-bus)

* [ ] Možete li **komunicirati sa nekim D-Bus-om**?

### [Mreža](privilege-escalation/#network)

* [ ] Enumerisati mrežu da biste znali gde se nalazite
* [ ] **Otvoriti portove kojima niste mogli pristupiti pre** dobijanja pristupa mašini?
* [ ] Možete li **snifovati saobraćaj** koristeći `tcpdump`?

### [Korisnici](privilege-escalation/#users)

* [ ] Opšta enumeracija korisnika/grupa
* [ ] Da li imate **veoma veliki UID**? Da li je **mašina** **ranjiva**?
* [ ] Možete li [**eskalarirati privilegije zahvaljujući grupi**](privilege-escalation/interesting-groups-linux-pe/) kojoj pripadate?
* [ ] **Podaci iz clipboard-a**?
* [ ] Politika lozinki?
* [ ] Pokušajte da **koristite** svaku **poznatu lozinku** koju ste prethodno otkrili da biste se prijavili **sa svakim** mogućim **korisnikom**. Pokušajte se takođe prijaviti i bez lozinke.

### [Fascikla za pisanje u PATH-u](privilege-escalation/#writable-path-abuses)

* [ ] Ako imate **prava za pisanje nad nekom fasciklom u PATH-u** možda ćete moći da eskalirate privilegije

### [SUDO i SUID komande](privilege-escalation/#sudo-and-suid)

* [ ] Možete li izvršiti **bilo koju komandu sa sudo-om**? Možete li je koristiti da **ČITATE, PIŠETE ili IZVRŠITE** bilo šta kao root? ([**GTFOBins**](https://gtfobins.github.io))
* [ ] Da li postoji **eksploatabilni SUID binarni fajl**? ([**GTFOBins**](https://gtfobins.github.io))
* [ ] Da li su [**sudo komande ograničene** putanjom? možete li **zaobići** ograničenja](privilege-escalation/#sudo-execution-bypassing-paths)?
* [ ] [**Sudo/SUID binarni fajl bez navedene putanje**](privilege-escalation/#sudo-command-suid-binary-without-command-path)?
* [ ] [**SUID binarni fajl sa navedenom putanjom**](privilege-escalation/#suid-binary-with-command-path)? Zaobilaženje
* [ ] [**LD\_PRELOAD ranjivost**](privilege-escalation/#ld\_preload)
* [ ] [**Nedostatak .so biblioteke u SUID binarnom fajlu**](privilege-escalation/#suid-binary-so-injection) iz fascikle za pisanje?
* [ ] [**Dostupni SUDO tokeni**](privilege-escalation/#reusing-sudo-tokens)? [**Možete li kreirati SUDO token**](privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than)?
* [ ] Možete li [**čitati ili modifikovati sudoers fajlove**](privilege-escalation/#etc-sudoers-etc-sudoers-d)?
* [ ] Možete li [**modifikovati /etc/ld.so.conf.d/**](privilege-escalation/#etc-ld-so-conf-d)?
* [ ] [**OpenBSD DOAS**](privilege-escalation/#doas) komanda
### [Mogućnosti](privilege-escalation/#capabilities)

* [ ] Da li bilo koji binarni fajl ima **neočekivanu mogućnost**?

### [ACLs](privilege-escalation/#acls)

* [ ] Da li bilo koji fajl ima **neočekivani ACL**?

### [Otvorene sesije komandne linije](privilege-escalation/#open-shell-sessions)

* [ ] **screen**
* [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

* [ ] **Debian** [**OpenSSL Predvidljiv PRNG - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
* [ ] [**SSH Interesantne vrednosti konfiguracije**](privilege-escalation/#ssh-interesting-configuration-values)

### [Interesantni fajlovi](privilege-escalation/#interesting-files)

* [ ] **Profil fajlovi** - Čitanje osetljivih podataka? Pisanje za privesc?
* [ ] **passwd/shadow fajlovi** - Čitanje osetljivih podataka? Pisanje za privesc?
* [ ] **Provera često interesantnih foldera** za osetljive podatke
* [ ] **Čudna lokacija/vlasnički fajlovi,** do kojih možete pristupiti ili ih izmeniti
* [ ] **Izmenjeni** u poslednjih nekoliko minuta
* [ ] **Sqlite DB fajlovi**
* [ ] **Skriveni fajlovi**
* [ ] **Skripte/Binarni fajlovi u PATH-u**
* [ ] **Web fajlovi** (šifre?)
* [ ] **Backup-ovi**?
* [ ] **Poznati fajlovi koji sadrže šifre**: Koristite **Linpeas** i **LaZagne**
* [ ] **Generička pretraga**

### [**Fajlovi za pisanje**](privilege-escalation/#writable-files)

* [ ] **Izmena python biblioteke** da izvršite proizvoljne komande?
* [ ] Možete li **izmeniti log fajlove**? Eksploatacija **Logtotten**
* [ ] Možete li **izmeniti /etc/sysconfig/network-scripts/**? Eksploatacija za Centos/Redhat
* [ ] Možete li [**pisati u ini, int.d, systemd ili rc.d fajlove**](privilege-escalation/#init-init-d-systemd-and-rc-d)?

### [**Drugi trikovi**](privilege-escalation/#other-tricks)

* [ ] Možete li [**zloupotrebiti NFS za eskalaciju privilegija**](privilege-escalation/#nfs-privilege-escalation)?
* [ ] Da li treba da [**pobegnete iz restriktivne ljuske**](privilege-escalation/#escaping-from-restricted-shells)?
