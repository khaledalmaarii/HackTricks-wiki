# Checklist - Escalazione dei privilegi su Linux

<details>

<summary><strong>Impara l'hacking su AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repository di Github.

</details>

<figure><img src="../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

Unisciti al server [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) per comunicare con hacker esperti e cacciatori di bug bounty!

**Approfondimenti sull'Hacking**\
Coinvolgiti con contenuti che esplorano l'emozione e le sfide dell'hacking

**Notizie sull'Hacking in Tempo Reale**\
Resta aggiornato con il mondo dell'hacking in rapida evoluzione attraverso notizie e approfondimenti in tempo reale

**Ultime Annunci**\
Resta informato sui nuovi bug bounty in arrivo e sugli aggiornamenti cruciali delle piattaforme

**Unisciti a noi su** [**Discord**](https://discord.com/invite/N3FrSbmwdy) e inizia a collaborare con i migliori hacker oggi!

### **Miglior strumento per cercare vettori di escalation dei privilegi locali su Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Informazioni di Sistema](privilege-escalation/#system-information)

* [ ] Ottieni le **informazioni sul sistema operativo**
* [ ] Controlla il [**PATH**](privilege-escalation/#path), qualche **cartella scrivibile**?
* [ ] Controlla le [**variabili d'ambiente**](privilege-escalation/#env-info), qualche dettaglio sensibile?
* [ ] Cerca [**exploit del kernel**](privilege-escalation/#kernel-exploits) **usando script** (DirtyCow?)
* [ ] **Controlla** se la [**versione di sudo è vulnerabile**](privilege-escalation/#sudo-version)
* [ ] [**Verifica fallita della firma di Dmesg**](privilege-escalation/#dmesg-signature-verification-failed)
* [ ] Altre enumerazioni di sistema ([data, statistiche di sistema, informazioni sulla CPU, stampanti](privilege-escalation/#more-system-enumeration))
* [ ] [Enumerare ulteriori difese](privilege-escalation/#enumerate-possible-defenses)

### [Dischi](privilege-escalation/#drives)

* [ ] **Elenca i** dischi montati
* [ ] **Qualche disco non montato?**
* [ ] **Qualche credenziale in fstab?**

### [**Software Installato**](privilege-escalation/#installed-software)

* [ ] **Controlla se c'è** [**software utile**](privilege-escalation/#useful-software) **installato**
* [ ] **Controlla se c'è** [**software vulnerabile**](privilege-escalation/#vulnerable-software-installed) **installato**

### [Processi](privilege-escalation/#processes)

* [ ] Sta eseguendo qualche **software sconosciuto**?
* [ ] Sta eseguendo qualche software con **più privilegi di quelli dovuti**?
* [ ] Cerca **exploit dei processi in esecuzione** (soprattutto la versione in esecuzione).
* [ ] Puoi **modificare il binario** di qualche processo in esecuzione?
* [ ] **Monitora i processi** e controlla se qualche processo interessante viene eseguito frequentemente.
* [ ] Puoi **leggere** qualche **memoria di processo** interessante (dove potrebbero essere salvate le password)?

### [Lavori Pianificati/Cron jobs?](privilege-escalation/#scheduled-jobs)

* [ ] Il [**PATH** ](privilege-escalation/#cron-path)viene modificato da qualche cron e puoi **scrivere** al suo interno?
* [ ] Qualche [**carattere jolly** ](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection)in un lavoro cron?
* [ ] Alcuni [**script modificabili** ](privilege-escalation/#cron-script-overwriting-and-symlink)vengono **eseguiti** o si trovano in una **cartella modificabile**?
* [ ] Hai rilevato che qualche **script** potrebbe essere o viene [**eseguito** molto **frequentemente**](privilege-escalation/#frequent-cron-jobs)? (ogni 1, 2 o 5 minuti)

### [Servizi](privilege-escalation/#services)

* [ ] Qualche file **.service scrivibile**?
* [ ] Qualche binario scrivibile eseguito da un **servizio**?
* [ ] Qualche cartella scrivibile nel PATH di systemd?

### [Timers](privilege-escalation/#timers)

* [ ] Qualche **timer scrivibile**?

### [Sockets](privilege-escalation/#sockets)

* [ ] Qualche file **.socket scrivibile**?
* [ ] Puoi **comunicare con qualche socket**?
* [ ] **Socket HTTP** con informazioni interessanti?

### [D-Bus](privilege-escalation/#d-bus)

* [ ] Puoi **comunicare con qualche D-Bus**?

### [Rete](privilege-escalation/#network)

* [ ] Enumera la rete per sapere dove ti trovi
* [ ] **Porte aperte a cui non potevi accedere prima** ottenendo una shell all'interno della macchina?
* [ ] Puoi **sniffare il traffico** usando `tcpdump`?

### [Utenti](privilege-escalation/#users)

* [ ] Enumerazione di utenti/gruppi **generici**
* [ ] Hai un **UID molto grande**? La **macchina** è **vulnerabile**?
* [ ] Puoi [**escalare i privilegi grazie a un gruppo**](privilege-escalation/interesting-groups-linux-pe/) a cui appartieni?
* [ ] Dati della **clipboard**?
* [ ] Politica delle password?
* [ ] Prova a **usare** ogni **password conosciuta** che hai scoperto in precedenza per accedere **con ogni** possibile **utente**. Prova ad accedere anche senza password.

### [PATH Scrivibile](privilege-escalation/#writable-path-abuses)

* [ ] Se hai **privilegi di scrittura su qualche cartella nel PATH** potresti essere in grado di escalare i privilegi

### [Comandi SUDO e SUID](privilege-escalation/#sudo-and-suid)

* [ ] Puoi eseguire **qualunque comando con sudo**? Puoi usarlo per LEGGERE, SCRIVERE o ESEGUIRE qualcosa come root? ([**GTFOBins**](https://gtfobins.github.io))
* [ ] C'è qualche **binario SUID sfruttabile**? ([**GTFOBins**](https://gtfobins.github.io))
* [ ] I [**comandi sudo** sono **limitati** dal **path**? puoi **bypassare** le restrizioni](privilege-escalation/#sudo-execution-bypassing-paths)?
* [ ] [**Binario Sudo/SUID senza percorso indicato**](privilege-escalation/#sudo-command-suid-binary-without-command-path)?
* [ ] [**Binario SUID specificando il percorso**](privilege-escalation/#suid-binary-with-command-path)? Bypass
* [ ] [**Vulnerabilità LD\_PRELOAD**](privilege-escalation/#ld\_preload)
* [ ] [**Mancanza di libreria .so nel binario SUID**](privilege-escalation/#suid-binary-so-injection) da una cartella scrivibile?
* [ ] [**Token SUDO disponibili**](privilege-escalation/#reusing-sudo-tokens)? [**Puoi creare un token SUDO**](privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than)?
* [ ] Puoi [**leggere o modificare i file sudoers**](privilege-escalation/#etc-sudoers-etc-sudoers-d)?
* [ ] Puoi [**modificare /etc/ld.so.conf.d/**](privilege-escalation/#etc-ld-so-conf-d)?
* [ ] [**Comando OpenBSD DOAS**](privilege-escalation/#doas)
### [Capacità](privilege-escalation/#capabilities)

* [ ] Qualsiasi binario ha qualche **capacità inaspettata**?

### [ACL](privilege-escalation/#acls)

* [ ] Qualsiasi file ha qualche **ACL inaspettata**?

### [Sessioni Shell aperte](privilege-escalation/#open-shell-sessions)

* [ ] **screen**
* [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

* [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
* [ ] [**Valori di configurazione SSH interessanti**](privilege-escalation/#ssh-interesting-configuration-values)

### [File Interessanti](privilege-escalation/#interesting-files)

* [ ] **File di profilo** - Leggere dati sensibili? Scrivere per privesc?
* [ ] **File passwd/shadow** - Leggere dati sensibili? Scrivere per privesc?
* [ ] **Controllare cartelle comunemente interessanti** per dati sensibili
* [ ] **File in Posizioni Strane/Proprietà**, a cui potresti avere accesso o alterare file eseguibili
* [ ] **Modificati** negli ultimi minuti
* [ ] **File DB Sqlite**
* [ ] **File Nascosti**
* [ ] **Script/Eseguibili nel PATH**
* [ ] **File Web** (password?)
* [ ] **Backup**?
* [ ] **File noti che contengono password**: Usare **Linpeas** e **LaZagne**
* [ ] **Ricerca generica**

### [**File Scrivibili**](privilege-escalation/#writable-files)

* [ ] **Modificare libreria python** per eseguire comandi arbitrari?
* [ ] Puoi **modificare file di log**? Sfruttare l'exploit **Logtotten**
* [ ] Puoi **modificare /etc/sysconfig/network-scripts/**? Sfruttare l'exploit di Centos/Redhat
* [ ] Puoi [**scrivere in file ini, int.d, systemd o rc.d**](privilege-escalation/#init-init-d-systemd-and-rc-d)?

### [**Altri trucchi**](privilege-escalation/#other-tricks)

* [ ] Puoi [**abusare di NFS per escalare privilegi**](privilege-escalation/#nfs-privilege-escalation)?
* [ ] Devi [**uscire da una shell restrittiva**](privilege-escalation/#escaping-from-restricted-shells)?

<figure><img src="../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

Unisciti al server [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) per comunicare con hacker esperti e cacciatori di bug!

**Insight sulle Hacking**\
Coinvolgiti con contenuti che esplorano l'emozione e le sfide dell'hacking

**Notizie sull'Hacking in Tempo Reale**\
Resta aggiornato con il mondo dell'hacking attraverso notizie e approfondimenti in tempo reale

**Ultime Annunci**\
Rimani informato sui nuovi bug bounty in arrivo e sugli aggiornamenti cruciali della piattaforma

**Unisciti a noi su** [**Discord**](https://discord.com/invite/N3FrSbmwdy) e inizia a collaborare con i migliori hacker oggi!

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
