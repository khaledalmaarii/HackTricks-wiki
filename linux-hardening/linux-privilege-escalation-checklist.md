# Checklist - Escalazione dei privilegi in Linux

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Unisciti al server [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) per comunicare con hacker esperti e cacciatori di bug bounty!

**Hacking Insights**\
Interagisci con contenuti che approfondiscono l'emozione e le sfide dell'hacking

**Notizie sull'hacking in tempo reale**\
Resta aggiornato sul mondo dell'hacking frenetico attraverso notizie e approfondimenti in tempo reale

**Ultime novità**\
Rimani informato sul lancio delle nuove bug bounty e sugli aggiornamenti cruciali della piattaforma

**Unisciti a noi su** [**Discord**](https://discord.com/invite/N3FrSbmwdy) e inizia a collaborare con i migliori hacker oggi stesso!

### **Il miglior strumento per cercare vettori di escalation dei privilegi locali in Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Informazioni di sistema](privilege-escalation/#system-information)

* [ ] Ottieni le **informazioni sul sistema operativo**
* [ ] Controlla il [**PATH**](privilege-escalation/#path), qualche **cartella scrivibile**?
* [ ] Controlla le [**variabili di ambiente**](privilege-escalation/#env-info), qualche dettaglio sensibile?
* [ ] Cerca [**exploit del kernel**](privilege-escalation/#kernel-exploits) **utilizzando script** (DirtyCow?)
* [ ] **Verifica** se la [**versione di sudo è vulnerabile**](privilege-escalation/#sudo-version)
* [ ] [**Dmesg** verifica della firma fallita](privilege-escalation/#dmesg-signature-verification-failed)
* [ ] Altre informazioni di sistema ([data, statistiche di sistema, informazioni sulla CPU, stampanti](privilege-escalation/#more-system-enumeration))
* [ ] [Enumerare ulteriori difese](privilege-escalation/#enumerate-possible-defenses)

### [Unità](privilege-escalation/#drives)

* [ ] Elenca le unità **montate**
* [ ] C'è qualche unità **non montata**?
* [ ] Ci sono credenziali in fstab?

### [**Software installato**](privilege-escalation/#installed-software)

* [ ] Controlla se è stato **installato del software utile**
* [ ] Controlla se è stato **installato del software vulnerabile**

### [Processi](privilege-escalation/#processes)

* [ ] Sta eseguendo qualche **software sconosciuto**?
* [ ] Sta eseguendo qualche software con **più privilegi di quelli che dovrebbe avere**?
* [ ] Cerca **exploit dei processi in esecuzione** (soprattutto la versione in esecuzione).
* [ ] Puoi **modificare il binario** di qualche processo in esecuzione?
* [ ] **Monitora i processi** e controlla se viene eseguito frequentemente qualche processo interessante.
* [ ] Puoi **leggere** qualche **memoria di processo** interessante (dove potrebbero essere salvate le password)?

### [Lavori pianificati/Cron jobs?](privilege-escalation/#scheduled-jobs)

* [ ] Il [**PATH** ](privilege-escalation/#cron-path)viene modificato da qualche cron e puoi **scrivere** al suo interno?
* [ ] C'è qualche [**carattere jolly** ](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection)in un lavoro cron?
* [ ] Viene **eseguito** uno **script modificabile** o si trova in una **cartella modificabile**?
* [ ] Hai rilevato che qualche **script** potrebbe essere o viene [**eseguito** molto **frequentemente**](privilege-escalation/#frequent-cron-jobs)? (ogni 1, 2 o 5 minuti)

### [Servizi](privilege-escalation/#services)

* [ ] C'è qualche file **.service scrivibile**?
* [ ] Viene eseguito qualche **binario scrivibile** da un **servizio**?
* [ ] C'è qualche cartella **scrivibile nel PATH di systemd**?

### [Timers](privilege-escalation/#timers)

* [ ] C'è qualche **timer scrivibile**?

### [Sockets](privilege-escalation/#sockets)

* [ ] C'è qualche file **.socket scrivibile**?
* [ ] Puoi **comunicare con qualche socket**?
* [ ] Ci sono **socket HTTP** con informazioni interessanti?

### [D-Bus](privilege-escalation/#d-bus)

* [ ] Puoi **comunicare con qualche D-Bus**?

### [Rete](privilege-escalation/#network)

* [ ] Enumera la rete per sapere dove ti trovi
* [ ] Ci sono **porte aperte** a cui non potevi accedere prima di ottenere una shell all'interno della macchina?
* [ ] Puoi **intercettare il traffico** utilizzando `tcpdump`?

### [Utenti](privilege-escalation/#users)

* [ ] Enumerazione di utenti/gruppi **generici**
* [ ] Hai un **UID molto grande**? La **macchina** è **vulnerabile**?
* [ ] Puoi [**aumentare i privilegi grazie a un gruppo**](privilege-escalation/interesting-groups-linux-pe/) a cui appartieni?
* [ ] Dati **negli appunti**?
* [ ] Politica delle password?
* [ ] Prova a **utilizzare** ogni **password conosciuta** che hai scoperto in precedenza per effettuare il login **con ogni** possibile **utente**. Prova anche a effettuare il login senza password.

### [Percorso scrivibile](privilege-escalation/#writable-path-abuses)

* [ ] Se hai **privilegi di scrittura su qualche cartella nel PATH** potresti essere in grado di aumentare i privilegi

### [Comandi SUDO e SUID](privilege-escalation/#sudo-and-suid)

* [ ] Puoi eseguire **qualunque comando con sudo**? Puoi usarlo per LEGGERE, SCRIVERE o ESEGUIRE qualcosa come root? ([**GTFOBins**](https://gtfobins.github.io))
* [ ] C'è qualche **binario SUID sfruttabile**? ([**GTFOBins**](https://gtfobins.github.io))
* [ ] I [**comandi sudo sono limitati** dalla **path**? puoi **eludere** le restrizioni](privilege-escalation/#sudo-execution-bypassing-paths
### [Capabilities](privilege-escalation/#capabilities)

* [ ] Qualsiasi binario ha una **capability inaspettata**?

### [ACLs](privilege-escalation/#acls)

* [ ] Qualsiasi file ha una **ACL inaspettata**?

### [Sessioni di shell aperte](privilege-escalation/#open-shell-sessions)

* [ ] **screen**
* [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

* [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
* [ ] [**Valori di configurazione interessanti di SSH**](privilege-escalation/#ssh-interesting-configuration-values)

### [File interessanti](privilege-escalation/#interesting-files)

* [ ] **File di profilo** - Leggere dati sensibili? Scrivere per privesc?
* [ ] **File passwd/shadow** - Leggere dati sensibili? Scrivere per privesc?
* [ ] **Controllare cartelle comunemente interessanti** per dati sensibili
* [ ] **Posizione strana/File di proprietà**, potresti avere accesso o modificare file eseguibili
* [ ] **Modificato** negli ultimi minuti
* [ ] **File di database Sqlite**
* [ ] **File nascosti**
* [ ] **Script/Binari in PATH**
* [ ] **File web** (password?)
* [ ] **Backup**?
* [ ] **File noti che contengono password**: Usa **Linpeas** e **LaZagne**
* [ ] **Ricerca generica**

### [**File scrivibili**](privilege-escalation/#writable-files)

* [ ] **Modificare la libreria python** per eseguire comandi arbitrari?
* [ ] Puoi **modificare i file di log**? Sfrutta l'exploit di **Logtotten**
* [ ] Puoi **modificare /etc/sysconfig/network-scripts/**? Exploit di Centos/Redhat
* [ ] Puoi [**scrivere nei file ini, int.d, systemd o rc.d**](privilege-escalation/#init-init-d-systemd-and-rc-d)?

### [**Altri trucchi**](privilege-escalation/#other-tricks)

* [ ] Puoi [**abusare di NFS per ottenere privilegi**](privilege-escalation/#nfs-privilege-escalation)?
* [ ] Devi [**uscire da una shell restrittiva**](privilege-escalation/#escaping-from-restricted-shells)?

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Unisciti al server [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) per comunicare con hacker esperti e cacciatori di bug!

**Hacking Insights**\
Interagisci con contenuti che approfondiscono l'emozione e le sfide dell'hacking

**Notizie sull'hacking in tempo reale**\
Resta aggiornato sul mondo dell'hacking frenetico attraverso notizie e approfondimenti in tempo reale

**Ultime novità**\
Rimani informato sul lancio delle nuove taglie di bug e sugli aggiornamenti cruciali della piattaforma

**Unisciti a noi su** [**Discord**](https://discord.com/invite/N3FrSbmwdy) e inizia a collaborare con i migliori hacker oggi stesso!

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**repository di HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
