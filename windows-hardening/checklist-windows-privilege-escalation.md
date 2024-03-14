# Checklist - Escalazione dei privilegi locali di Windows

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se desideri vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione esclusiva di [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>

**Try Hard Security Group**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

### **Miglior strumento per cercare vettori di escalation dei privilegi locali di Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Informazioni di sistema](windows-local-privilege-escalation/#system-info)

* [ ] Ottenere [**Informazioni di sistema**](windows-local-privilege-escalation/#system-info)
* [ ] Cercare **exploit del kernel** [**utilizzando script**](windows-local-privilege-escalation/#version-exploits)
* [ ] Utilizzare **Google per cercare** exploit del kernel
* [ ] Utilizzare **searchsploit per cercare** exploit del kernel
* [ ] Informazioni interessanti nelle [**variabili d'ambiente**](windows-local-privilege-escalation/#environment)?
* [ ] Password in [**cronologia di PowerShell**](windows-local-privilege-escalation/#powershell-history)?
* [ ] Informazioni interessanti nelle [**impostazioni Internet**](windows-local-privilege-escalation/#internet-settings)?
* [ ] [**Unità**](windows-local-privilege-escalation/#drives)?
* [ ] [**Exploit WSUS**](windows-local-privilege-escalation/#wsus)?
* [**AlwaysInstallElevated**](windows-local-privilege-escalation/#alwaysinstallelevated)?

### [Enumerazione Logging/AV](windows-local-privilege-escalation/#enumeration)

* [ ] Controllare le impostazioni di [**Audit** ](windows-local-privilege-escalation/#audit-settings)e [**WEF** ](windows-local-privilege-escalation/#wef)
* [ ] Controllare se [**WDigest** ](windows-local-privilege-escalation/#wdigest)è attivo
* [ ] [**Protezione LSA**](windows-local-privilege-escalation/#lsa-protection)?
* [ ] [**Guardia delle credenziali**](windows-local-privilege-escalation/#credentials-guard)[?](windows-local-privilege-escalation/#cached-credentials)
* [ ] [**Credenziali memorizzate**](windows-local-privilege-escalation/#cached-credentials)?
* [ ] Controllare se c'è qualche [**AV**](windows-av-bypass)
* [**Politica AppLocker**](authentication-credentials-uac-and-efs#applocker-policy)?
* [**UAC**](authentication-credentials-uac-and-efs/uac-user-account-control)
* [**Privilegi utente**](windows-local-privilege-escalation/#users-and-groups)
* Controllare i [**privilegi utente attuali**](windows-local-privilege-escalation/#users-and-groups)
* Sei [**membro di qualche gruppo privilegiato**](windows-local-privilege-escalation/#privileged-groups)?
* Controllare se hai abilitato [alcuni di questi token](windows-local-privilege-escalation/#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
* [**Sessioni utente**](windows-local-privilege-escalation/#logged-users-sessions)?
* Controlla [**le home degli utenti**](windows-local-privilege-escalation/#home-folders) (accesso?)
* Controlla la [**Politica delle password**](windows-local-privilege-escalation/#password-policy)
* Cosa c'è [**negli Appunti**](windows-local-privilege-escalation/#get-the-content-of-the-clipboard)?

### [Rete](windows-local-privilege-escalation/#network)

* Controlla le **informazioni di rete** [**attuali**](windows-local-privilege-escalation/#network)
* Controlla i **servizi locali nascosti** limitati all'esterno

### [Processi in esecuzione](windows-local-privilege-escalation/#running-processes)

* Permessi dei file e delle cartelle dei binari dei processi [**file and folders permissions**](windows-local-privilege-escalation/#file-and-folder-permissions)
* [**Mining delle password in memoria**](windows-local-privilege-escalation/#memory-password-mining)
* [**Applicazioni GUI non sicure**](windows-local-privilege-escalation/#insecure-gui-apps)
* Rubare le credenziali con **processi interessanti** tramite `ProcDump.exe` ? (firefox, chrome, ecc ...)

### [Servizi](windows-local-privilege-escalation/#services)

* [Puoi **modificare qualche servizio**?](windows-local-privilege-escalation#permissions)
* [Puoi **modificare** il **binario** eseguito da un **servizio**?](windows-local-privilege-escalation/#modify-service-binary-path)
* [Puoi **modificare** il **registro** di un **servizio**?](windows-local-privilege-escalation/#services-registry-modify-permissions)
* Puoi approfittare di qualche **percorso binario di servizio non quotato**?](windows-local-privilege-escalation/#unquoted-service-paths)

### [**Applicazioni**](windows-local-privilege-escalation/#applications)

* **Permessi di scrittura sulle applicazioni installate**](windows-local-privilege-escalation/#write-permissions)
* [**Applicazioni di avvio**](windows-local-privilege-escalation/#run-at-startup)
* **Driver** vulnerabili](windows-local-privilege-escalation/#drivers)
### [DLL Hijacking](windows-local-privilege-escalation/#path-dll-hijacking)

* [ ] Puoi **scrivere in qualsiasi cartella all'interno del PATH**?
* [ ] Esiste un binario di servizio noto che **cerca di caricare una DLL inesistente**?
* [ ] Puoi **scrivere** in qualsiasi **cartella di binari**?

### [Rete](windows-local-privilege-escalation/#network)

* [ ] Enumera la rete (condivisioni, interfacce, percorsi, vicini, ...)
* [ ] Dai un'occhiata speciale ai servizi di rete in ascolto su localhost (127.0.0.1)

### [Credenziali Windows](windows-local-privilege-escalation/#windows-credentials)

* [ ] Credenziali di [**Winlogon**](windows-local-privilege-escalation/#winlogon-credentials)
* [ ] Credenziali di [**Windows Vault**](windows-local-privilege-escalation/#credentials-manager-windows-vault) che potresti utilizzare?
* [ ] Credenziali [**DPAPI interessanti**](windows-local-privilege-escalation/#dpapi)?
* [ ] Password delle [**reti Wifi salvate**](windows-local-privilege-escalation/#wifi)?
* [ ] Informazioni interessanti nelle [**connessioni RDP salvate**](windows-local-privilege-escalation/#saved-rdp-connections)?
* [ ] Password nelle [**comandi eseguiti di recente**](windows-local-privilege-escalation/#recently-run-commands)?
* [ ] Password del [**Gestore delle credenziali Desktop remoto**](windows-local-privilege-escalation/#remote-desktop-credential-manager)?
* [ ] [**AppCmd.exe** esiste](windows-local-privilege-escalation/#appcmd-exe)? Credenziali?
* [ ] [**SCClient.exe**](windows-local-privilege-escalation/#scclient-sccm)? Caricamento laterale DLL?

### [File e Registro (Credenziali)](windows-local-privilege-escalation/#files-and-registry-credentials)

* [ ] **Putty:** [**Credenziali**](windows-local-privilege-escalation/#putty-creds) **e** [**Chiavi host SSH**](windows-local-privilege-escalation/#putty-ssh-host-keys)
* [ ] [**Chiavi SSH nel registro**](windows-local-privilege-escalation/#ssh-keys-in-registry)?
* [ ] Password nei [**file non assistiti**](windows-local-privilege-escalation/#unattended-files)?
* [ ] Qualsiasi backup di [**SAM & SYSTEM**](windows-local-privilege-escalation/#sam-and-system-backups)?
* [ ] [**Credenziali cloud**](windows-local-privilege-escalation/#cloud-credentials)?
* [ ] File [**McAfee SiteList.xml**](windows-local-privilege-escalation/#mcafee-sitelist.xml)?
* [**Password GPP memorizzata**](windows-local-privilege-escalation/#cached-gpp-pasword)?
* Password nel [**file di configurazione web di IIS**](windows-local-privilege-escalation/#iis-web-config)?
* Informazioni interessanti nei [**log web**](windows-local-privilege-escalation/#logs)?
* Vuoi [**chiedere le credenziali**](windows-local-privilege-escalation/#ask-for-credentials) all'utente?
* File interessanti all'interno del [**Cestino**](windows-local-privilege-escalation/#credentials-in-the-recyclebin)?
* Altri [**registri contenenti credenziali**](windows-local-privilege-escalation/#inside-the-registry)?
* All'interno dei [**dati del browser**](windows-local-privilege-escalation/#browsers-history) (database, cronologia, segnalibri, ...)?
* [**Ricerca generica delle password**](windows-local-privilege-escalation/#generic-password-search-in-files-and-registry) nei file e nel registro
* [**Strumenti**](windows-local-privilege-escalation/#tools-that-search-for-passwords) per cercare automaticamente le password

### [Handler Divulgati](windows-local-privilege-escalation/#leaked-handlers)

* [ ] Hai accesso a un handler di un processo eseguito dall'amministratore?

### [Impersonificazione del Client della Pipe](windows-local-privilege-escalation/#named-pipe-client-impersonation)

* [ ] Verifica se puoi abusarne

**Try Hard Security Group**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repository di Github.

</details>
