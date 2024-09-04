# Checklist - Local Windows Privilege Escalation

{% hint style="success" %}
Impara e pratica il hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica il hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>
{% endhint %}

### **Miglior strumento per cercare vettori di escalation dei privilegi locali di Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Informazioni di sistema](windows-local-privilege-escalation/#system-info)

* [ ] Ottieni [**informazioni di sistema**](windows-local-privilege-escalation/#system-info)
* [ ] Cerca **exploit del kernel** [**utilizzando script**](windows-local-privilege-escalation/#version-exploits)
* [ ] Usa **Google per cercare** exploit del kernel
* [ ] Usa **searchsploit per cercare** exploit del kernel
* [ ] Informazioni interessanti in [**variabili d'ambiente**](windows-local-privilege-escalation/#environment)?
* [ ] Password nella [**cronologia di PowerShell**](windows-local-privilege-escalation/#powershell-history)?
* [ ] Informazioni interessanti nelle [**impostazioni di Internet**](windows-local-privilege-escalation/#internet-settings)?
* [ ] [**Unità**](windows-local-privilege-escalation/#drives)?
* [ ] [**Exploit WSUS**](windows-local-privilege-escalation/#wsus)?
* [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/#alwaysinstallelevated)?

### [Enumerazione di Logging/AV](windows-local-privilege-escalation/#enumeration)

* [ ] Controlla le impostazioni di [**Audit**](windows-local-privilege-escalation/#audit-settings) e [**WEF**](windows-local-privilege-escalation/#wef)
* [ ] Controlla [**LAPS**](windows-local-privilege-escalation/#laps)
* [ ] Controlla se [**WDigest**](windows-local-privilege-escalation/#wdigest) è attivo
* [ ] [**Protezione LSA**](windows-local-privilege-escalation/#lsa-protection)?
* [ ] [**Credentials Guard**](windows-local-privilege-escalation/#credentials-guard)[?](windows-local-privilege-escalation/#cached-credentials)
* [ ] [**Credenziali memorizzate**](windows-local-privilege-escalation/#cached-credentials)?
* [ ] Controlla se ci sono [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
* [ ] [**Politica AppLocker**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
* [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
* [ ] [**Privilegi utente**](windows-local-privilege-escalation/#users-and-groups)
* [ ] Controlla i [**privilegi**] dell'utente [**corrente**](windows-local-privilege-escalation/#users-and-groups)
* [ ] Sei [**membro di qualche gruppo privilegiato**](windows-local-privilege-escalation/#privileged-groups)?
* [ ] Controlla se hai [alcuni di questi token abilitati](windows-local-privilege-escalation/#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
* [ ] [**Sessioni utenti**](windows-local-privilege-escalation/#logged-users-sessions)?
* [ ] Controlla [**le home degli utenti**](windows-local-privilege-escalation/#home-folders) (accesso?)
* [ ] Controlla la [**Politica delle password**](windows-local-privilege-escalation/#password-policy)
* [ ] Cosa c'è [**dentro il Clipboard**](windows-local-privilege-escalation/#get-the-content-of-the-clipboard)?

### [Rete](windows-local-privilege-escalation/#network)

* [ ] Controlla le [**informazioni di rete**](windows-local-privilege-escalation/#network) **correnti**
* [ ] Controlla i **servizi locali nascosti** riservati all'esterno

### [Processi in esecuzione](windows-local-privilege-escalation/#running-processes)

* [ ] Permessi [**file e cartelle dei binari dei processi**](windows-local-privilege-escalation/#file-and-folder-permissions)
* [ ] [**Estrazione password dalla memoria**](windows-local-privilege-escalation/#memory-password-mining)
* [ ] [**App GUI insicure**](windows-local-privilege-escalation/#insecure-gui-apps)
* [ ] Ruba credenziali con **processi interessanti** tramite `ProcDump.exe` ? (firefox, chrome, ecc ...)

### [Servizi](windows-local-privilege-escalation/#services)

* [ ] [Puoi **modificare qualche servizio**?](windows-local-privilege-escalation/#permissions)
* [ ] [Puoi **modificare** il **binario** che viene **eseguito** da qualche **servizio**?](windows-local-privilege-escalation/#modify-service-binary-path)
* [ ] [Puoi **modificare** il **registro** di qualche **servizio**?](windows-local-privilege-escalation/#services-registry-modify-permissions)
* [ ] [Puoi approfittare di qualche **percorso binario di servizio non quotato**?](windows-local-privilege-escalation/#unquoted-service-paths)

### [**Applicazioni**](windows-local-privilege-escalation/#applications)

* [ ] **Scrivi** [**permessi sulle applicazioni installate**](windows-local-privilege-escalation/#write-permissions)
* [ ] [**Applicazioni di avvio**](windows-local-privilege-escalation/#run-at-startup)
* [ ] **Driver vulnerabili** [**Driver**](windows-local-privilege-escalation/#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/#path-dll-hijacking)

* [ ] Puoi **scrivere in qualche cartella dentro PATH**?
* [ ] Esiste qualche binario di servizio noto che **cerca di caricare qualche DLL non esistente**?
* [ ] Puoi **scrivere** in qualche **cartella di binari**?

### [Rete](windows-local-privilege-escalation/#network)

* [ ] Enumera la rete (condivisioni, interfacce, rotte, vicini, ...)
* [ ] Fai particolare attenzione ai servizi di rete in ascolto su localhost (127.0.0.1)

### [Credenziali di Windows](windows-local-privilege-escalation/#windows-credentials)

* [ ] [**Credenziali Winlogon**](windows-local-privilege-escalation/#winlogon-credentials)
* [ ] [**Credenziali Windows Vault**](windows-local-privilege-escalation/#credentials-manager-windows-vault) che potresti usare?
* [ ] Credenziali [**DPAPI**] interessanti](windows-local-privilege-escalation/#dpapi)?
* [ ] Password delle [**reti Wifi salvate**](windows-local-privilege-escalation/#wifi)?
* [ ] Informazioni interessanti nelle [**connessioni RDP salvate**](windows-local-privilege-escalation/#saved-rdp-connections)?
* [ ] Password nei [**comandi eseguiti di recente**](windows-local-privilege-escalation/#recently-run-commands)?
* [ ] Password nel [**gestore delle credenziali di Desktop Remoto**](windows-local-privilege-escalation/#remote-desktop-credential-manager)?
* [ ] Esiste [**AppCmd.exe**](windows-local-privilege-escalation/#appcmd-exe)? Credenziali?
* [ ] [**SCClient.exe**](windows-local-privilege-escalation/#scclient-sccm)? DLL Side Loading?

### [File e Registro (Credenziali)](windows-local-privilege-escalation/#files-and-registry-credentials)

* [ ] **Putty:** [**Credenziali**](windows-local-privilege-escalation/#putty-creds) **e** [**chiavi host SSH**](windows-local-privilege-escalation/#putty-ssh-host-keys)
* [ ] [**Chiavi SSH nel registro**](windows-local-privilege-escalation/#ssh-keys-in-registry)?
* [ ] Password in [**file non presidiati**](windows-local-privilege-escalation/#unattended-files)?
* [ ] Qualche backup di [**SAM & SYSTEM**](windows-local-privilege-escalation/#sam-and-system-backups)?
* [ ] [**Credenziali cloud**](windows-local-privilege-escalation/#cloud-credentials)?
* [ ] File [**McAfee SiteList.xml**](windows-local-privilege-escalation/#mcafee-sitelist.xml)?
* [ ] [**Password GPP memorizzate**](windows-local-privilege-escalation/#cached-gpp-pasword)?
* [ ] Password nel [**file di configurazione IIS Web**](windows-local-privilege-escalation/#iis-web-config)?
* [ ] Informazioni interessanti nei [**log web**](windows-local-privilege-escalation/#logs)?
* [ ] Vuoi [**chiedere credenziali**](windows-local-privilege-escalation/#ask-for-credentials) all'utente?
* [ ] File [**interessanti dentro il Cestino**](windows-local-privilege-escalation/#credentials-in-the-recyclebin)?
* [ ] Altri [**registri contenenti credenziali**](windows-local-privilege-escalation/#inside-the-registry)?
* [ ] Dentro i [**dati del browser**](windows-local-privilege-escalation/#browsers-history) (db, cronologia, segnalibri, ...)?
* [ ] [**Ricerca generica di password**](windows-local-privilege-escalation/#generic-password-search-in-files-and-registry) in file e registro
* [ ] [**Strumenti**](windows-local-privilege-escalation/#tools-that-search-for-passwords) per cercare automaticamente le password

### [Gestori di leak](windows-local-privilege-escalation/#leaked-handlers)

* [ ] Hai accesso a qualche gestore di un processo eseguito da amministratore?

### [Impersonificazione del client Pipe](windows-local-privilege-escalation/#named-pipe-client-impersonation)

* [ ] Controlla se puoi abusarne

{% hint style="success" %}
Impara e pratica il hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica il hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>
{% endhint %}
