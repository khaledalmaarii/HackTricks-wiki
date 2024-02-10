# Protezioni delle credenziali di Windows

## Protezioni delle credenziali

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## WDigest

Il protocollo [WDigest](https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396), introdotto con Windows XP, è progettato per l'autenticazione tramite il protocollo HTTP ed è **abilitato per impostazione predefinita su Windows XP fino a Windows 8.0 e Windows Server 2003 fino a Windows Server 2012**. Questa impostazione predefinita comporta **l'archiviazione delle password in testo normale in LSASS** (Local Security Authority Subsystem Service). Un attaccante può utilizzare Mimikatz per **estrarre queste credenziali** eseguendo:
```bash
sekurlsa::wdigest
```
Per **attivare o disattivare questa funzionalità**, le chiavi del registro _**UseLogonCredential**_ e _**Negotiate**_ all'interno di _**HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ devono essere impostate su "1". Se queste chiavi sono **assenti o impostate su "0"**, WDigest è **disabilitato**:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## Protezione LSA

A partire da **Windows 8.1**, Microsoft ha migliorato la sicurezza di LSA per **bloccare letture di memoria non autorizzate o iniezioni di codice da parte di processi non fidati**. Questo miglioramento ostacola il funzionamento tipico di comandi come `mimikatz.exe sekurlsa:logonpasswords`. Per **abilitare questa protezione avanzata**, il valore _**RunAsPPL**_ in _**HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\LSA**_ deve essere impostato su 1:
```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
### Bypass

È possibile aggirare questa protezione utilizzando il driver Mimikatz mimidrv.sys:

![](../../.gitbook/assets/mimidrv.png)

## Credential Guard

**Credential Guard**, una funzionalità esclusiva di **Windows 10 (edizioni Enterprise ed Education)**, migliora la sicurezza delle credenziali di macchina utilizzando **Virtual Secure Mode (VSM)** e **Virtualization Based Security (VBS)**. Sfrutta le estensioni di virtualizzazione della CPU per isolare i processi chiave all'interno di uno spazio di memoria protetto, lontano dalla portata del sistema operativo principale. Questo isolamento garantisce che nemmeno il kernel possa accedere alla memoria in VSM, proteggendo efficacemente le credenziali da attacchi come **pass-the-hash**. L'**Autorità di sicurezza locale (LSA)** opera in questo ambiente sicuro come un trustlet, mentre il processo **LSASS** nel sistema operativo principale agisce solo come un comunicatore con l'LSA di VSM.

Per impostazione predefinita, **Credential Guard** non è attivo e richiede l'attivazione manuale all'interno di un'organizzazione. È fondamentale per migliorare la sicurezza contro strumenti come **Mimikatz**, che sono ostacolati nella loro capacità di estrarre credenziali. Tuttavia, le vulnerabilità possono ancora essere sfruttate attraverso l'aggiunta di **Security Support Provider (SSP)** personalizzati per catturare le credenziali in chiaro durante i tentativi di accesso.

Per verificare lo stato di attivazione di **Credential Guard**, è possibile controllare la chiave di registro **_LsaCfgFlags_** in **_HKLM\System\CurrentControlSet\Control\LSA_**. Un valore di "**1**" indica l'attivazione con **blocco UEFI**, "**2**" senza blocco e "**0**" indica che non è abilitato. Questo controllo del registro, sebbene un forte indicatore, non è l'unico passaggio per abilitare Credential Guard. Sono disponibili linee guida dettagliate e uno script PowerShell per abilitare questa funzionalità online.
```powershell
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Per una comprensione completa e istruzioni su come abilitare **Credential Guard** in Windows 10 e la sua attivazione automatica nei sistemi compatibili di **Windows 11 Enterprise ed Education (versione 22H2)**, visita la [documentazione di Microsoft](https://docs.microsoft.com/it-it/windows/security/identity-protection/credential-guard/credential-guard-manage).

Ulteriori dettagli sull'implementazione di SSP personalizzati per la cattura delle credenziali sono forniti in [questa guida](../active-directory-methodology/custom-ssp.md).


## Modalità RDP RestrictedAdmin

**Windows 8.1 e Windows Server 2012 R2** hanno introdotto diverse nuove funzionalità di sicurezza, tra cui la **_modalità Restricted Admin per RDP_**. Questa modalità è stata progettata per migliorare la sicurezza mitigando i rischi associati agli attacchi di **[pass the hash](https://blog.ahasayen.com/pass-the-hash/)**.

Tradizionalmente, quando ci si connette a un computer remoto tramite RDP, le credenziali vengono memorizzate sulla macchina di destinazione. Ciò rappresenta un rischio significativo per la sicurezza, soprattutto quando si utilizzano account con privilegi elevati. Tuttavia, con l'introduzione della **_modalità Restricted Admin_**, questo rischio viene notevolmente ridotto.

Quando si avvia una connessione RDP utilizzando il comando **mstsc.exe /RestrictedAdmin**, l'autenticazione al computer remoto viene eseguita senza memorizzare le credenziali su di esso. Questo approccio garantisce che, in caso di infezione da malware o se un utente malintenzionato ottiene accesso al server remoto, le tue credenziali non siano compromesse, in quanto non vengono memorizzate sul server.

È importante notare che nella **modalità Restricted Admin**, i tentativi di accedere alle risorse di rete dalla sessione RDP non utilizzeranno le tue credenziali personali; al contrario, verrà utilizzata l'identità della macchina.

Questa funzionalità rappresenta un passo significativo avanti nella sicurezza delle connessioni desktop remote e nella protezione delle informazioni sensibili da esposizione in caso di violazione della sicurezza.

![](../../.gitbook/assets/ram.png)

Per ulteriori informazioni dettagliate visita [questa risorsa](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).


## Credenziali memorizzate in cache

Windows protegge le **credenziali di dominio** tramite il **Local Security Authority (LSA)**, supportando processi di accesso con protocolli di sicurezza come **Kerberos** e **NTLM**. Una caratteristica chiave di Windows è la sua capacità di memorizzare nella cache gli **ultimi dieci accessi al dominio** per garantire agli utenti di poter ancora accedere ai loro computer anche se il **controller di dominio è offline** - un vantaggio per gli utenti di laptop spesso lontani dalla rete aziendale.

Il numero di accessi memorizzati nella cache può essere regolato tramite una specifica **chiave di registro o una policy di gruppo**. Per visualizzare o modificare questa impostazione, viene utilizzato il seguente comando:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
L'accesso a queste credenziali memorizzate nella cache è strettamente controllato, con solo l'account **SYSTEM** che ha le necessarie autorizzazioni per visualizzarle. Gli amministratori che hanno bisogno di accedere a queste informazioni devono farlo con i privilegi dell'utente SYSTEM. Le credenziali sono memorizzate in: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** può essere utilizzato per estrarre queste credenziali memorizzate nella cache utilizzando il comando `lsadump::cache`.

Per ulteriori dettagli, la [fonte](http://juggernaut.wikidot.com/cached-credentials) originale fornisce informazioni complete.


## Utenti protetti

L'appartenenza al gruppo **Protected Users** introduce diversi miglioramenti della sicurezza per gli utenti, garantendo livelli più elevati di protezione contro il furto e l'abuso delle credenziali:

- **Delega delle credenziali (CredSSP)**: Anche se l'impostazione della Group Policy per **Consenti la delega delle credenziali predefinite** è abilitata, le credenziali in testo normale degli utenti protetti non verranno memorizzate nella cache.
- **Windows Digest**: A partire da **Windows 8.1 e Windows Server 2012 R2**, il sistema non memorizzerà le credenziali in testo normale degli utenti protetti, indipendentemente dallo stato di Windows Digest.
- **NTLM**: Il sistema non memorizzerà le credenziali in testo normale degli utenti protetti o le funzioni unidirezionali NT (NTOWF).
- **Kerberos**: Per gli utenti protetti, l'autenticazione Kerberos non genererà chiavi **DES** o **RC4**, né memorizzerà le credenziali in testo normale o le chiavi a lungo termine oltre l'acquisizione iniziale del Ticket-Granting Ticket (TGT).
- **Accesso offline**: Gli utenti protetti non avranno un verificatore memorizzato creato durante l'accesso o lo sblocco, il che significa che l'accesso offline non è supportato per questi account.

Queste protezioni vengono attivate nel momento in cui un utente, che è membro del gruppo **Protected Users**, accede al dispositivo. Ciò garantisce che siano in atto misure di sicurezza critiche per proteggersi da vari metodi di compromissione delle credenziali.

Per ulteriori informazioni dettagliate, consultare la [documentazione](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group) ufficiale.

**Tabella tratta dalla** [**documentazione**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

| Windows Server 2003 RTM | Windows Server 2003 SP1+ | <p>Windows Server 2012,<br>Windows Server 2008 R2,<br>Windows Server 2008</p> | Windows Server 2016          |
| ----------------------- | ------------------------ | ----------------------------------------------------------------------------- | ---------------------------- |
| Account Operators       | Account Operators        | Account Operators                                                             | Account Operators            |
| Administrator           | Administrator            | Administrator                                                                 | Administrator                |
| Administrators          | Administrators           | Administrators                                                                | Administrators               |
| Backup Operators        | Backup Operators         | Backup Operators                                                              | Backup Operators             |
| Cert Publishers         |                          |                                                                               |                              |
| Domain Admins           | Domain Admins            | Domain Admins                                                                 | Domain Admins                |
| Domain Controllers      | Domain Controllers       | Domain Controllers                                                            | Domain Controllers           |
| Enterprise Admins       | Enterprise Admins        | Enterprise Admins                                                             | Enterprise Admins            |
|                         |                          |                                                                               | Enterprise Key Admins        |
|                         |                          |                                                                               | Key Admins                   |
| Krbtgt                  | Krbtgt                   | Krbtgt                                                                        | Krbtgt                       |
| Print Operators         | Print Operators          | Print Operators                                                               | Print Operators              |
|                         |                          | Read-only Domain Controllers                                                  | Read-only Domain Controllers |
| Replicator              | Replicator               | Replicator                                                                    | Replicator                   |
| Schema Admins           | Schema Admins            | Schema Admins                                                                 | Schema Admins                |
| Server Operators        | Server Operators         | Server Operators                                                              | Server Operators             |

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository github di** [**HackTricks**](https://github.com/carlospolop/hacktricks) **e** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
