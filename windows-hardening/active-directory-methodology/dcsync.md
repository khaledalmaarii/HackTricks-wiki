# DCSync

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilizza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) per creare facilmente e automatizzare flussi di lavoro con gli strumenti della community più avanzati al mondo.\
Ottieni l'accesso oggi stesso:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## DCSync

L'autorizzazione **DCSync** implica avere queste autorizzazioni sul dominio stesso: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** e **Replicating Directory Changes In Filtered Set**.

**Note importanti su DCSync:**

* L'attacco **DCSync simula il comportamento di un Domain Controller e chiede ad altri Domain Controller di replicare le informazioni** utilizzando il protocollo remoto del servizio di replica della directory (MS-DRSR). Poiché MS-DRSR è una funzione valida e necessaria di Active Directory, non può essere disattivato o disabilitato.
* Per impostazione predefinita, solo i gruppi **Domain Admins, Enterprise Admins, Administrators e Domain Controllers** hanno i privilegi richiesti.
* Se una password di un account è memorizzata con una crittografia reversibile, è disponibile un'opzione in Mimikatz per restituire la password in chiaro.

### Enumerazione

Verifica chi ha queste autorizzazioni utilizzando `powerview`:
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
### Sfruttare localmente

To exploit a Windows Active Directory environment locally, you can use the DCSync attack. This attack allows you to retrieve the NTLM hash of a domain user without the need for administrative privileges. 

Per sfruttare localmente un ambiente Windows Active Directory, è possibile utilizzare l'attacco DCSync. Questo attacco consente di recuperare l'hash NTLM di un utente di dominio senza la necessità di privilegi amministrativi. 

The DCSync attack takes advantage of the Domain Controller (DC) functionality that allows replication of domain data. By impersonating a DC, an attacker can request the replication of the NTLM hash of a specific user account. 

L'attacco DCSync sfrutta la funzionalità del Domain Controller (DC) che consente la replica dei dati di dominio. Impersonando un DC, un attaccante può richiedere la replica dell'hash NTLM di un account utente specifico. 

To perform the DCSync attack, you need to have the necessary permissions to impersonate a DC. This can be achieved by compromising a machine with administrative privileges or by using a compromised domain user account with the "Replicating Directory Changes" permission. 

Per eseguire l'attacco DCSync, è necessario disporre delle autorizzazioni necessarie per impersonare un DC. Ciò può essere ottenuto compromettendo una macchina con privilegi amministrativi o utilizzando un account utente di dominio compromesso con l'autorizzazione "Replicating Directory Changes". 

Once you have the necessary permissions, you can use the `mimikatz` tool to perform the DCSync attack. `mimikatz` is a powerful tool that allows you to extract various types of credentials from Windows systems. 

Una volta ottenute le autorizzazioni necessarie, è possibile utilizzare lo strumento `mimikatz` per eseguire l'attacco DCSync. `mimikatz` è uno strumento potente che consente di estrarre vari tipi di credenziali dai sistemi Windows. 

By running the `lsadump::dcsync` command in `mimikatz`, you can request the replication of the NTLM hash for a specific user account. The hash will be stored in a file that you can later crack using tools like `hashcat` or `John the Ripper`. 

Eseguendo il comando `lsadump::dcsync` in `mimikatz`, è possibile richiedere la replica dell'hash NTLM per un account utente specifico. L'hash verrà memorizzato in un file che successivamente potrà essere decifrato utilizzando strumenti come `hashcat` o `John the Ripper`. 

It is important to note that the DCSync attack requires administrative privileges or the "Replicating Directory Changes" permission, making it a powerful technique for privilege escalation in an Active Directory environment. 

È importante notare che l'attacco DCSync richiede privilegi amministrativi o l'autorizzazione "Replicating Directory Changes", rendendolo una tecnica potente per l'escalation dei privilegi in un ambiente Active Directory.
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Sfruttare in remoto

To exploit the DCSync attack remotely, you need to have remote code execution (RCE) on a domain-joined machine. Once you have RCE, you can use the `mimikatz` tool to perform the DCSync attack.

Per sfruttare l'attacco DCSync in remoto, è necessario avere l'esecuzione remota del codice (RCE) su una macchina connessa al dominio. Una volta ottenuta l'RCE, è possibile utilizzare lo strumento `mimikatz` per eseguire l'attacco DCSync.
```powershell
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-pwd-last-set] #To see when each account's password was last changed
[-history] #To dump password history, may be helpful for offline password cracking
```
`-just-dc` genera 3 file:

* uno con gli **hash NTLM**
* uno con le **chiavi Kerberos**
* uno con le password in chiaro dal NTDS per gli account impostati con [**cifratura reversibile**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) abilitata. Puoi ottenere gli utenti con cifratura reversibile con

```powershell
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Persistenza

Se sei un amministratore di dominio, puoi concedere queste autorizzazioni a qualsiasi utente con l'aiuto di `powerview`:
```powershell
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Quindi, puoi **verificare se all'utente sono stati assegnati correttamente** i 3 privilegi cercandoli nell'output di (dovresti essere in grado di vedere i nomi dei privilegi all'interno del campo "ObjectType"):
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Mitigazione

* Security Event ID 4662 (Deve essere abilitata la policy di audit per l'oggetto) - È stata eseguita un'operazione su un oggetto
* Security Event ID 5136 (Deve essere abilitata la policy di audit per l'oggetto) - È stato modificato un oggetto del servizio di directory
* Security Event ID 4670 (Deve essere abilitata la policy di audit per l'oggetto) - Sono state modificate le autorizzazioni su un oggetto
* AD ACL Scanner - Crea e confronta report delle ACL. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## Riferimenti

* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
* [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) per creare e **automatizzare workflow** con gli strumenti della community più avanzati al mondo.\
Ottieni l'accesso oggi stesso:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
