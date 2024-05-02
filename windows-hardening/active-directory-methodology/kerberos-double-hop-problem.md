# Problema del doppio salto di Kerberos

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la **tua azienda pubblicizzata su HackTricks**? o vuoi avere accesso all'**ultima versione del PEASS o scaricare HackTricks in PDF**? Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **e al** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Introduzione

Il problema del "doppio salto" di Kerberos si verifica quando un attaccante tenta di utilizzare **l'autenticazione Kerberos attraverso due** **salti**, ad esempio utilizzando **PowerShell**/**WinRM**.

Quando avviene un'**autenticazione** tramite **Kerberos**, le **credenziali** **non** vengono memorizzate in **memoria**. Pertanto, se esegui mimikatz non **troverai le credenziali** dell'utente nella macchina anche se sta eseguendo processi.

Ciò avviene perché quando ci si connette con Kerberos, avvengono i seguenti passaggi:

1. L'utente fornisce le credenziali e il **domain controller** restituisce un **TGT** di Kerberos all'utente.
2. L'utente utilizza il **TGT** per richiedere un **service ticket** per **connettersi** a Server1.
3. L'utente si **connette** a **Server1** e fornisce il **service ticket**.
4. **Server1** **non** ha le **credenziali** di User1 memorizzate o il **TGT** di User1. Pertanto, quando User1 da Server1 tenta di accedere a un secondo server, non è in grado di autenticarsi.

### Delega non vincolata

Se la **delega non vincolata** è abilitata nel PC, ciò non accadrà poiché il **Server** otterrà un **TGT** di ciascun utente che vi accede. Inoltre, se viene utilizzata la delega non vincolata, è probabile che si possa **compromettere il Domain Controller** da essa.\
[**Ulteriori informazioni nella pagina sulla delega non vincolata**](unconstrained-delegation.md).

### CredSSP

Un altro modo per evitare questo problema, che è [**notoriamente insicuro**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7), è il **Credential Security Support Provider**. Da Microsoft:

> L'autenticazione CredSSP delega le credenziali dell'utente dal computer locale a un computer remoto. Questa pratica aumenta il rischio di sicurezza dell'operazione remota. Se il computer remoto viene compromesso, quando le credenziali vengono trasmesse ad esso, le credenziali possono essere utilizzate per controllare la sessione di rete.

È altamente consigliabile disabilitare **CredSSP** nei sistemi di produzione, nelle reti sensibili e in ambienti simili a causa di preoccupazioni per la sicurezza. Per determinare se **CredSSP** è abilitato, è possibile eseguire il comando `Get-WSManCredSSP`. Questo comando consente di **verificare lo stato di CredSSP** e può essere eseguito anche in remoto, a condizione che **WinRM** sia abilitato.
```powershell
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
## Soluzioni alternative

### Eseguire il comando

Per affrontare il problema del doppio salto, viene presentato un metodo che coinvolge un `Invoke-Command` nidificato. Questo non risolve direttamente il problema ma offre una soluzione alternativa senza la necessità di configurazioni speciali. L'approccio consente di eseguire un comando (`hostname`) su un server secondario tramite un comando PowerShell eseguito da una macchina di attacco iniziale o tramite una sessione PS precedentemente stabilita con il primo server. Ecco come si fa:
```powershell
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
### Registrazione della configurazione della sessione PSSession

Una soluzione per aggirare il problema del doppio salto coinvolge l'utilizzo di `Register-PSSessionConfiguration` con `Enter-PSSession`. Questo metodo richiede un approccio diverso rispetto a `evil-winrm` e consente una sessione che non soffre del limite del doppio salto.
```powershell
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName <pc_name> -Credential domain_name\username
klist
```
### InoltroPorta

Per gli amministratori locali su un target intermedio, l'inoltro porta consente di inviare richieste a un server finale. Utilizzando `netsh`, è possibile aggiungere una regola per l'inoltro porta, insieme a una regola del firewall di Windows per consentire la porta inoltrata.
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` può essere utilizzato per inoltrare le richieste WinRM, potenzialmente come opzione meno rilevabile se preoccupa il monitoraggio di PowerShell. Il comando di seguito ne dimostra l'uso:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

L'installazione di OpenSSH sul primo server consente di aggirare il problema del doppio hop, particolarmente utile per scenari di jump box. Questo metodo richiede l'installazione e la configurazione della CLI di OpenSSH per Windows. Quando configurato per l'Autenticazione della Password, ciò consente al server intermedio di ottenere un TGT per conto dell'utente.

#### Passaggi di Installazione di OpenSSH

1. Scaricare e spostare il file zip dell'ultima versione di OpenSSH sul server di destinazione.
2. Estrarre e eseguire lo script `Install-sshd.ps1`.
3. Aggiungere una regola del firewall per aprire la porta 22 e verificare che i servizi SSH siano in esecuzione.

Per risolvere gli errori di `Connection reset`, potrebbe essere necessario aggiornare i permessi per consentire a tutti di leggere ed eseguire l'accesso alla directory di OpenSSH.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
## Riferimenti

* [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
* [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
* [https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting)
* [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata su HackTricks**? o vuoi avere accesso all'**ultima versione del PEASS o scaricare HackTricks in PDF**? Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **e al** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
