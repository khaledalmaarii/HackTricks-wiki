# Problema del doppio salto di Kerberos

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in un'azienda di **sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata in HackTricks**? O vuoi avere accesso all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **e al** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Introduzione

Il problema del "doppio salto" di Kerberos si verifica quando un attaccante cerca di utilizzare l'autenticazione **Kerberos** attraverso due **salti**, ad esempio utilizzando **PowerShell**/**WinRM**.

Quando si verifica un'**autenticazione** tramite **Kerberos**, le **credenziali** non vengono memorizzate nella **memoria**. Pertanto, se si esegue mimikatz, non si troveranno le credenziali dell'utente nella macchina, anche se sta eseguendo processi.

Ciò accade perché durante la connessione con Kerberos si verificano i seguenti passaggi:

1. L'utente1 fornisce le credenziali e il **domain controller** restituisce un **TGT** di Kerberos all'utente1.
2. L'utente1 utilizza il **TGT** per richiedere un **service ticket** per **connettersi** al Server1.
3. L'utente1 si **connette** al **Server1** e fornisce il **service ticket**.
4. Il **Server1** non ha le credenziali dell'utente1 memorizzate né il **TGT** dell'utente1. Pertanto, quando l'utente1 da Server1 tenta di effettuare il login su un secondo server, non riesce ad autenticarsi.

### Delega non vincolata

Se la **delega non vincolata** è abilitata nel PC, ciò non accadrà poiché il **Server** otterrà un **TGT** di ogni utente che vi accede. Inoltre, se viene utilizzata la delega non vincolata, è probabile che si possa **compromettere il Domain Controller** da essa.\
[**Ulteriori informazioni nella pagina sulla delega non vincolata**](unconstrained-delegation.md).

### CredSSP

Un altro modo per evitare questo problema, che è [**notoriamente insicuro**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7), è **Credential Security Support Provider**. Secondo Microsoft:

> L'autenticazione CredSSP delega le credenziali dell'utente dal computer locale a un computer remoto. Questa pratica aumenta il rischio di sicurezza dell'operazione remota. Se il computer remoto viene compromesso, quando le credenziali vengono trasmesse ad esso, le credenziali possono essere utilizzate per controllare la sessione di rete.

Si consiglia vivamente di disabilitare **CredSSP** nei sistemi di produzione, nelle reti sensibili e in ambienti simili a causa di problemi di sicurezza. Per determinare se **CredSSP** è abilitato, è possibile eseguire il comando `Get-WSManCredSSP`. Questo comando consente di **verificare lo stato di CredSSP** e può essere eseguito anche in remoto, a condizione che **WinRM** sia abilitato.
```powershell
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
## Soluzioni alternative

### Invoke Command

Per affrontare il problema del doppio salto, viene presentato un metodo che coinvolge un `Invoke-Command` annidato. Questo non risolve direttamente il problema, ma offre una soluzione alternativa senza la necessità di configurazioni speciali. L'approccio consente di eseguire un comando (`hostname`) su un server secondario tramite un comando PowerShell eseguito da una macchina di attacco iniziale o tramite una sessione PS precedentemente stabilita con il primo server. Ecco come si fa:
```powershell
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
In alternativa, si suggerisce di stabilire una PS-Session con il primo server ed eseguire il comando `Invoke-Command` utilizzando `$cred` per centralizzare le attività.

### Registrare la configurazione di PSSession

Una soluzione per bypassare il problema del doppio hop consiste nell'utilizzare `Register-PSSessionConfiguration` con `Enter-PSSession`. Questo metodo richiede un approccio diverso rispetto a `evil-winrm` e consente di avere una sessione che non soffre della limitazione del doppio hop.
```powershell
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName <pc_name> -Credential domain_name\username
klist
```
### PortForwarding

Per gli amministratori locali su un target intermedio, il port forwarding consente di inviare richieste a un server finale. Utilizzando `netsh`, è possibile aggiungere una regola per il port forwarding, insieme a una regola del firewall di Windows per consentire la porta inoltrata.
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` può essere utilizzato per inoltrare le richieste di WinRM, potenzialmente come opzione meno rilevabile se la sorveglianza di PowerShell è una preoccupazione. Il comando di seguito ne dimostra l'utilizzo:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

L'installazione di OpenSSH sul primo server consente una soluzione alternativa per il problema del doppio hop, particolarmente utile per scenari di jump box. Questo metodo richiede l'installazione e la configurazione della CLI di OpenSSH per Windows. Quando configurato per l'autenticazione tramite password, ciò consente al server intermedio di ottenere un TGT per conto dell'utente.

#### Passaggi per l'installazione di OpenSSH

1. Scaricare e spostare il file zip dell'ultima versione di OpenSSH sul server di destinazione.
2. Decomprimere ed eseguire lo script `Install-sshd.ps1`.
3. Aggiungere una regola del firewall per aprire la porta 22 e verificare che i servizi SSH siano in esecuzione.

Per risolvere gli errori di "Connessione resettata", potrebbe essere necessario aggiornare i permessi per consentire a tutti di leggere ed eseguire l'accesso alla directory di OpenSSH.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
## Riferimenti

* [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
* [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
* [https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting)
* [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata su HackTricks**? O vuoi avere accesso all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **e al** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
