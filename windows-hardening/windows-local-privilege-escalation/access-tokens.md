# Access Tokens

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata in HackTricks**? O vuoi avere accesso all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **e al** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Token di accesso

Ogni **utente loggato** nel sistema **possiede un token di accesso con informazioni di sicurezza** per quella sessione di accesso. Il sistema crea un token di accesso quando l'utente effettua il login. **Ogni processo eseguito** a nome dell'utente **ha una copia del token di accesso**. Il token identifica l'utente, i gruppi dell'utente e i privilegi dell'utente. Un token contiene anche un SID di accesso (Security Identifier) che identifica la sessione di accesso corrente.

Puoi vedere queste informazioni eseguendo `whoami /all`

```
whoami /all

USER INFORMATION
----------------

User Name             SID
===================== ============================================
desktop-rgfrdxl\cpolo S-1-5-21-3359511372-53430657-2078432294-1001


GROUP INFORMATION
-----------------

Group Name                                                    Type             SID                                                                                                           Attributes
============================================================= ================ ============================================================================================================= ==================================================
Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192
Everyone                                                      Well-known group S-1-1-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114                                                                                                     Group used for deny only
BUILTIN\Administrators                                        Alias            S-1-5-32-544                                                                                                  Group used for deny only
BUILTIN\Users                                                 Alias            S-1-5-32-545                                                                                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Performance Log Users                                 Alias            S-1-5-32-559                                                                                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                                      Well-known group S-1-5-4                                                                                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                                                 Well-known group S-1-2-1                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11                                                                                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15                                                                                                      Mandatory group, Enabled by default, Enabled group
MicrosoftAccount\cpolop@outlook.com                           User             S-1-11-96-3623454863-58364-18864-2661722203-1597581903-3158937479-2778085403-3651782251-2842230462-2314292098 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113                                                                                                     Mandatory group, Enabled by default, Enabled group
LOCAL                                                         Well-known group S-1-2-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Cloud Account Authentication                     Well-known group S-1-5-64-36                                                                                                   Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```

o utilizzando _Process Explorer_ di Sysinternals (seleziona il processo e accedi alla scheda "Sicurezza"):

![](<../../.gitbook/assets/image (321).png>)

### Amministratore locale

Quando un amministratore locale effettua il login, **vengono creati due token di accesso**: uno con i diritti di amministratore e l'altro con i diritti normali. **Per impostazione predefinita**, quando questo utente esegue un processo viene utilizzato quello con i **diritti regolari** (non amministratore). Quando questo utente cerca di **eseguire** qualcosa **come amministratore** ("Esegui come amministratore", ad esempio), verrà utilizzato il **UAC** per richiedere il permesso.\
Se vuoi [**saperne di più sul UAC leggi questa pagina**](../authentication-credentials-uac-and-efs/#uac)**.**

### Impersonazione delle credenziali dell'utente

Se hai **credenziali valide di un altro utente**, puoi **creare** una **nuova sessione di accesso** con quelle credenziali:

```
runas /user:domain\username cmd.exe
```

Il **token di accesso** ha anche un **riferimento** alle sessioni di accesso all'interno di **LSASS**, ciò è utile se il processo ha bisogno di accedere a degli oggetti della rete.\
Puoi avviare un processo che **utilizza credenziali diverse per accedere ai servizi di rete** utilizzando:

```
runas /user:domain\username /netonly cmd.exe
```

Questo è utile se si dispone di credenziali valide per accedere agli oggetti nella rete, ma tali credenziali non sono valide all'interno dell'host corrente in quanto verranno utilizzate solo nella rete (nell'host corrente verranno utilizzati i privilegi dell'utente corrente).

### Tipi di token

Ci sono due tipi di token disponibili:

* **Token primario**: Serve come rappresentazione delle credenziali di sicurezza di un processo. La creazione e l'associazione di token primari con i processi sono azioni che richiedono privilegi elevati, enfatizzando il principio della separazione dei privilegi. Tipicamente, un servizio di autenticazione è responsabile della creazione del token, mentre un servizio di accesso gestisce la sua associazione con la shell del sistema operativo dell'utente. È importante notare che i processi ereditano il token primario dal processo padre alla creazione.
* **Token di impersonificazione**: Consente a un'applicazione server di adottare temporaneamente l'identità del client per accedere a oggetti sicuri. Questo meccanismo è stratificato in quattro livelli di operazione:
* **Anonimo**: Concede all'applicazione server l'accesso simile a quello di un utente non identificato.
* **Identificazione**: Consente al server di verificare l'identità del client senza utilizzarla per l'accesso agli oggetti.
* **Impersonificazione**: Consente al server di operare con l'identità del client.
* **Delega**: Simile all'impersonificazione, ma include la capacità di estendere questa assunzione di identità a sistemi remoti con cui il server interagisce, garantendo la conservazione delle credenziali.

#### Impersonare i token

Utilizzando il modulo _**incognito**_ di Metasploit, se si dispone di privilegi sufficienti, è possibile elencare e impersonare facilmente altri token. Questo potrebbe essere utile per eseguire azioni come se si fosse l'altro utente. È anche possibile ottenere un'escalation dei privilegi con questa tecnica.

### Privilegi dei token

Scopri quali **privilegi dei token possono essere sfruttati per ottenere un'escalation dei privilegi:**

{% content-ref url="privilege-escalation-abusing-tokens.md" %}
[privilege-escalation-abusing-tokens.md](privilege-escalation-abusing-tokens.md)
{% endcontent-ref %}

Dai un'occhiata a [**tutti i possibili privilegi dei token e alcune definizioni su questa pagina esterna**](https://github.com/gtworek/Priv2Admin).

## Riferimenti

Per saperne di più sui token, consulta questi tutorial: [https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa) e [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata su HackTricks**? O vuoi avere accesso all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **e al** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
