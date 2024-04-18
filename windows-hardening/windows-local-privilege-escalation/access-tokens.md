# Token di Accesso

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la **tua azienda pubblicizzata su HackTricks**? o vuoi avere accesso all'**ultima versione del PEASS o scaricare HackTricks in PDF**? Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al** [**repo di hacktricks**](https://github.com/carlospolop/hacktricks) **e al** [**repo di hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) è un motore di ricerca alimentato dal **dark web** che offre funzionalità **gratuite** per verificare se un'azienda o i suoi clienti sono stati **compromessi** da **malware ruba-informazioni**.

Il loro obiettivo principale di WhiteIntel è combattere i takeover di account e gli attacchi ransomware derivanti da malware che rubano informazioni.

Puoi controllare il loro sito web e provare il loro motore **gratuitamente** su:

{% embed url="https://whiteintel.io" %}

---

## Token di Accesso

Ogni **utente loggato** al sistema **possiede un token di accesso con informazioni di sicurezza** per quella sessione di accesso. Il sistema crea un token di accesso quando l'utente effettua il login. **Ogni processo eseguito** a nome dell'utente **ha una copia del token di accesso**. Il token identifica l'utente, i gruppi dell'utente e i privilegi dell'utente. Un token contiene anche un SID di login (Security Identifier) che identifica la sessione di accesso corrente.

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
oppure utilizzando _Process Explorer_ di Sysinternals (seleziona il processo e accedi alla scheda "Sicurezza"):

![](<../../.gitbook/assets/image (769).png>)

### Amministratore locale

Quando accede un amministratore locale, **vengono creati due token di accesso**: uno con i diritti di amministratore e l'altro con i diritti normali. **Per impostazione predefinita**, quando questo utente esegue un processo viene utilizzato quello con i **diritti regolari** (non amministratore). Quando questo utente cerca di **eseguire** qualcosa **come amministratore** ("Esegui come amministratore", ad esempio) verrà utilizzato l'**UAC** per chiedere il permesso.\
Se desideri [**saperne di più sull'UAC leggi questa pagina**](../authentication-credentials-uac-and-efs/#uac)**.**

### Impersonificazione delle credenziali utente

Se hai le **credenziali valide di un altro utente**, puoi **creare** una **nuova sessione di accesso** con tali credenziali:
```
runas /user:domain\username cmd.exe
```
Il **token di accesso** ha anche un **riferimento** delle sessioni di accesso all'interno di **LSASS**, questo è utile se il processo ha bisogno di accedere ad alcuni oggetti della rete.\
È possibile avviare un processo che **utilizza credenziali diverse per accedere ai servizi di rete** utilizzando:
```
runas /user:domain\username /netonly cmd.exe
```
Questo è utile se si dispongono di credenziali utili per accedere agli oggetti nella rete ma tali credenziali non sono valide all'interno dell'host attuale in quanto verranno utilizzate solo nella rete (nell'host attuale verranno utilizzati i privilegi dell'utente corrente).

### Tipi di token

Ci sono due tipi di token disponibili:

* **Token primario**: Serve come rappresentazione delle credenziali di sicurezza di un processo. La creazione e l'associazione di token primari con i processi sono azioni che richiedono privilegi elevati, sottolineando il principio della separazione dei privilegi. Tipicamente, un servizio di autenticazione è responsabile della creazione del token, mentre un servizio di accesso gestisce la sua associazione con la shell del sistema operativo dell'utente. È importante notare che i processi ereditano il token primario del processo genitore alla creazione.
* **Token di impersonificazione**: Permette a un'applicazione server di adottare temporaneamente l'identità del client per accedere agli oggetti sicuri. Questo meccanismo è stratificato in quattro livelli di funzionamento:
  * **Anonimo**: Concede all'applicazione server l'accesso simile a quello di un utente non identificato.
  * **Identificazione**: Consente al server di verificare l'identità del client senza utilizzarla per l'accesso agli oggetti.
  * **Impersonificazione**: Consente al server di operare con l'identità del client.
  * **Delega**: Simile all'Impersonificazione ma include la capacità di estendere questa assunzione di identità a sistemi remoti con cui il server interagisce, garantendo la conservazione delle credenziali.

#### Impersonare Token

Utilizzando il modulo _**incognito**_ di metasploit, se si dispone di sufficienti privilegi, è possibile **elencare** e **impersonare** altri **token**. Questo potrebbe essere utile per eseguire **azioni come se si fosse l'altro utente**. È anche possibile **escalare i privilegi** con questa tecnica.

### Privilegi dei Token

Scopri quali **privilegi dei token possono essere abusati per l'escalation dei privilegi:**

{% content-ref url="privilege-escalation-abusing-tokens.md" %}
[privilege-escalation-abusing-tokens.md](privilege-escalation-abusing-tokens.md)
{% endcontent-ref %}

Dai un'occhiata a [**tutti i possibili privilegi dei token e alcune definizioni su questa pagina esterna**](https://github.com/gtworek/Priv2Admin).

## Riferimenti

Per saperne di più sui token in questi tutorial: [https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa) e [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)


## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) è un motore di ricerca alimentato dal **dark web** che offre funzionalità **gratuite** per verificare se un'azienda o i suoi clienti sono stati **compromessi** da **malware ruba-informazioni**.

L'obiettivo principale di WhiteIntel è combattere le violazioni degli account e gli attacchi ransomware derivanti da malware che rubano informazioni.

Puoi visitare il loro sito web e provare il loro motore **gratuitamente** su:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata in HackTricks**? o vuoi avere accesso all'**ultima versione del PEASS o scaricare HackTricks in PDF**? Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **e al** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
