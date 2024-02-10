# ACLs - DACLs/SACLs/ACEs

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilizza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) per creare e automatizzare facilmente flussi di lavoro supportati dagli strumenti della community più avanzati al mondo.\
Ottieni l'accesso oggi stesso:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## **Access Control List (ACL)**

Una Access Control List (ACL) consiste in un insieme ordinato di Access Control Entries (ACE) che indicano le protezioni per un oggetto e le sue proprietà. In sostanza, una ACL definisce quali azioni da parte di quali principali di sicurezza (utenti o gruppi) sono consentite o negate su un determinato oggetto.

Ci sono due tipi di ACL:

- **Discretionary Access Control List (DACL):** Specifica quali utenti e gruppi hanno o non hanno accesso a un oggetto.
- **System Access Control List (SACL):** Regola l'audit dei tentativi di accesso a un oggetto.

Il processo di accesso a un file prevede che il sistema verifichi il descrittore di sicurezza dell'oggetto rispetto al token di accesso dell'utente per determinare se l'accesso deve essere concesso e l'estensione di tale accesso, in base agli ACE.

### **Componenti chiave**

- **DACL:** Contiene ACE che concedono o negano le autorizzazioni di accesso agli utenti e ai gruppi per un oggetto. È essenzialmente la principale ACL che determina i diritti di accesso.

- **SACL:** Utilizzato per l'audit dell'accesso agli oggetti, dove gli ACE definiscono i tipi di accesso da registrare nel Registro eventi di sicurezza. Questo può essere prezioso per rilevare tentativi di accesso non autorizzati o risolvere problemi di accesso.

### **Interazione del sistema con le ACL**

Ogni sessione utente è associata a un token di accesso che contiene informazioni di sicurezza pertinenti a quella sessione, inclusi utente, identità di gruppo e privilegi. Questo token include anche un SID di accesso che identifica in modo univoco la sessione.

L'Autorità di sicurezza locale (LSASS) elabora le richieste di accesso agli oggetti esaminando il DACL per ACE che corrispondono al principale di sicurezza che tenta l'accesso. L'accesso viene immediatamente concesso se non vengono trovati ACE rilevanti. In caso contrario, LSASS confronta gli ACE con il SID del principale di sicurezza nel token di accesso per determinare l'ammissibilità all'accesso.

### **Processo riassunto**

- **ACL:** Definisce le autorizzazioni di accesso tramite DACL e le regole di audit tramite SACL.
- **Token di accesso:** Contiene informazioni utente, di gruppo e di privilegio per una sessione.
- **Decisione di accesso:** Effettuata confrontando gli ACE del DACL con il token di accesso; i SACL vengono utilizzati per l'audit.


### ACEs

Ci sono **tre tipi principali di Access Control Entries (ACEs)**:

- **Access Denied ACE**: Questo ACE nega esplicitamente l'accesso a un oggetto per utenti o gruppi specificati (in un DACL).
- **Access Allowed ACE**: Questo ACE concede esplicitamente l'accesso a un oggetto per utenti o gruppi specificati (in un DACL).
- **System Audit ACE**: Posizionato all'interno di una System Access Control List (SACL), questo ACE è responsabile della generazione di log di audit durante i tentativi di accesso a un oggetto da parte di utenti o gruppi. Documenta se l'accesso è stato consentito o negato e la natura dell'accesso.

Ogni ACE ha **quattro componenti fondamentali**:

1. L'**Identificatore di sicurezza (SID)** dell'utente o del gruppo (o il loro nome principale in una rappresentazione grafica).
2. Un **flag** che identifica il tipo di ACE (accesso negato, consentito o audit di sistema).
3. **Flag di ereditarietà** che determinano se gli oggetti figlio possono ereditare l'ACE dal loro genitore.
4. Una **[maschera di accesso](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN)**, un valore a 32 bit che specifica i diritti concessi all'oggetto.

La determinazione dell'accesso viene effettuata esaminando sequenzialmente ciascun ACE fino a quando:

- Un **Access-Denied ACE** nega esplicitamente i diritti richiesti a un trustee identificato nel token di accesso.
- **Access-Allowed ACE(s)** concedono esplicitamente tutti i diritti richiesti a un trustee nel token di accesso.
- Dopo aver controllato tutti gli ACE, se un qualsiasi diritto richiesto non è stato esplicitamente consentito, l'accesso viene implicitamente **negato**.


### Ordine degli ACEs

Il modo in cui gli **ACEs** (regole che indicano chi può o non può accedere a qualcosa) vengono inseriti in una lista chiamata **DACL** è molto importante. Questo perché una volta che il sistema concede o nega l'accesso in base a queste regole, smette di guardare il resto.

Esiste un modo migliore per organizzare questi ACEs, ed è chiamato **"ordine canonico"**. Questo metodo aiuta a garantire che tutto funzioni in modo fluido ed equo. Ecco come funziona per sistemi come **Windows 2000** e **Windows Server 2003**:

- Prima di tutto, metti tutte le regole che sono fatte **specificamente per questo elemento** prima di quelle che provengono da un'altra parte, come una cartella genitore.
- In quelle regole specifiche, metti prima quelle che dicono **"no" (deny)** prima di quelle che dicono **"sì" (allow)**.
- Per le regole che provengono da un'altra parte, inizia con quelle della **fonte più vicina**, come il genitore, e poi vai indietro da lì. Di nuovo, metti **"no"** prima di **"sì".**

Questa configurazione aiuta in due modi importanti:

* Assicura che se c'è un **"no"** specifico, venga rispettato, indipendentemente da altre regole **"sì"** presenti.
* Permette al proprietario di un elemento di avere l'**ultima parola** su chi può accedere, prima che entrino in gioco eventuali regole delle cartelle genitore o più indietro.

Facendo in questo modo, il proprietario di un file o di una cartella può essere molto preciso su chi ottiene l'accesso, assicurandosi che le persone giuste possano entrare e quelle sbagliate no.

![](https://www.ntfs.com/images/screenshots/ACEs.gif)

Quindi, questo **"ordine canonico"** riguarda il fatto di assicurarsi che le regole di accesso siano chiare e funzionino
### Esempio GUI

**[Esempio da qui](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)**

Questa è la scheda di sicurezza classica di una cartella che mostra ACL, DACL e ACE:

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../.gitbook/assets/classicsectab.jpg)

Se facciamo clic sul **pulsante Avanzate**, otterremo più opzioni come l'ereditarietà:

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../.gitbook/assets/aceinheritance.jpg)

E se aggiungi o modifichi un Principale di sicurezza:

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../.gitbook/assets/editseprincipalpointers1.jpg)

E infine abbiamo il SACL nella scheda Audit:

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../.gitbook/assets/audit-tab.jpg)

### Spiegazione semplificata del controllo degli accessi

Nella gestione dell'accesso alle risorse, come una cartella, utilizziamo liste e regole note come Access Control List (ACL) e Access Control Entry (ACE). Queste definiscono chi può o non può accedere a determinati dati.

#### Negare l'accesso a un gruppo specifico

Immagina di avere una cartella chiamata Cost e vuoi che tutti vi accedano tranne il team di marketing. Impostando correttamente le regole, possiamo garantire che il team di marketing sia esplicitamente negato l'accesso prima di consentire a tutti gli altri. Ciò viene fatto posizionando la regola per negare l'accesso al team di marketing prima della regola che consente l'accesso a tutti.

#### Consentire l'accesso a un membro specifico di un gruppo negato

Supponiamo che Bob, il direttore marketing, abbia bisogno di accedere alla cartella Cost, anche se in generale il team di marketing non dovrebbe avere accesso. Possiamo aggiungere una regola specifica (ACE) per Bob che gli concede l'accesso e posizionarla prima della regola che nega l'accesso al team di marketing. In questo modo, Bob ottiene l'accesso nonostante la restrizione generale sul suo team.

#### Comprensione delle voci di controllo degli accessi

Le ACE sono le regole individuali in un ACL. Identificano utenti o gruppi, specificano quali accessi sono consentiti o negati e determinano come queste regole si applicano agli elementi secondari (ereditarietà). Ci sono due tipi principali di ACE:

- **ACE generiche**: si applicano ampiamente, influenzando tutti i tipi di oggetti o distinguendo solo tra contenitori (come cartelle) e non contenitori (come file). Ad esempio, una regola che consente agli utenti di visualizzare il contenuto di una cartella ma non di accedere ai file al suo interno.

- **ACE specifiche dell'oggetto**: forniscono un controllo più preciso, consentendo di impostare regole per tipi specifici di oggetti o addirittura proprietà individuali all'interno di un oggetto. Ad esempio, in una directory di utenti, una regola potrebbe consentire a un utente di aggiornare il proprio numero di telefono ma non le ore di accesso.

Ogni ACE contiene informazioni importanti come a chi si applica la regola (utilizzando un identificatore di sicurezza o SID), cosa consente o nega la regola (utilizzando una maschera di accesso) e come viene ereditata dagli altri oggetti.

#### Differenze chiave tra i tipi di ACE

- Le **ACE generiche** sono adatte per scenari di controllo degli accessi semplici, in cui la stessa regola si applica a tutti gli aspetti di un oggetto o a tutti gli oggetti all'interno di un contenitore.

- Le **ACE specifiche dell'oggetto** vengono utilizzate per scenari più complessi, specialmente in ambienti come Active Directory, in cui potrebbe essere necessario controllare l'accesso a proprietà specifiche di un oggetto in modo diverso.

In sintesi, ACL e ACE aiutano a definire controlli di accesso precisi, garantendo che solo le persone o i gruppi giusti abbiano accesso a informazioni o risorse sensibili, con la possibilità di personalizzare i diritti di accesso fino al livello di proprietà individuali o tipi di oggetti.

### Layout dell'Access Control Entry

| Campo ACE   | Descrizione                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Tipo        | Flag che indica il tipo di ACE. Windows 2000 e Windows Server 2003 supportano sei tipi di ACE: tre tipi di ACE generiche che sono collegati a tutti gli oggetti securizzabili e tre tipi di ACE specifiche dell'oggetto che possono verificarsi per gli oggetti di Active Directory.                                                                                                                                                                                                                                                            |
| Flag        | Insieme di bit che controllano l'ereditarietà e l'auditing.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Dimensione   | Numero di byte di memoria allocati per l'ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Maschera di accesso | Valore a 32 bit i cui bit corrispondono ai diritti di accesso per l'oggetto. I bit possono essere impostati su on o off, ma il significato dell'impostazione dipende dal tipo di ACE. Ad esempio, se il bit corrispondente al diritto di leggere le autorizzazioni è acceso e il tipo di ACE è Deny, l'ACE nega il diritto di leggere le autorizzazioni dell'oggetto. Se lo stesso bit è impostato su on ma il tipo di ACE è Allow, l'ACE concede il diritto di leggere le autorizzazioni dell'oggetto. Ulteriori dettagli sulla maschera di accesso compaiono nella tabella successiva. |
| SID         | Identifica un utente o un gruppo il cui accesso è controllato o monitorato da questo ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Layout della maschera di accesso

| Bit (Intervallo) | Significato                            | Descrizione/Esempio                       |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | Diritti di accesso specifici dell'oggetto      | Leggi dati, Esegui, Aggiungi dati           |
| 16 - 22     | Diritti di accesso standard             | Elimina, Scrivi ACL, Scrivi proprietario            |
| 23          | Può accedere all'ACL di sicurezza            |                                           |
| 24 - 27     | Riservato                           |                                           |
| 28          | Generico TUTTO (Leggi, Scrivi, Esegui) | Tutto ciò che segue                          |
| 29          | Esegui generico                    | Tutto ciò che è necessario per eseguire un programma |
| 30          | Scrivi generico                      | Tutto ciò che è necessario per scrivere su un file   |
| 31          | Leggi generico                       | Tutto ciò che è necessario per leggere un file       |

## Riferimenti

* [https://www.ntfs.com/ntfs-permissions-acl-use.htm](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
* [https://secureidentity.se/acl-dacl-sacl-and-the-ace/](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)
* [https://www.coopware.in2.info/_ntfsacl_ht.htm](https://www.coopware.in2.info/_ntfsacl_ht.htm)

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/h
