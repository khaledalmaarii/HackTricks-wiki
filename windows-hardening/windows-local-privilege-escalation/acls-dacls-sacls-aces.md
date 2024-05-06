# ACLs - DACLs/SACLs/ACEs

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=acls-dacls-sacls-aces) per creare e **automatizzare facilmente flussi di lavoro** supportati dagli strumenti della comunità più avanzati al mondo.\
Ottieni l'accesso oggi:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=acls-dacls-sacls-aces" %}

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione esclusiva di [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## **Lista di controllo degli accessi (ACL)**

Una Lista di Controllo degli Accessi (ACL) consiste in un insieme ordinato di Voci di Controllo degli Accessi (ACE) che determinano le protezioni per un oggetto e le sue proprietà. In sostanza, un ACL definisce quali azioni da quali principali della sicurezza (utenti o gruppi) sono permesse o negate su un determinato oggetto.

Ci sono due tipi di ACL:

* **Lista di Controllo degli Accessi Discrezionali (DACL):** Specifica quali utenti e gruppi hanno o non hanno accesso a un oggetto.
* **Lista di Controllo degli Accessi di Sistema (SACL):** Regola l'auditing dei tentativi di accesso a un oggetto.

Il processo di accesso a un file coinvolge il sistema che controlla il descrittore di sicurezza dell'oggetto rispetto al token di accesso dell'utente per determinare se l'accesso dovrebbe essere concesso e l'estensione di tale accesso, in base agli ACE.

### **Componenti Chiave**

* **DACL:** Contiene ACE che concedono o negano autorizzazioni di accesso agli utenti e ai gruppi per un oggetto. È essenzialmente la principale ACL che determina i diritti di accesso.
* **SACL:** Utilizzato per l'auditing dell'accesso agli oggetti, dove gli ACE definiscono i tipi di accesso da registrare nel Log degli Eventi di Sicurezza. Questo può essere prezioso per rilevare tentativi di accesso non autorizzati o risolvere problemi di accesso.

### **Interazione del Sistema con le ACL**

Ogni sessione utente è associata a un token di accesso che contiene informazioni di sicurezza rilevanti per quella sessione, inclusi utente, identità di gruppo e privilegi. Questo token include anche un SID di accesso che identifica univocamente la sessione.

L'Autorità di Sicurezza Locale (LSASS) elabora le richieste di accesso agli oggetti esaminando il DACL per ACE che corrispondono al principale della sicurezza che tenta l'accesso. L'accesso viene immediatamente concesso se non vengono trovati ACE rilevanti. Altrimenti, LSASS confronta gli ACE con il SID del principale della sicurezza nel token di accesso per determinare l'ammissibilità dell'accesso.

### **Processo Sintetizzato**

* **ACL:** Definisce le autorizzazioni di accesso tramite DACL e le regole di auditing tramite SACL.
* **Token di Accesso:** Contiene informazioni utente, di gruppo e di privilegio per una sessione.
* **Decisione di Accesso:** Effettuata confrontando gli ACE del DACL con il token di accesso; i SACL vengono utilizzati per l'auditing.

### ACE

Ci sono **tre principali tipi di Voci di Controllo degli Accessi (ACE)**:

* **ACE di Accesso Negato**: Questo ACE nega esplicitamente l'accesso a un oggetto per utenti o gruppi specificati (in un DACL).
* **ACE di Accesso Consentito**: Questo ACE concede esplicitamente l'accesso a un oggetto per utenti o gruppi specificati (in un DACL).
* **ACE di Audit di Sistema**: Posizionato all'interno di una Lista di Controllo degli Accessi di Sistema (SACL), questo ACE è responsabile della generazione di log di audit sui tentativi di accesso a un oggetto da parte di utenti o gruppi. Documenta se l'accesso è stato consentito o negato e la natura dell'accesso.

Ogni ACE ha **quattro componenti critici**:

1. L'**Identificatore di Sicurezza (SID)** dell'utente o del gruppo (o il loro nome principale in una rappresentazione grafica).
2. Un **flag** che identifica il tipo di ACE (accesso negato, consentito o audit di sistema).
3. **Flag di ereditarietà** che determinano se gli oggetti figlio possono ereditare l'ACE dal loro genitore.
4. Una [**maschera di accesso**](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN), un valore a 32 bit che specifica i diritti concessi all'oggetto.

La determinazione dell'accesso avviene esaminando sequenzialmente ciascun ACE fino a quando:

* Un **ACE di Accesso Negato** nega esplicitamente i diritti richiesti a un trustee identificato nel token di accesso.
* Gli **ACE di Accesso Consentito** concedono esplicitamente tutti i diritti richiesti a un trustee nel token di accesso.
* Dopo aver controllato tutti gli ACE, se un qualsiasi diritto richiesto non è stato esplicitamente concesso, l'accesso viene implicitamente **negato**.

### Ordine degli ACE

Il modo in cui gli **ACE** (regole che dicono chi può o non può accedere a qualcosa) sono inseriti in una lista chiamata **DACL** è molto importante. Questo perché una volta che il sistema concede o nega l'accesso in base a queste regole, smette di guardare il resto.

C'è un modo migliore per organizzare questi ACE, ed è chiamato **"ordine canonico."** Questo metodo aiuta a garantire che tutto funzioni in modo fluido ed equo. Ecco come funziona per sistemi come **Windows 2000** e **Windows Server 2003**:

* Prima, metti tutte le regole fatte **specificamente per questo elemento** prima di quelle che provengono da un'altra parte, come una cartella genitore.
* In quelle regole specifiche, metti prima quelle che dicono **"no" (negare)** prima di quelle che dicono **"sì" (consentire)**.
* Per le regole che provengono da un'altra parte, inizia con quelle dalla **fonte più vicina**, come il genitore, e poi torna indietro da lì. Di nuovo, metti **"no"** prima di **"sì."**

Questa configurazione aiuta in due modi importanti:

* Assicura che se c'è un **"no"** specifico, viene rispettato, indipendentemente dalle altre regole del **"sì"** che ci sono.
* Permette al proprietario di un elemento di avere l'**ultima parola** su chi può accedere, prima che entrino in gioco le regole delle cartelle genitore o più indietro.

Facendo in questo modo, il proprietario di un file o di una cartella può essere molto preciso su chi ha accesso, garantendo che le persone giuste possano accedere e quelle sbagliate no.

![](https://www.ntfs.com/images/screenshots/ACEs.gif)

Quindi, questo **"ordine canonico"** riguarda tutto fare in modo che le regole di accesso siano chiare e funzionino bene, mettendo prima le regole specifiche e organizzando tutto in modo intelligente.

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) per creare e **automatizzare facilmente flussi di lavoro** supportati dagli strumenti della comunità più avanzati al mondo.\
Ottieni l'accesso oggi:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
### Esempio GUI

[**Esempio da qui**](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)

Questa è la classica scheda di sicurezza di una cartella che mostra l'ACL, il DACL e gli ACE:

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../.gitbook/assets/classicsectab.jpg)

Se clicchiamo sul **pulsante Avanzate** otterremo più opzioni come l'ereditarietà:

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../.gitbook/assets/aceinheritance.jpg)

E se aggiungi o modifichi un Principale di Sicurezza:

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../.gitbook/assets/editseprincipalpointers1.jpg)

E infine abbiamo il SACL nella scheda Auditing:

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../.gitbook/assets/audit-tab.jpg)

### Spiegazione del Controllo degli Accessi in modo Semplificato

Nel gestire l'accesso alle risorse, come una cartella, utilizziamo liste e regole note come Liste di Controllo degli Accessi (ACL) e Voci di Controllo degli Accessi (ACE). Queste definiscono chi può o non può accedere a determinati dati.

#### Negare l'Accesso a un Gruppo Specifico

Immagina di avere una cartella chiamata Costi e vuoi che tutti vi accedano tranne il team di marketing. Configurando correttamente le regole, possiamo garantire che al team di marketing venga esplicitamente negato l'accesso prima di consentirlo a tutti gli altri. Ciò viene fatto posizionando la regola per negare l'accesso al team di marketing prima della regola che consente l'accesso a tutti.

#### Consentire l'Accesso a un Membro Specifico di un Gruppo Negato

Supponiamo che Bob, il direttore del marketing, abbia bisogno di accedere alla cartella Costi, anche se in generale il team di marketing non dovrebbe avervi accesso. Possiamo aggiungere una regola specifica (ACE) per Bob che gli concede l'accesso e posizionarla prima della regola che nega l'accesso al team di marketing. In questo modo, Bob ottiene l'accesso nonostante la restrizione generale sul suo team.

#### Comprensione delle Voci di Controllo degli Accessi

Le ACE sono le regole individuali in un ACL. Identificano utenti o gruppi, specificano quali accessi sono consentiti o negati e determinano come queste regole si applicano agli elementi secondari (ereditarietà). Ci sono due tipi principali di ACE:

* **ACE Generiche**: Queste si applicano ampiamente, influenzando tutti i tipi di oggetti o distinguendo solo tra contenitori (come cartelle) e non-contenitori (come file). Ad esempio, una regola che consente agli utenti di visualizzare i contenuti di una cartella ma non di accedere ai file al suo interno.
* **ACE Specifiche dell'Oggetto**: Queste forniscono un controllo più preciso, consentendo di impostare regole per tipi specifici di oggetti o addirittura proprietà individuali all'interno di un oggetto. Ad esempio, in una directory di utenti, una regola potrebbe consentire a un utente di aggiornare il proprio numero di telefono ma non le ore di accesso.

Ogni ACE contiene informazioni importanti come a chi si applica la regola (usando un Identificatore di Sicurezza o SID), cosa consente o nega la regola (usando una maschera di accesso) e come viene ereditata da altri oggetti.

#### Principali Differenze tra i Tipi di ACE

* Le **ACE Generiche** sono adatte per scenari di controllo degli accessi semplici, dove la stessa regola si applica a tutti gli aspetti di un oggetto o a tutti gli oggetti all'interno di un contenitore.
* Le **ACE Specifiche dell'Oggetto** sono utilizzate per scenari più complessi, specialmente in ambienti come Active Directory, dove potresti aver bisogno di controllare l'accesso a proprietà specifiche di un oggetto in modo diverso.

In sintesi, ACL e ACE aiutano a definire controlli di accesso precisi, garantendo che solo le persone o i gruppi giusti abbiano accesso a informazioni o risorse sensibili, con la possibilità di personalizzare i diritti di accesso fino al livello di proprietà individuali o tipi di oggetti.

### Layout della Voce di Controllo degli Accessi

| Campo ACE  | Descrizione                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Tipo        | Flag che indica il tipo di ACE. Windows 2000 e Windows Server 2003 supportano sei tipi di ACE: Tre tipi di ACE generiche che sono collegati a tutti gli oggetti securizzabili. Tre tipi di ACE specifiche dell'oggetto che possono verificarsi per gli oggetti di Active Directory.                                                                                                                                                                                                                                                            |
| Flag        | Insieme di bit flag che controllano l'ereditarietà e l'auditing.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Dimensione  | Numero di byte di memoria allocati per l'ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Maschera di accesso | Valore a 32 bit i cui bit corrispondono ai diritti di accesso per l'oggetto. I bit possono essere impostati su on o off, ma il significato dell'impostazione dipende dal tipo di ACE. Ad esempio, se il bit che corrisponde al diritto di leggere le autorizzazioni è attivato e il tipo di ACE è Deny, l'ACE nega il diritto di leggere le autorizzazioni dell'oggetto. Se lo stesso bit è attivato ma il tipo di ACE è Allow, l'ACE concede il diritto di leggere le autorizzazioni dell'oggetto. Ulteriori dettagli sulla Maschera di Accesso appaiono nella tabella successiva. |
| SID         | Identifica un utente o gruppo il cui accesso è controllato o monitorato da questo ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Layout della Maschera di Accesso

| Bit (Intervallo) | Significato                            | Descrizione/Esempio                       |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | Diritti di Accesso Specifici dell'Oggetto      | Leggi dati, Esegui, Aggiungi dati           |
| 16 - 22     | Diritti di Accesso Standard             | Elimina, Scrivi ACL, Scrivi Proprietario            |
| 23          | Può accedere all'ACL di sicurezza            |                                           |
| 24 - 27     | Riservato                           |                                           |
| 28          | Generico TUTTO (Lettura, Scrittura, Esecuzione) | Tutto ciò che segue                          |
| 29          | Esecuzione Generica                    | Tutto ciò che è necessario per eseguire un programma |
| 30          | Scrittura Generica                      | Tutto ciò che è necessario per scrivere su un file   |
| 31          | Lettura Generica                       | Tutto ciò che è necessario per leggere un file       |

## Riferimenti

* [https://www.ntfs.com/ntfs-permissions-acl-use.htm](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
* [https://secureidentity.se/acl-dacl-sacl-and-the-ace/](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)
* [https://www.coopware.in2.info/\_ntfsacl\_ht.htm](https://www.coopware.in2.info/\_ntfsacl\_ht.htm)

<details>

<summary><strong>Impara l'hacking su AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se desideri vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=acls-dacls-sacls-aces) per creare e **automatizzare facilmente flussi di lavoro** supportati dagli strumenti della comunità più avanzati al mondo.\
Ottieni l'Accesso Oggi:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=acls-dacls-sacls-aces" %}
