# ACLs - DACLs/SACLs/ACEs

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=acls-dacls-sacls-aces) per costruire e **automatizzare flussi di lavoro** alimentati dagli **strumenti comunitari più avanzati** al mondo.\
Ottieni accesso oggi:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=acls-dacls-sacls-aces" %}

{% hint style="success" %}
Impara e pratica AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>
{% endhint %}

## **Access Control List (ACL)**

Un'Access Control List (ACL) consiste in un insieme ordinato di Access Control Entries (ACEs) che dettano le protezioni per un oggetto e le sue proprietà. In sostanza, un'ACL definisce quali azioni da parte di quali principi di sicurezza (utenti o gruppi) sono permesse o negate su un dato oggetto.

Ci sono due tipi di ACL:

* **Discretionary Access Control List (DACL):** Specifica quali utenti e gruppi hanno o non hanno accesso a un oggetto.
* **System Access Control List (SACL):** Regola l'audit dei tentativi di accesso a un oggetto.

Il processo di accesso a un file comporta che il sistema controlli il descrittore di sicurezza dell'oggetto rispetto al token di accesso dell'utente per determinare se l'accesso debba essere concesso e l'estensione di tale accesso, basato sulle ACEs.

### **Componenti Chiave**

* **DACL:** Contiene ACEs che concedono o negano permessi di accesso a utenti e gruppi per un oggetto. È essenzialmente l'ACL principale che detta i diritti di accesso.
* **SACL:** Utilizzato per l'audit degli accessi agli oggetti, dove le ACEs definiscono i tipi di accesso da registrare nel Security Event Log. Questo può essere inestimabile per rilevare tentativi di accesso non autorizzati o per risolvere problemi di accesso.

### **Interazione del Sistema con le ACLs**

Ogni sessione utente è associata a un token di accesso che contiene informazioni di sicurezza rilevanti per quella sessione, inclusi identità utente, di gruppo e privilegi. Questo token include anche un SID di accesso che identifica univocamente la sessione.

L'Autorità di Sicurezza Locale (LSASS) elabora le richieste di accesso agli oggetti esaminando la DACL per le ACEs che corrispondono al principio di sicurezza che tenta di accedere. L'accesso viene immediatamente concesso se non vengono trovate ACEs rilevanti. Altrimenti, LSASS confronta le ACEs con il SID del principio di sicurezza nel token di accesso per determinare l'idoneità all'accesso.

### **Processo Riassunto**

* **ACLs:** Definiscono i permessi di accesso attraverso DACLs e le regole di audit attraverso SACLs.
* **Access Token:** Contiene informazioni su utenti, gruppi e privilegi per una sessione.
* **Decisione di Accesso:** Fatta confrontando le ACEs della DACL con il token di accesso; le SACLs sono utilizzate per l'audit.

### ACEs

Ci sono **tre principali tipi di Access Control Entries (ACEs)**:

* **Access Denied ACE**: Questa ACE nega esplicitamente l'accesso a un oggetto per utenti o gruppi specificati (in una DACL).
* **Access Allowed ACE**: Questa ACE concede esplicitamente l'accesso a un oggetto per utenti o gruppi specificati (in una DACL).
* **System Audit ACE**: Posizionata all'interno di una System Access Control List (SACL), questa ACE è responsabile della generazione di log di audit in caso di tentativi di accesso a un oggetto da parte di utenti o gruppi. Documenta se l'accesso è stato consentito o negato e la natura dell'accesso.

Ogni ACE ha **quattro componenti critiche**:

1. Il **Security Identifier (SID)** dell'utente o del gruppo (o il loro nome principale in una rappresentazione grafica).
2. Un **flag** che identifica il tipo di ACE (accesso negato, consentito o audit di sistema).
3. **Flags di ereditarietà** che determinano se gli oggetti figli possono ereditare l'ACE dal loro genitore.
4. Un [**access mask**](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN), un valore a 32 bit che specifica i diritti concessi all'oggetto.

La determinazione dell'accesso viene condotta esaminando sequenzialmente ogni ACE fino a:

* Un **Access-Denied ACE** nega esplicitamente i diritti richiesti a un fiduciario identificato nel token di accesso.
* **Access-Allowed ACE(s)** concedono esplicitamente tutti i diritti richiesti a un fiduciario nel token di accesso.
* Dopo aver controllato tutte le ACEs, se qualche diritto richiesto **non è stato esplicitamente consentito**, l'accesso è implicitamente **negato**.

### Ordine delle ACEs

Il modo in cui le **ACEs** (regole che dicono chi può o non può accedere a qualcosa) sono messe in una lista chiamata **DACL** è molto importante. Questo perché una volta che il sistema concede o nega l'accesso in base a queste regole, smette di guardare il resto.

C'è un modo migliore per organizzare queste ACEs, e si chiama **"ordine canonico."** Questo metodo aiuta a garantire che tutto funzioni senza intoppi e in modo equo. Ecco come funziona per sistemi come **Windows 2000** e **Windows Server 2003**:

* Prima, metti tutte le regole fatte **specificamente per questo elemento** prima di quelle che provengono da altrove, come una cartella genitore.
* In quelle regole specifiche, metti quelle che dicono **"no" (nega)** prima di quelle che dicono **"sì" (consenti)**.
* Per le regole che provengono da altrove, inizia con quelle della **fonte più vicina**, come il genitore, e poi torna indietro. Ancora, metti **"no"** prima di **"sì."**

Questa configurazione aiuta in due modi principali:

* Garantisce che se c'è un **"no"** specifico, venga rispettato, indipendentemente da quali altre regole **"sì"** ci siano.
* Permette al proprietario di un elemento di avere l'**ultima parola** su chi può entrare, prima che entrino in gioco eventuali regole da cartelle genitore o più lontane.

Facendo le cose in questo modo, il proprietario di un file o di una cartella può essere molto preciso su chi ottiene accesso, assicurandosi che le persone giuste possano entrare e quelle sbagliate no.

![](https://www.ntfs.com/images/screenshots/ACEs.gif)

Quindi, questo **"ordine canonico"** riguarda tutto il garantire che le regole di accesso siano chiare e funzionino bene, mettendo prima le regole specifiche e organizzando tutto in modo intelligente.

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) per costruire e **automatizzare flussi di lavoro** alimentati dagli **strumenti comunitari più avanzati** al mondo.\
Ottieni accesso oggi:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### Esempio GUI

[**Esempio da qui**](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)

Questa è la classica scheda di sicurezza di una cartella che mostra l'ACL, DACL e ACEs:

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../.gitbook/assets/classicsectab.jpg)

Se clicchiamo sul **pulsante Avanzate** otterremo più opzioni come l'ereditarietà:

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../.gitbook/assets/aceinheritance.jpg)

E se aggiungi o modifichi un Principale di Sicurezza:

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../.gitbook/assets/editseprincipalpointers1.jpg)

E infine abbiamo la SACL nella scheda di Audit:

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../.gitbook/assets/audit-tab.jpg)

### Spiegare il Controllo degli Accessi in Modo Semplificato

Quando gestiamo l'accesso alle risorse, come una cartella, utilizziamo liste e regole note come Access Control Lists (ACLs) e Access Control Entries (ACEs). Queste definiscono chi può o non può accedere a determinati dati.

#### Negare l'Accesso a un Gruppo Specifico

Immagina di avere una cartella chiamata Cost, e vuoi che tutti possano accedervi tranne il team di marketing. Impostando correttamente le regole, possiamo assicurarci che al team di marketing venga esplicitamente negato l'accesso prima di consentire a tutti gli altri. Questo viene fatto posizionando la regola per negare l'accesso al team di marketing prima della regola che consente l'accesso a tutti.

#### Consentire l'Accesso a un Membro Specifico di un Gruppo Negato

Supponiamo che Bob, il direttore marketing, abbia bisogno di accesso alla cartella Cost, anche se il team di marketing in generale non dovrebbe avere accesso. Possiamo aggiungere una regola specifica (ACE) per Bob che gli concede l'accesso, e posizionarla prima della regola che nega l'accesso al team di marketing. In questo modo, Bob ottiene accesso nonostante la restrizione generale sul suo team.

#### Comprendere le Access Control Entries

Le ACEs sono le singole regole in un'ACL. Identificano utenti o gruppi, specificano quali accessi sono consentiti o negati e determinano come queste regole si applicano agli elementi secondari (ereditarietà). Ci sono due principali tipi di ACEs:

* **Generic ACEs**: Queste si applicano in modo ampio, influenzando tutti i tipi di oggetti o distinguendo solo tra contenitori (come cartelle) e non contenitori (come file). Ad esempio, una regola che consente agli utenti di vedere il contenuto di una cartella ma non di accedere ai file al suo interno.
* **Object-Specific ACEs**: Queste forniscono un controllo più preciso, consentendo di impostare regole per tipi specifici di oggetti o persino per singole proprietà all'interno di un oggetto. Ad esempio, in una directory di utenti, una regola potrebbe consentire a un utente di aggiornare il proprio numero di telefono ma non le proprie ore di accesso.

Ogni ACE contiene informazioni importanti come a chi si applica la regola (utilizzando un Security Identifier o SID), cosa consente o nega la regola (utilizzando un access mask) e come viene ereditata da altri oggetti.

#### Differenze Chiave Tra i Tipi di ACE

* **Generic ACEs** sono adatte per scenari di controllo accessi semplici, dove la stessa regola si applica a tutti gli aspetti di un oggetto o a tutti gli oggetti all'interno di un contenitore.
* **Object-Specific ACEs** sono utilizzate per scenari più complessi, specialmente in ambienti come Active Directory, dove potrebbe essere necessario controllare l'accesso a proprietà specifiche di un oggetto in modo diverso.

In sintesi, le ACLs e le ACEs aiutano a definire controlli di accesso precisi, assicurando che solo le giuste persone o gruppi abbiano accesso a informazioni o risorse sensibili, con la possibilità di personalizzare i diritti di accesso fino al livello delle singole proprietà o tipi di oggetti.

### Layout delle Access Control Entry

| Campo ACE   | Descrizione                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Tipo        | Flag che indica il tipo di ACE. Windows 2000 e Windows Server 2003 supportano sei tipi di ACE: Tre tipi di ACE generici che sono attaccati a tutti gli oggetti sicuri. Tre tipi di ACE specifici per oggetti che possono verificarsi per oggetti di Active Directory.                                                                                                                                                                                                                                                            |
| Flags       | Set di flag bit che controllano l'ereditarietà e l'audit.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Dimensione  | Numero di byte di memoria allocati per l'ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Access mask | Valore a 32 bit i cui bit corrispondono ai diritti di accesso per l'oggetto. I bit possono essere impostati accesi o spenti, ma il significato dell'impostazione dipende dal tipo di ACE. Ad esempio, se il bit che corrisponde al diritto di leggere i permessi è attivato, e il tipo di ACE è Nega, l'ACE nega il diritto di leggere i permessi dell'oggetto. Se lo stesso bit è attivato ma il tipo di ACE è Consenti, l'ACE concede il diritto di leggere i permessi dell'oggetto. Maggiori dettagli sull'Access mask appaiono nella tabella successiva. |
| SID         | Identifica un utente o un gruppo il cui accesso è controllato o monitorato da questo ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Layout dell'Access Mask

| Bit (Intervallo) | Significato                            | Descrizione/Esempio                       |
| ---------------- | -------------------------------------- | ----------------------------------------- |
| 0 - 15           | Diritti di Accesso Specifici per Oggetto      | Leggi dati, Esegui, Aggiungi dati           |
| 16 - 22          | Diritti di Accesso Standard             | Elimina, Scrivi ACL, Scrivi Proprietario            |
| 23               | Può accedere alla security ACL            |                                           |
| 24 - 27          | Riservato                           |                                           |
| 28               | Generico TUTTI (Leggi, Scrivi, Esegui) | Tutto ciò che segue                          |
| 29               | Generico Esegui                    | Tutte le cose necessarie per eseguire un programma |
| 30               | Generico Scrivi                      | Tutte le cose necessarie per scrivere in un file   |
| 31               | Generico Leggi                       | Tutte le cose necessarie per leggere un file       |

## Riferimenti

* [https://www.ntfs.com/ntfs-permissions-acl-use.htm](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
* [https://secureidentity.se/acl-dacl-sacl-and-the-ace/](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)
* [https://www.coopware.in2.info/_ntfsacl_ht.htm](https://www.coopware.in2.info/_ntfsacl_ht.htm)

{% hint style="success" %}
Impara e pratica AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=acls-dacls-sacls-aces) per costruire e **automatizzare flussi di lavoro** alimentati dagli **strumenti comunitari più avanzati** al mondo.\
Ottieni accesso oggi:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=acls-dacls-sacls-aces" %}
