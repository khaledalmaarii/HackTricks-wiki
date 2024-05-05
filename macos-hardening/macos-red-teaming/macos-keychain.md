# Portachiavi macOS

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) è un motore di ricerca alimentato dal **dark web** che offre funzionalità **gratuite** per verificare se un'azienda o i suoi clienti sono stati **compromessi** da **malware ruba-informazioni**.

Il loro obiettivo principale è combattere le violazioni degli account e gli attacchi ransomware derivanti da malware che ruba informazioni.

Puoi visitare il loro sito web e provare il loro motore **gratuitamente** su:

{% embed url="https://whiteintel.io" %}

***

## Principali Portachiavi

* Il **Portachiavi Utente** (`~/Library/Keychains/login.keycahin-db`), che viene utilizzato per memorizzare **credenziali specifiche dell'utente** come password delle applicazioni, password Internet, certificati generati dall'utente, password di rete e chiavi pubbliche/private generate dall'utente.
* Il **Portachiavi di Sistema** (`/Library/Keychains/System.keychain`), che memorizza **credenziali a livello di sistema** come password WiFi, certificati radice di sistema, chiavi private di sistema e password delle applicazioni di sistema.

### Accesso al Portachiavi delle Password

Questi file, sebbene non abbiano protezione intrinseca e possano essere **scaricati**, sono crittografati e richiedono la **password in chiaro dell'utente per essere decifrati**. Uno strumento come [**Chainbreaker**](https://github.com/n0fate/chainbreaker) potrebbe essere utilizzato per la decrittazione.

## Protezioni delle Voci del Portachiavi

### ACLs

Ogni voce nel portachiavi è regolata da **Liste di Controllo degli Accessi (ACL)** che indicano chi può eseguire varie azioni sulla voce del portachiavi, tra cui:

* **ACLAuhtorizationExportClear**: Consente al titolare di ottenere il testo in chiaro del segreto.
* **ACLAuhtorizationExportWrapped**: Consente al titolare di ottenere il testo in chiaro criptato con un'altra password fornita.
* **ACLAuhtorizationAny**: Consente al titolare di eseguire qualsiasi azione.

Le ACL sono ulteriormente accompagnate da un **elenco di applicazioni attendibili** che possono eseguire queste azioni senza richiesta. Questo potrebbe essere:

* **N`il`** (nessuna autorizzazione richiesta, **tutti sono attendibili**)
* Un **elenco vuoto** (nessuno è attendibile)
* **Elenco** di **applicazioni specifiche**.

Inoltre, la voce potrebbe contenere la chiave **`ACLAuthorizationPartitionID`,** che viene utilizzata per identificare il **teamid, apple,** e **cdhash.**

* Se il **teamid** è specificato, allora per **accedere al valore della voce** senza un **prompt** l'applicazione utilizzata deve avere lo **stesso teamid**.
* Se l'**apple** è specificato, allora l'app deve essere **firmata** da **Apple**.
* Se il **cdhash** è indicato, allora l'app deve avere il **cdhash** specifico.

### Creazione di una Voce nel Portachiavi

Quando viene creata una **nuova** **voce** utilizzando **`Keychain Access.app`**, si applicano le seguenti regole:

* Tutte le app possono crittografare.
* **Nessuna app** può esportare/decrittografare (senza richiedere all'utente).
* Tutte le app possono vedere il controllo di integrità.
* Nessuna app può modificare le ACL.
* Il **partitionID** è impostato su **`apple`**.

Quando un'applicazione crea una voce nel portachiavi, le regole sono leggermente diverse:

* Tutte le app possono crittografare.
* Solo l'applicazione che crea (o qualsiasi altra app esplicitamente aggiunta) può esportare/decrittografare (senza richiedere all'utente).
* Tutte le app possono vedere il controllo di integrità.
* Nessuna app può modificare le ACL.
* Il **partitionID** è impostato su **`teamid:[teamID qui]`**.

## Accesso al Portachiavi

### `security`
```bash
# Dump all metadata and decrypted secrets (a lot of pop-ups)
security dump-keychain -a -d

# Find generic password for the "Slack" account and print the secrets
security find-generic-password -a "Slack" -g

# Change the specified entrys PartitionID entry
security set-generic-password-parition-list -s "test service" -a "test acount" -S
```
### API

{% hint style="success" %}
L'**enumerazione e il dumping del portachiavi** dei segreti che **non genereranno un prompt** possono essere fatti con lo strumento [**LockSmith**](https://github.com/its-a-feature/LockSmith)
{% endhint %}

Elenca e ottieni **informazioni** su ciascuna voce del portachiavi:

* L'API **`SecItemCopyMatching`** fornisce informazioni su ciascuna voce e ci sono alcuni attributi che è possibile impostare quando la si utilizza:
* **`kSecReturnData`**: Se è vero, cercherà di decifrare i dati (impostare su falso per evitare potenziali popup)
* **`kSecReturnRef`**: Ottieni anche il riferimento all'elemento del portachiavi (impostare su vero nel caso in cui successivamente si possa decifrare senza popup)
* **`kSecReturnAttributes`**: Ottieni metadati sulle voci
* **`kSecMatchLimit`**: Quanti risultati restituire
* **`kSecClass`**: Che tipo di voce del portachiavi

Ottieni **ACL** di ciascuna voce:

* Con l'API **`SecAccessCopyACLList`** è possibile ottenere l'**ACL per l'elemento del portachiavi**, e restituirà un elenco di ACL (come `ACLAuhtorizationExportClear` e gli altri precedentemente menzionati) dove ciascun elenco ha:
* Descrizione
* **Elenco delle applicazioni attendibili**. Questo potrebbe essere:
* Un'applicazione: /Applications/Slack.app
* Un binario: /usr/libexec/airportd
* Un gruppo: group://AirPort

Esporta i dati:

* L'API **`SecKeychainItemCopyContent`** ottiene il testo in chiaro
* L'API **`SecItemExport`** esporta le chiavi e i certificati ma potrebbe essere necessario impostare le password per esportare il contenuto criptato

E questi sono i **requisiti** per poter **esportare un segreto senza un prompt**:

* Se sono elencate **1 o più app attendibili**:
* È necessario avere le appropriate **autorizzazioni** (**`Nil`**, o far **parte** dell'elenco consentito di app nell'autorizzazione per accedere alle informazioni segrete)
* È necessario che la firma del codice corrisponda a **PartitionID**
* È necessario che la firma del codice corrisponda a quella di un'app **attendibile** (o far parte del giusto KeychainAccessGroup)
* Se **tutte le applicazioni sono attendibili**:
* È necessario avere le appropriate **autorizzazioni**
* È necessario che la firma del codice corrisponda a **PartitionID**
* Se non c'è **PartitionID**, allora questo non è necessario

{% hint style="danger" %}
Pertanto, se è elencata **1 applicazione**, è necessario **iniettare codice in quell'applicazione**.

Se **apple** è indicato in **partitionID**, potresti accedervi con **`osascript`** quindi a tutto ciò che si fida di tutte le applicazioni con apple nel partitionID. **`Python`** potrebbe anche essere utilizzato per questo.
{% endhint %}

### Due attributi aggiuntivi

* **Invisibile**: È un flag booleano per **nascondere** la voce dall'app **UI** del portachiavi
* **Generale**: Serve per memorizzare **metadati** (quindi NON È CIFRATO)
* Microsoft stava memorizzando in testo normale tutti i token di aggiornamento per accedere ai punti di accesso sensibili.

## Riferimenti

* [**#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas**](https://www.youtube.com/watch?v=jKE1ZW33JpY)

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) è un motore di ricerca alimentato dal **dark web** che offre funzionalità **gratuite** per verificare se un'azienda o i suoi clienti sono stati **compromessi** da **malware ruba-informazioni**.

Il loro obiettivo principale è contrastare le violazioni degli account e gli attacchi ransomware derivanti da malware che rubano informazioni.

Puoi visitare il loro sito web e provare il loro motore **gratuitamente** su:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se desideri vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusivi [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
