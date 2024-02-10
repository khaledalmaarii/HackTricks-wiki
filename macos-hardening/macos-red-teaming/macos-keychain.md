# Keychain di macOS

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Keychain Principali

* Il **Keychain Utente** (`~/Library/Keychains/login.keycahin-db`), che viene utilizzato per archiviare le **credenziali specifiche dell'utente** come password delle applicazioni, password di Internet, certificati generati dall'utente, password di rete e chiavi pubbliche/private generate dall'utente.
* Il **Keychain di Sistema** (`/Library/Keychains/System.keychain`), che archivia le **credenziali a livello di sistema** come password WiFi, certificati radice di sistema, chiavi private di sistema e password delle applicazioni di sistema.

### Accesso alle Password del Keychain

Questi file, sebbene non abbiano una protezione intrinseca e possano essere **scaricati**, sono crittografati e richiedono la **password in chiaro dell'utente per essere decifrati**. Uno strumento come [**Chainbreaker**](https://github.com/n0fate/chainbreaker) potrebbe essere utilizzato per la decrittazione.

## Protezioni delle Voci del Keychain

### ACLs

Ogni voce nel keychain è governata da **Access Control Lists (ACLs)** che indicano chi può eseguire varie azioni sulla voce del keychain, tra cui:

* **ACLAuhtorizationExportClear**: Consente al titolare di ottenere il testo in chiaro del segreto.
* **ACLAuhtorizationExportWrapped**: Consente al titolare di ottenere il testo in chiaro criptato con un'altra password fornita.
* **ACLAuhtorizationAny**: Consente al titolare di eseguire qualsiasi azione.

Le ACL sono accompagnate da un **elenco di applicazioni fidate** che possono eseguire queste azioni senza richiesta. Questo potrebbe essere:

* &#x20;**N`il`** (nessuna autorizzazione richiesta, **tutti sono fidati**)
* Un elenco **vuoto** (nessuno è fidato)
* **Elenco** di **applicazioni** specifiche.

Inoltre, la voce potrebbe contenere la chiave **`ACLAuthorizationPartitionID`,** che viene utilizzata per identificare il **teamid, apple** e **cdhash.**

* Se viene specificato il **teamid**, allora per **accedere al valore** della voce **senza** una **richiesta**, l'applicazione utilizzata deve avere lo **stesso teamid**.
* Se viene specificato **apple**, l'app deve essere **firmata** da **Apple**.
* Se viene indicato **cdhash**, allora l'app deve avere il **cdhash** specifico.

### Creazione di una Voce del Keychain

Quando viene creata una **nuova voce** utilizzando **`Keychain Access.app`**, si applicano le seguenti regole:

* Tutte le app possono crittografare.
* **Nessuna app** può esportare/decrittografare (senza richiesta all'utente).
* Tutte le app possono vedere il controllo di integrità.
* Nessuna app può modificare le ACL.
* L'**ID di partizione** è impostato su **`apple`**.

Quando un'applicazione crea una voce nel keychain, le regole sono leggermente diverse:

* Tutte le app possono crittografare.
* Solo l'applicazione di creazione (o qualsiasi altra app esplicitamente aggiunta) può esportare/decrittografare (senza richiesta all'utente).
* Tutte le app possono vedere il controllo di integrità.
* Nessuna app può modificare le ACL.
* L'**ID di partizione** è impostato su **`teamid:[teamID qui]`**.

## Accesso al Keychain

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
L'**enumerazione e il dumping** delle segrete del **portachiavi** che **non generano una richiesta** possono essere effettuati con lo strumento [**LockSmith**](https://github.com/its-a-feature/LockSmith)
{% endhint %}

Elenca e ottieni **informazioni** su ogni voce del portachiavi:

* L'API **`SecItemCopyMatching`** fornisce informazioni su ogni voce e ci sono alcuni attributi che è possibile impostare quando lo si utilizza:
* **`kSecReturnData`**: Se è vero, cercherà di decifrare i dati (impostare su falso per evitare eventuali popup)
* **`kSecReturnRef`**: Ottieni anche il riferimento all'elemento del portachiavi (impostare su vero nel caso in cui successivamente si possa decifrare senza popup)
* **`kSecReturnAttributes`**: Ottieni metadati sulle voci
* **`kSecMatchLimit`**: Quanti risultati restituire
* **`kSecClass`**: Che tipo di voce del portachiavi

Ottieni le **ACL** di ogni voce:

* Con l'API **`SecAccessCopyACLList`** puoi ottenere l'**ACL per l'elemento del portachiavi**, e restituirà una lista di ACL (come `ACLAuhtorizationExportClear` e le altre menzionate in precedenza) in cui ogni lista ha:
* Descrizione
* **Elenco delle applicazioni attendibili**. Questo potrebbe essere:
* Un'app: /Applications/Slack.app
* Un binario: /usr/libexec/airportd
* Un gruppo: group://AirPort

Esporta i dati:

* L'API **`SecKeychainItemCopyContent`** ottiene il testo in chiaro
* L'API **`SecItemExport`** esporta le chiavi e i certificati ma potrebbe essere necessario impostare le password per esportare il contenuto criptato

E questi sono i **requisiti** per poter **esportare una segreta senza una richiesta**:

* Se ci sono **1 o più applicazioni attendibili** elencate:
* È necessario avere le appropriate **autorizzazioni** (**`Nil`**, o far parte dell'elenco consentito di applicazioni nell'autorizzazione per accedere alle informazioni segrete)
* È necessario che la firma del codice corrisponda a **PartitionID**
* È necessario che la firma del codice corrisponda a quella di un'**app attendibile** (o essere un membro del gruppo KeychainAccessGroup corretto)
* Se **tutte le applicazioni sono attendibili**:
* È necessario avere le appropriate **autorizzazioni**
* È necessario che la firma del codice corrisponda a **PartitionID**
* Se **non c'è PartitionID**, allora questo non è necessario

{% hint style="danger" %}
Pertanto, se è indicata **1 applicazione**, è necessario **iniettare il codice in quella applicazione**.

Se **apple** è indicato in **partitionID**, è possibile accedervi con **`osascript`** in modo che tutto ciò che si fida di tutte le applicazioni con apple in partitionID. **`Python`** potrebbe essere utilizzato anche per questo.
{% endhint %}

### Due attributi aggiuntivi

* **Invisible**: È un flag booleano per **nascondere** la voce dall'applicazione **UI** del portachiavi
* **General**: Serve per archiviare **metadati** (quindi NON È CIFRATO)
* Microsoft stava archiviando in testo normale tutti i token di aggiornamento per accedere a endpoint sensibili.

## Riferimenti

* [**#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas**](https://www.youtube.com/watch?v=jKE1ZW33JpY)

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
