# macOS Keychain

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) è un motore di ricerca alimentato dal **dark-web** che offre funzionalità **gratuite** per verificare se un'azienda o i suoi clienti sono stati **compromessi** da **malware rubatori**.

Il loro obiettivo principale di WhiteIntel è combattere il furto di account e gli attacchi ransomware derivanti da malware che ruba informazioni.

Puoi controllare il loro sito web e provare il loro motore **gratuitamente** su:

{% embed url="https://whiteintel.io" %}

***

## Main Keychains

* Il **User Keychain** (`~/Library/Keychains/login.keycahin-db`), che viene utilizzato per memorizzare **credenziali specifiche dell'utente** come password delle applicazioni, password di internet, certificati generati dall'utente, password di rete e chiavi pubbliche/private generate dall'utente.
* Il **System Keychain** (`/Library/Keychains/System.keychain`), che memorizza **credenziali a livello di sistema** come password WiFi, certificati radice di sistema, chiavi private di sistema e password delle applicazioni di sistema.

### Password Keychain Access

Questi file, pur non avendo protezione intrinseca e potendo essere **scaricati**, sono crittografati e richiedono la **password in chiaro dell'utente per essere decrittografati**. Uno strumento come [**Chainbreaker**](https://github.com/n0fate/chainbreaker) potrebbe essere utilizzato per la decrittografia.

## Keychain Entries Protections

### ACLs

Ogni voce nel keychain è governata da **Access Control Lists (ACLs)** che determinano chi può eseguire varie azioni sulla voce del keychain, inclusi:

* **ACLAuhtorizationExportClear**: Consente al titolare di ottenere il testo in chiaro del segreto.
* **ACLAuhtorizationExportWrapped**: Consente al titolare di ottenere il testo in chiaro crittografato con un'altra password fornita.
* **ACLAuhtorizationAny**: Consente al titolare di eseguire qualsiasi azione.

Le ACL sono ulteriormente accompagnate da un **elenco di applicazioni fidate** che possono eseguire queste azioni senza richiedere conferma. Questo potrebbe essere:

* **N`il`** (nessuna autorizzazione richiesta, **tutti sono fidati**)
* Un elenco **vuoto** (**nessuno** è fidato)
* **Elenco** di **applicazioni** specifiche.

Inoltre, la voce potrebbe contenere la chiave **`ACLAuthorizationPartitionID`,** che viene utilizzata per identificare il **teamid, apple,** e **cdhash.**

* Se il **teamid** è specificato, allora per **accedere al valore della voce** **senza** un **prompt** l'applicazione utilizzata deve avere lo **stesso teamid**.
* Se l'**apple** è specificato, allora l'app deve essere **firmata** da **Apple**.
* Se il **cdhash** è indicato, allora l'**app** deve avere il **cdhash** specifico.

### Creating a Keychain Entry

Quando viene creata una **nuova** **voce** utilizzando **`Keychain Access.app`**, si applicano le seguenti regole:

* Tutte le app possono crittografare.
* **Nessuna app** può esportare/decrittografare (senza richiedere conferma all'utente).
* Tutte le app possono vedere il controllo di integrità.
* Nessuna app può modificare le ACL.
* Il **partitionID** è impostato su **`apple`**.

Quando un'**applicazione crea una voce nel keychain**, le regole sono leggermente diverse:

* Tutte le app possono crittografare.
* Solo l'**applicazione che crea** (o altre app esplicitamente aggiunte) può esportare/decrittografare (senza richiedere conferma all'utente).
* Tutte le app possono vedere il controllo di integrità.
* Nessuna app può modificare le ACL.
* Il **partitionID** è impostato su **`teamid:[teamID here]`**.

## Accessing the Keychain

### `security`
```bash
# List keychains
security list-keychains

# Dump all metadata and decrypted secrets (a lot of pop-ups)
security dump-keychain -a -d

# Find generic password for the "Slack" account and print the secrets
security find-generic-password -a "Slack" -g

# Change the specified entrys PartitionID entry
security set-generic-password-parition-list -s "test service" -a "test acount" -S

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```
### APIs

{% hint style="success" %}
L'**enumerazione e il dumping** delle chiavi che **non genereranno un prompt** possono essere effettuati con lo strumento [**LockSmith**](https://github.com/its-a-feature/LockSmith)
{% endhint %}

Elenca e ottieni **info** su ogni voce del portachiavi:

* L'API **`SecItemCopyMatching`** fornisce informazioni su ogni voce e ci sono alcuni attributi che puoi impostare quando la usi:
* **`kSecReturnData`**: Se vero, cercherà di decrittografare i dati (imposta su falso per evitare potenziali pop-up)
* **`kSecReturnRef`**: Ottieni anche un riferimento all'elemento del portachiavi (imposta su vero nel caso in cui successivamente vedi che puoi decrittografare senza pop-up)
* **`kSecReturnAttributes`**: Ottieni metadati sulle voci
* **`kSecMatchLimit`**: Quanti risultati restituire
* **`kSecClass`**: Che tipo di voce del portachiavi

Ottieni **ACL** di ogni voce:

* Con l'API **`SecAccessCopyACLList`** puoi ottenere l'**ACL per l'elemento del portachiavi**, e restituirà un elenco di ACL (come `ACLAuhtorizationExportClear` e gli altri precedentemente menzionati) dove ogni elenco ha:
* Descrizione
* **Elenco delle applicazioni fidate**. Questo potrebbe essere:
* Un'app: /Applications/Slack.app
* Un binario: /usr/libexec/airportd
* Un gruppo: group://AirPort

Esporta i dati:

* L'API **`SecKeychainItemCopyContent`** ottiene il testo in chiaro
* L'API **`SecItemExport`** esporta le chiavi e i certificati ma potrebbe essere necessario impostare le password per esportare il contenuto crittografato

E questi sono i **requisiti** per poter **esportare un segreto senza un prompt**:

* Se ci sono **1+ app fidate** elencate:
* Necessita delle appropriate **autorizzazioni** (**`Nil`**, o essere **parte** dell'elenco delle app autorizzate ad accedere alle informazioni segrete)
* Necessita che la firma del codice corrisponda al **PartitionID**
* Necessita che la firma del codice corrisponda a quella di un **app fidata** (o essere un membro del giusto KeychainAccessGroup)
* Se **tutte le applicazioni sono fidate**:
* Necessita delle appropriate **autorizzazioni**
* Necessita che la firma del codice corrisponda al **PartitionID**
* Se **non c'è PartitionID**, allora questo non è necessario

{% hint style="danger" %}
Pertanto, se c'è **1 applicazione elencata**, è necessario **iniettare codice in quell'applicazione**.

Se **apple** è indicato nel **partitionID**, potresti accedervi con **`osascript`** quindi qualsiasi cosa che stia fidando tutte le applicazioni con apple nel partitionID. **`Python`** potrebbe anche essere usato per questo.
{% endhint %}

### Due attributi aggiuntivi

* **Invisible**: È un flag booleano per **nascondere** la voce dall'app **UI** del portachiavi
* **General**: Serve a memorizzare **metadati** (quindi NON È CRIPTATO)
* Microsoft memorizzava in testo chiaro tutti i token di aggiornamento per accedere a endpoint sensibili.

## Riferimenti

* [**#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas**](https://www.youtube.com/watch?v=jKE1ZW33JpY)

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) è un motore di ricerca alimentato dal **dark-web** che offre funzionalità **gratuite** per controllare se un'azienda o i suoi clienti sono stati **compromessi** da **malware rubatori**.

Il loro obiettivo principale di WhiteIntel è combattere le assunzioni di account e gli attacchi ransomware derivanti da malware che rubano informazioni.

Puoi controllare il loro sito web e provare il loro motore **gratuitamente** su:

{% embed url="https://whiteintel.io" %}

{% hint style="success" %}
Impara e pratica il hacking AWS:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica il hacking GCP: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>
{% endhint %}
