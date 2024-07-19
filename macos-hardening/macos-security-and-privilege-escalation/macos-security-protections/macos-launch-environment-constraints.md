# macOS Launch/Environment Constraints & Trust Cache

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Informazioni di base

I vincoli di avvio in macOS sono stati introdotti per migliorare la sicurezza **regolando come, chi e da dove un processo può essere avviato**. Introdotti in macOS Ventura, forniscono un framework che categorizza **ogni binario di sistema in distinte categorie di vincolo**, definite all'interno della **trust cache**, un elenco contenente i binari di sistema e i loro rispettivi hash. Questi vincoli si estendono a ogni binario eseguibile all'interno del sistema, comportando un insieme di **regole** che delineano i requisiti per **l'avvio di un particolare binario**. Le regole comprendono vincoli autoimposti che un binario deve soddisfare, vincoli parentali che devono essere soddisfatti dal suo processo padre e vincoli di responsabilità a cui devono attenersi altre entità rilevanti.

Il meccanismo si estende alle app di terze parti attraverso i **Vincoli di Ambiente**, a partire da macOS Sonoma, consentendo agli sviluppatori di proteggere le loro app specificando un **insieme di chiavi e valori per i vincoli di ambiente.**

Definisci **vincoli di ambiente e libreria di avvio** in dizionari di vincoli che salvi in **file di elenco di proprietà `launchd`**, o in **file di elenco di proprietà separati** che utilizzi nella firma del codice.

Ci sono 4 tipi di vincoli:

* **Vincoli Autoimposti**: Vincoli applicati al **binario in esecuzione**.
* **Processo Padre**: Vincoli applicati al **genitore del processo** (ad esempio **`launchd`** che esegue un servizio XP)
* **Vincoli di Responsabilità**: Vincoli applicati al **processo che chiama il servizio** in una comunicazione XPC
* **Vincoli di caricamento della libreria**: Usa i vincoli di caricamento della libreria per descrivere selettivamente il codice che può essere caricato

Quindi, quando un processo cerca di avviare un altro processo — chiamando `execve(_:_:_:)` o `posix_spawn(_:_:_:_:_:_:)` — il sistema operativo verifica che il file **eseguibile** **soddisfi** il proprio **vincolo autoimposto**. Controlla anche che l'eseguibile del **processo padre** **soddisfi** il **vincolo parentale** dell'eseguibile e che l'eseguibile del **processo responsabile** **soddisfi il vincolo di responsabilità** dell'eseguibile. Se uno di questi vincoli di avvio non è soddisfatto, il sistema operativo non esegue il programma.

Se durante il caricamento di una libreria qualsiasi parte del **vincolo della libreria non è vera**, il tuo processo **non carica** la libreria.

## Categorie LC

Un LC è composto da **fatti** e **operazioni logiche** (e, o..) che combinano fatti.

I[ **fatti che un LC può utilizzare sono documentati**](https://developer.apple.com/documentation/security/defining\_launch\_environment\_and\_library\_constraints). Ad esempio:

* is-init-proc: Un valore booleano che indica se l'eseguibile deve essere il processo di inizializzazione del sistema operativo (`launchd`).
* is-sip-protected: Un valore booleano che indica se l'eseguibile deve essere un file protetto da System Integrity Protection (SIP).
* `on-authorized-authapfs-volume:` Un valore booleano che indica se il sistema operativo ha caricato l'eseguibile da un volume APFS autorizzato e autenticato.
* `on-authorized-authapfs-volume`: Un valore booleano che indica se il sistema operativo ha caricato l'eseguibile da un volume APFS autorizzato e autenticato.
* Volume Cryptexes
* `on-system-volume:` Un valore booleano che indica se il sistema operativo ha caricato l'eseguibile dal volume di sistema attualmente avviato.
* Dentro /System...
* ...

Quando un binario Apple è firmato, **viene assegnato a una categoria LC** all'interno della **trust cache**.

* Le **categorie LC di iOS 16** sono state [**invertite e documentate qui**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).
* Le attuali **categorie LC (macOS 14** - Somona) sono state invertite e le loro [**descrizioni possono essere trovate qui**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).

Ad esempio, la Categoria 1 è:
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
* `(on-authorized-authapfs-volume || on-system-volume)`: Deve trovarsi nel volume di sistema o Cryptexes.
* `launch-type == 1`: Deve essere un servizio di sistema (plist in LaunchDaemons).
* `validation-category == 1`: Un eseguibile del sistema operativo.
* `is-init-proc`: Launchd

### Reversing LC Categories

Hai ulteriori informazioni [**a riguardo qui**](https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/#reversing-constraints), ma fondamentalmente, sono definiti in **AMFI (AppleMobileFileIntegrity)**, quindi devi scaricare il Kernel Development Kit per ottenere il **KEXT**. I simboli che iniziano con **`kConstraintCategory`** sono quelli **interessanti**. Estraendoli otterrai uno stream codificato DER (ASN.1) che dovrai decodificare con [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) o la libreria python-asn1 e il suo script `dump.py`, [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master) che ti darà una stringa più comprensibile.

## Environment Constraints

Questi sono i Launch Constraints impostati configurati in **applicazioni di terze parti**. Lo sviluppatore può selezionare i **fatti** e **operatori logici da utilizzare** nella sua applicazione per limitare l'accesso a se stesso.

È possibile enumerare i Environment Constraints di un'applicazione con:
```bash
codesign -d -vvvv app.app
```
## Trust Caches

In **macOS** ci sono alcuni cache di fiducia:

* **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
* **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
* **`/System/Library/Security/OSLaunchPolicyData`**

E in iOS sembra che si trovi in **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`**.

{% hint style="warning" %}
Su macOS in esecuzione su dispositivi Apple Silicon, se un binario firmato da Apple non è nel cache di fiducia, AMFI rifiuterà di caricarlo.
{% endhint %}

### Enumerating Trust Caches

I precedenti file di cache di fiducia sono nel formato **IMG4** e **IM4P**, essendo IM4P la sezione payload di un formato IMG4.

Puoi usare [**pyimg4**](https://github.com/m1stadev/PyIMG4) per estrarre il payload dei database:

{% code overflow="wrap" %}
```bash
# Installation
python3 -m pip install pyimg4

# Extract payloads data
cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/BaseSystemTrustCache.img4 -p /tmp/BaseSystemTrustCache.im4p
pyimg4 im4p extract -i /tmp/BaseSystemTrustCache.im4p -o /tmp/BaseSystemTrustCache.data

cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/StaticTrustCache.img4 -p /tmp/StaticTrustCache.im4p
pyimg4 im4p extract -i /tmp/StaticTrustCache.im4p -o /tmp/StaticTrustCache.data

pyimg4 im4p extract -i /System/Library/Security/OSLaunchPolicyData -o /tmp/OSLaunchPolicyData.data
```
{% endcode %}

(Un'altra opzione potrebbe essere utilizzare lo strumento [**img4tool**](https://github.com/tihmstar/img4tool), che funzionerà anche su M1 anche se il rilascio è vecchio e per x86\_64 se lo installi nelle posizioni appropriate).

Ora puoi utilizzare lo strumento [**trustcache**](https://github.com/CRKatri/trustcache) per ottenere le informazioni in un formato leggibile:
```bash
# Install
wget https://github.com/CRKatri/trustcache/releases/download/v2.0/trustcache_macos_arm64
sudo mv ./trustcache_macos_arm64 /usr/local/bin/trustcache
xattr -rc /usr/local/bin/trustcache
chmod +x /usr/local/bin/trustcache

# Run
trustcache info /tmp/OSLaunchPolicyData.data | head
trustcache info /tmp/StaticTrustCache.data | head
trustcache info /tmp/BaseSystemTrustCache.data | head

version = 2
uuid = 35EB5284-FD1E-4A5A-9EFB-4F79402BA6C0
entry count = 969
0065fc3204c9f0765049b82022e4aa5b44f3a9c8 [none] [2] [1]
00aab02b28f99a5da9b267910177c09a9bf488a2 [none] [2] [1]
0186a480beeee93050c6c4699520706729b63eff [none] [2] [2]
0191be4c08426793ff3658ee59138e70441fc98a [none] [2] [3]
01b57a71112235fc6241194058cea5c2c7be3eb1 [none] [2] [2]
01e6934cb8833314ea29640c3f633d740fc187f2 [none] [2] [2]
020bf8c388deaef2740d98223f3d2238b08bab56 [none] [2] [3]
```
La cache di fiducia segue la seguente struttura, quindi la **categoria LC è la quarta colonna**
```c
struct trust_cache_entry2 {
uint8_t cdhash[CS_CDHASH_LEN];
uint8_t hash_type;
uint8_t flags;
uint8_t constraintCategory;
uint8_t reserved0;
} __attribute__((__packed__));
```
Then, you could use a script such as [**this one**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30) to extract data.

From that data you can check the Apps with a **launch constraints value of `0`**, which are the ones that aren't constrained ([**check here**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056) for what each value is).

## Mitigazioni degli attacchi

Le Launch Constraints avrebbero mitigato diversi attacchi vecchi **assicurandosi che il processo non venga eseguito in condizioni inaspettate:** Ad esempio, da posizioni inaspettate o invocato da un processo padre inaspettato (se solo launchd dovrebbe lanciarlo).

Inoltre, le Launch Constraints **mitigano anche gli attacchi di downgrade.**

Tuttavia, non **mitigano gli abusi comuni di XPC**, **iniezioni di codice Electron** o **iniezioni di dylib** senza validazione della libreria (a meno che gli ID team che possono caricare librerie non siano noti).

### Protezione del Demone XPC

Nella release di Sonoma, un punto notevole è la **configurazione della responsabilità** del servizio demone XPC. Il servizio XPC è responsabile di se stesso, a differenza del client connesso che è responsabile. Questo è documentato nel rapporto di feedback FB13206884. Questa configurazione potrebbe sembrare difettosa, poiché consente alcune interazioni con il servizio XPC:

- **Avvio del Servizio XPC**: Se considerato un bug, questa configurazione non consente di avviare il servizio XPC tramite codice dell'attaccante.
- **Connessione a un Servizio Attivo**: Se il servizio XPC è già in esecuzione (possibilmente attivato dalla sua applicazione originale), non ci sono barriere per connettersi ad esso.

Sebbene l'implementazione di vincoli sul servizio XPC possa essere vantaggiosa **ristretta la finestra per potenziali attacchi**, non affronta la preoccupazione principale. Garantire la sicurezza del servizio XPC richiede fondamentalmente **di validare efficacemente il client connesso**. Questo rimane l'unico metodo per rafforzare la sicurezza del servizio. Inoltre, vale la pena notare che la configurazione di responsabilità menzionata è attualmente operativa, il che potrebbe non allinearsi con il design previsto.

### Protezione Electron

Anche se è richiesto che l'applicazione debba essere **aperta da LaunchService** (nei vincoli dei genitori). Questo può essere ottenuto utilizzando **`open`** (che può impostare variabili di ambiente) o utilizzando l'**API dei Servizi di Lancio** (dove possono essere indicate le variabili di ambiente).

## Riferimenti

* [https://youtu.be/f1HA5QhLQ7Y?t=24146](https://youtu.be/f1HA5QhLQ7Y?t=24146)
* [https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/](https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/)
* [https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
* [https://developer.apple.com/videos/play/wwdc2023/10266/](https://developer.apple.com/videos/play/wwdc2023/10266/)

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
