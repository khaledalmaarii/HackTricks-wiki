# Vincoli di avvio/ambiente macOS e Trust Cache

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata su HackTricks**? O vuoi avere accesso all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **e al** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud)
*
* .

</details>

## Informazioni di base

I vincoli di avvio in macOS sono stati introdotti per migliorare la sicurezza regolamentando come, da chi e da dove può essere avviato un processo. Introdotto in macOS Ventura, forniscono un framework che categorizza **ogni binario di sistema in categorie di vincoli distinte**, definite all'interno della **cache di fiducia**, una lista contenente i binari di sistema e i loro hash corrispondenti. Questi vincoli si estendono a ogni binario eseguibile all'interno del sistema, comportando un insieme di **regole** che delineano i requisiti per **avviare un determinato binario**. Le regole comprendono vincoli interni che un binario deve soddisfare, vincoli genitori che devono essere soddisfatti dal processo padre e vincoli responsabili che devono essere aderiti da altre entità pertinenti.

Il meccanismo si estende alle app di terze parti attraverso i **vincoli di ambiente**, a partire da macOS Sonoma, consentendo agli sviluppatori di proteggere le proprie app specificando un **insieme di chiavi e valori per i vincoli di ambiente**.

Definisci i **vincoli di avvio e di libreria** in dizionari di vincoli che salvi in **file di proprietà `launchd`**, o in **file di proprietà separati** che utilizzi nella firma del codice.

Ci sono 4 tipi di vincoli:

* **Vincoli interni**: Vincoli applicati al binario **in esecuzione**.
* **Vincoli del processo padre**: Vincoli applicati al **genitore del processo** (ad esempio **`launchd`** che esegue un servizio XP)
* **Vincoli responsabili**: Vincoli applicati al **processo che chiama il servizio** in una comunicazione XPC
* **Vincoli di caricamento della libreria**: Utilizza i vincoli di caricamento della libreria per descrivere selettivamente il codice che può essere caricato

Quando un processo cerca di avviare un altro processo - chiamando `execve(_:_:_:)` o `posix_spawn(_:_:_:_:_:_:)` - il sistema operativo verifica che il file eseguibile soddisfi il suo **vincolo interno**. Verifica anche che il file eseguibile del **processo padre** soddisfi il **vincolo genitore** del file eseguibile e che il file eseguibile del **processo responsabile** soddisfi il **vincolo del processo responsabile** del file eseguibile. Se uno di questi vincoli di avvio non viene soddisfatto, il sistema operativo non esegue il programma.

Se durante il caricamento di una libreria una parte del **vincolo della libreria non è vera**, il tuo processo **non carica** la libreria.

## Categorie LC

Un LC è composto da **fatti** e **operazioni logiche** (and, or...) che combinano i fatti.

I [**fatti che un LC può utilizzare sono documentati**](https://developer.apple.com/documentation/security/defining\_launch\_environment\_and\_library\_constraints). Ad esempio:

* is-init-proc: Un valore booleano che indica se il file eseguibile deve essere il processo di inizializzazione del sistema operativo (`launchd`).
* is-sip-protected: Un valore booleano che indica se il file eseguibile deve essere un file protetto da System Integrity Protection (SIP).
* `on-authorized-authapfs-volume:` Un valore booleano che indica se il sistema operativo ha caricato il file eseguibile da un volume APFS autorizzato e autenticato.
* `on-authorized-authapfs-volume`: Un valore booleano che indica se il sistema operativo ha caricato il file eseguibile da un volume APFS autorizzato e autenticato.
* Volume Cryptexes
* `on-system-volume:` Un valore booleano che indica se il sistema operativo ha caricato il file eseguibile dal volume di sistema attualmente avviato.
* All'interno di /System...
* ...

Quando un binario Apple viene firmato, viene **assegnato a una categoria LC** all'interno della **cache di fiducia**.

* Le **categorie LC di iOS 16** sono state [**invertite e documentate qui**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).
* Le **categorie LC attuali (macOS 14** - Somona) sono state invertite e le loro [**descrizioni possono essere trovate qui**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).

Ad esempio, la Categoria 1 è:
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
* `(on-authorized-authapfs-volume || on-system-volume)`: Deve essere in un volume di sistema o Cryptexes.
* `launch-type == 1`: Deve essere un servizio di sistema (plist in LaunchDaemons).
* `validation-category == 1`: Un eseguibile di sistema operativo.
* `is-init-proc`: Launchd

### Reversing LC Categories

Hai maggiori informazioni [**qui**](https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/#reversing-constraints), ma in sostanza sono definite in **AMFI (AppleMobileFileIntegrity)**, quindi è necessario scaricare il Kernel Development Kit per ottenere il **KEXT**. I simboli che iniziano con **`kConstraintCategory`** sono quelli **interessanti**. Estraendoli otterrai uno stream codificato DER (ASN.1) che dovrai decodificare con [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) o la libreria python-asn1 e il suo script `dump.py`, [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master), che ti fornirà una stringa più comprensibile.

## Vincoli dell'ambiente

Questi sono i vincoli di avvio configurati nelle **applicazioni di terze parti**. Lo sviluppatore può selezionare i **fatti** e gli **operandi logici da utilizzare** nella sua applicazione per limitare l'accesso ad essa.

È possibile enumerare i vincoli dell'ambiente di un'applicazione con:
```bash
codesign -d -vvvv app.app
```
## Cache di fiducia

In **macOS** ci sono alcune cache di fiducia:

* **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
* **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
* **`/System/Library/Security/OSLaunchPolicyData`**

E in iOS sembra che sia in **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`**.

{% hint style="warning" %}
Su macOS che gira su dispositivi Apple Silicon, se un binario firmato da Apple non è nella cache di fiducia, AMFI rifiuterà di caricarlo.
{% endhint %}

### Enumerazione delle cache di fiducia

I file di cache di fiducia precedenti sono nel formato **IMG4** e **IM4P**, dove IM4P è la sezione payload di un formato IMG4.

Puoi utilizzare [**pyimg4**](https://github.com/m1stadev/PyIMG4) per estrarre il payload dei database:

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

(Un'altra opzione potrebbe essere utilizzare lo strumento [**img4tool**](https://github.com/tihmstar/img4tool), che funzionerà anche su M1 anche se la versione è vecchia e per x86\_64 se lo installi nelle posizioni corrette).

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
La cache di fiducia segue la seguente struttura, quindi la **categoria LC è la quarta colonna**.
```c
struct trust_cache_entry2 {
uint8_t cdhash[CS_CDHASH_LEN];
uint8_t hash_type;
uint8_t flags;
uint8_t constraintCategory;
uint8_t reserved0;
} __attribute__((__packed__));
```
Successivamente, potresti utilizzare uno script come [**questo**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30) per estrarre i dati.

Da quei dati puoi verificare le App con un **valore di vincolo di avvio di `0`**, che sono quelle non vincolate ([**controlla qui**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056) per sapere cosa rappresenta ciascun valore).

## Mitigazioni degli attacchi

I vincoli di avvio avrebbero mitigato diversi vecchi attacchi **assicurandosi che il processo non venga eseguito in condizioni impreviste**: ad esempio da posizioni impreviste o invocato da un processo padre imprevisto (se solo launchd dovesse avviarlo)

Inoltre, i vincoli di avvio **mitigano anche gli attacchi di declassificazione**.

Tuttavia, non mitigano gli abusi comuni di XPC, le iniezioni di codice di Electron o le iniezioni di dylib senza convalida della libreria (a meno che non siano noti gli ID del team che possono caricare le librerie).

### Protezione del demone XPC

Nella versione Sonoma, un punto notevole è la **configurazione della responsabilità del servizio XPC del demone**. Il servizio XPC è responsabile di se stesso, a differenza del client di connessione che è responsabile. Questo è documentato nella segnalazione di feedback FB13206884. Questa configurazione potrebbe sembrare difettosa, poiché consente determinate interazioni con il servizio XPC:

- **Avvio del servizio XPC**: Se si assume che sia un bug, questa configurazione non consente di avviare il servizio XPC tramite codice di attacco.
- **Connessione a un servizio attivo**: Se il servizio XPC è già in esecuzione (possibilmente attivato dalla sua applicazione originale), non ci sono ostacoli alla connessione ad esso.

Sebbene l'implementazione di vincoli sul servizio XPC potrebbe essere vantaggiosa **restringendo la finestra per potenziali attacchi**, non affronta la preoccupazione principale. Garantire la sicurezza del servizio XPC richiede fondamentalmente **la convalida efficace del client di connessione**. Questo rimane l'unico metodo per rafforzare la sicurezza del servizio. Inoltre, è importante notare che la configurazione di responsabilità menzionata è attualmente operativa, il che potrebbe non essere in linea con il design previsto.


### Protezione di Electron

Anche se è necessario che l'applicazione debba essere **aperta da LaunchService** (nei vincoli dei processi padre). Questo può essere ottenuto utilizzando **`open`** (che può impostare variabili di ambiente) o utilizzando l'**API di Launch Services** (dove possono essere indicate variabili di ambiente).

## Riferimenti

* [https://youtu.be/f1HA5QhLQ7Y?t=24146](https://youtu.be/f1HA5QhLQ7Y?t=24146)
* [https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/](https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/)
* [https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
* [https://developer.apple.com/videos/play/wwdc2023/10266/](https://developer.apple.com/videos/play/wwdc2023/10266/)

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata su HackTricks**? O vuoi avere accesso all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **e al** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud)
*
* .

</details>
