# Bundle di macOS

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) su GitHub.

</details>

## Informazioni di base

I bundle in macOS fungono da contenitori per una varietà di risorse, tra cui applicazioni, librerie e altri file necessari, facendoli apparire come oggetti singoli in Finder, come i familiari file `*.app`. Il bundle più comune è il bundle `.app`, anche se sono diffusi anche altri tipi come `.framework`, `.systemextension` e `.kext`.

### Componenti essenziali di un bundle

All'interno di un bundle, in particolare all'interno della directory `<application>.app/Contents/`, sono presenti diverse risorse importanti:

- **_CodeSignature**: Questa directory memorizza i dettagli della firma del codice fondamentali per verificare l'integrità dell'applicazione. È possibile ispezionare le informazioni sulla firma del codice utilizzando comandi come:
%%%bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
%%%
- **MacOS**: Contiene il file binario eseguibile dell'applicazione che viene eseguito durante l'interazione dell'utente.
- **Resources**: Un repository per i componenti dell'interfaccia utente dell'applicazione, tra cui immagini, documenti e descrizioni dell'interfaccia (file nib/xib).
- **Info.plist**: Agisce come file di configurazione principale dell'applicazione, fondamentale affinché il sistema riconosca e interagisca correttamente con l'applicazione.

#### Chiavi importanti in Info.plist

Il file `Info.plist` è un elemento fondamentale per la configurazione dell'applicazione, contenente chiavi come:

- **CFBundleExecutable**: Specifica il nome del file eseguibile principale situato nella directory `Contents/MacOS`.
- **CFBundleIdentifier**: Fornisce un identificatore globale per l'applicazione, ampiamente utilizzato da macOS per la gestione delle applicazioni.
- **LSMinimumSystemVersion**: Indica la versione minima di macOS richiesta per l'esecuzione dell'applicazione.

### Esplorazione dei bundle

Per esplorare il contenuto di un bundle, come `Safari.app`, è possibile utilizzare il seguente comando:
%%%bash
ls -lR /Applications/Safari.app/Contents
%%%

Questa esplorazione rivela directory come `_CodeSignature`, `MacOS`, `Resources`, e file come `Info.plist`, ognuno con uno scopo unico, dalla sicurezza dell'applicazione alla definizione dell'interfaccia utente e dei parametri operativi.

#### Directory aggiuntive dei bundle

Oltre alle directory comuni, i bundle possono includere anche:

- **Frameworks**: Contiene framework inclusi nell'applicazione.
- **PlugIns**: Una directory per plug-in ed estensioni che migliorano le capacità dell'applicazione.
- **XPCServices**: Contiene servizi XPC utilizzati dall'applicazione per la comunicazione fuori processo.

Questa struttura garantisce che tutti i componenti necessari siano racchiusi nel bundle, facilitando un ambiente di applicazione modulare e sicuro.

Per informazioni più dettagliate sulle chiavi di `Info.plist` e il loro significato, la documentazione degli sviluppatori Apple fornisce risorse estese: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) su GitHub.

</details>
