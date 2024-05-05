# Estensioni del kernel di macOS

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

* Lavori per una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata su HackTricks**? O vuoi accedere all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Dai un'occhiata ai [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra esclusiva collezione di [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS e HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) **gruppo Discord** o al [**gruppo Telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Condividi i tuoi trucchi di hacking inviando PR a** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **e** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informazioni di base

Le estensioni del kernel (Kexts) sono **pacchetti** con estensione **`.kext`** che vengono **caricati direttamente nello spazio del kernel di macOS**, fornendo funzionalità aggiuntive al sistema operativo principale.

### Requisiti

Ovviamente, è così potente che è **complicato caricare un'estensione del kernel**. Questi sono i **requisiti** che una estensione del kernel deve soddisfare per essere caricata:

* Quando si **entra in modalità di ripristino**, le **estensioni del kernel devono essere autorizzate** a essere caricate:

<figure><img src="../../../.gitbook/assets/image (327).png" alt=""><figcaption></figcaption></figure>

* L'estensione del kernel deve essere **firmata con un certificato di firma del codice del kernel**, che può essere concesso solo da Apple. Chi esaminerà dettagliatamente l'azienda e i motivi per cui è necessario.
* L'estensione del kernel deve anche essere **notarizzata**, Apple sarà in grado di controllarla per malware.
* Quindi, l'utente **root** è l'unico che può **caricare l'estensione del kernel** e i file all'interno del pacchetto devono **appartenere a root**.
* Durante il processo di caricamento, il pacchetto deve essere preparato in una **posizione protetta non di root**: `/Library/StagedExtensions` (richiede il permesso `com.apple.rootless.storage.KernelExtensionManagement`).
* Infine, quando si tenta di caricarlo, l'utente riceverà una [**richiesta di conferma**](https://developer.apple.com/library/archive/technotes/tn2459/\_index.html) e, se accettata, il computer deve essere **riavviato** per caricarla.

### Processo di caricamento

In Catalina era così: È interessante notare che il processo di **verifica** avviene in **userland**. Tuttavia, solo le applicazioni con il permesso **`com.apple.private.security.kext-management`** possono **richiedere al kernel di caricare un'estensione**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **avvia** il processo di **verifica** per il caricamento di un'estensione
* Parlerà con **`kextd`** inviando tramite un **servizio Mach**.
2. **`kextd`** controllerà diverse cose, come la **firma**
* Parlerà con **`syspolicyd`** per **verificare** se l'estensione può essere **caricata**.
3. **`syspolicyd`** **chiederà** all'**utente** se l'estensione non è stata caricata in precedenza.
* **`syspolicyd`** riporterà il risultato a **`kextd`**
4. **`kextd`** potrà infine **dire al kernel di caricare** l'estensione

Se **`kextd`** non è disponibile, **`kextutil`** può eseguire gli stessi controlli.

## References

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

* Lavori per una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata su HackTricks**? O vuoi accedere all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Dai un'occhiata ai [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra esclusiva collezione di [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS e HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) **gruppo Discord** o al [**gruppo Telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Condividi i tuoi trucchi di hacking inviando PR a** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **e** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
