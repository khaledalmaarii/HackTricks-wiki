# Estensioni del kernel macOS

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised on HackTricks**? Or do you want to have access to the **latest version of PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our exclusive collection of [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS and HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) **Discord group** or the [**telegram group**](https://t.me/peass) or **follow me** on **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Share your hacking tricks by sending PR to** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informazioni di base

Le estensioni del kernel (Kext) sono **pacchetti** con estensione **`.kext`** che vengono **caricati direttamente nello spazio del kernel macOS**, fornendo funzionalità aggiuntive al sistema operativo principale.

### Requisiti

Ovviamente, questo è così potente che è **complicato caricare un'estensione del kernel**. Questi sono i **requisiti** che un'estensione del kernel deve soddisfare per essere caricata:

* Quando si **entra in modalità di ripristino**, le **estensioni del kernel devono essere consentite** per essere caricate:

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

* L'estensione del kernel deve essere **firmata con un certificato di firma del codice del kernel**, che può essere **concesso solo da Apple**. Chi controllerà in dettaglio l'azienda e le ragioni per cui è necessario.
* L'estensione del kernel deve anche essere **notarizzata**, Apple sarà in grado di controllarla per malware.
* Quindi, l'utente **root** è colui che può **caricare l'estensione del kernel** e i file all'interno del pacchetto devono **appartenere a root**.
* Durante il processo di caricamento, il pacchetto deve essere preparato in una **posizione non-root protetta**: `/Library/StagedExtensions` (richiede il permesso `com.apple.rootless.storage.KernelExtensionManagement`).
* Infine, quando si tenta di caricarlo, l'utente riceverà una [**richiesta di conferma**](https://developer.apple.com/library/archive/technotes/tn2459/\_index.html) e, se accettata, il computer deve essere **riavviato** per caricarla.

### Processo di caricamento

In Catalina era così: È interessante notare che il processo di **verifica** avviene in **userland**. Tuttavia, solo le applicazioni con il permesso **`com.apple.private.security.kext-management`** possono **richiedere al kernel di caricare un'estensione**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **avvia** il processo di **verifica** per il caricamento di un'estensione
* Comunicherà con **`kextd`** inviando un **servizio Mach**.
2. **`kextd`** verificherà diverse cose, come la **firma**
* Comunicherà con **`syspolicyd`** per **verificare** se l'estensione può essere **caricata**.
3. **`syspolicyd`** **richiederà** all'**utente** se l'estensione non è stata caricata in precedenza.
* **`syspolicyd`** riporterà il risultato a **`kextd`**
4. **`kextd`** potrà finalmente **dire al kernel di caricare** l'estensione

Se **`kextd`** non è disponibile, **`kextutil`** può eseguire gli stessi controlli.

## Referencias

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised on HackTricks**? Or do you want to have access to the **latest version of PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our exclusive collection of [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS and HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) **Discord group** or the [**telegram group**](https://t.me/peass) or **follow me** on **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Share your hacking tricks by sending PR to** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
