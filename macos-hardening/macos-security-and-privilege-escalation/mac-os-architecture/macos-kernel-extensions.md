# macOS Kernel Extensions

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

Le estensioni del kernel (Kext) sono **pacchetti** con un'estensione **`.kext`** che vengono **caricati direttamente nello spazio del kernel di macOS**, fornendo funzionalità aggiuntive al sistema operativo principale.

### Requisiti

Ovviamente, questo è così potente che è **complicato caricare un'estensione del kernel**. Questi sono i **requisiti** che un'estensione del kernel deve soddisfare per essere caricata:

* Quando si **entra in modalità di recupero**, le **estensioni del kernel devono essere autorizzate** a essere caricate:

<figure><img src="../../../.gitbook/assets/image (327).png" alt=""><figcaption></figcaption></figure>

* L'estensione del kernel deve essere **firmata con un certificato di firma del codice del kernel**, che può essere **concesso solo da Apple**. Chi esaminerà in dettaglio l'azienda e le ragioni per cui è necessaria.
* L'estensione del kernel deve anche essere **notarizzata**, Apple sarà in grado di controllarla per malware.
* Poi, l'utente **root** è colui che può **caricare l'estensione del kernel** e i file all'interno del pacchetto devono **appartenere a root**.
* Durante il processo di caricamento, il pacchetto deve essere preparato in una **posizione protetta non-root**: `/Library/StagedExtensions` (richiede il grant `com.apple.rootless.storage.KernelExtensionManagement`).
* Infine, quando si tenta di caricarlo, l'utente riceverà una [**richiesta di conferma**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) e, se accettata, il computer deve essere **riavviato** per caricarlo.

### Processo di caricamento

In Catalina era così: È interessante notare che il processo di **verifica** avviene in **userland**. Tuttavia, solo le applicazioni con il grant **`com.apple.private.security.kext-management`** possono **richiedere al kernel di caricare un'estensione**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **avvia** il processo di **verifica** per caricare un'estensione
* Comunicherà con **`kextd`** inviando utilizzando un **servizio Mach**.
2. **`kextd`** controllerà diverse cose, come la **firma**
* Comunicherà con **`syspolicyd`** per **verificare** se l'estensione può essere **caricata**.
3. **`syspolicyd`** **chiederà** all'**utente** se l'estensione non è stata precedentemente caricata.
* **`syspolicyd`** riporterà il risultato a **`kextd`**
4. **`kextd`** sarà infine in grado di **dire al kernel di caricare** l'estensione

Se **`kextd`** non è disponibile, **`kextutil`** può eseguire gli stessi controlli.

## Referenze

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

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
