# macOS Memory Dumping

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


## Memory Artifacts

### Swap Files

I file di swap, come `/private/var/vm/swapfile0`, servono come **cache quando la memoria fisica è piena**. Quando non c'è più spazio nella memoria fisica, i suoi dati vengono trasferiti a un file di swap e poi riportati nella memoria fisica secondo necessità. Possono essere presenti più file di swap, con nomi come swapfile0, swapfile1, e così via.

### Hibernate Image

Il file situato in `/private/var/vm/sleepimage` è cruciale durante la **modalità di ibernazione**. **I dati dalla memoria vengono memorizzati in questo file quando OS X va in ibernazione**. Al risveglio del computer, il sistema recupera i dati dalla memoria da questo file, consentendo all'utente di continuare da dove aveva interrotto.

Vale la pena notare che sui moderni sistemi MacOS, questo file è tipicamente crittografato per motivi di sicurezza, rendendo difficile il recupero.

* Per controllare se la crittografia è abilitata per il sleepimage, è possibile eseguire il comando `sysctl vm.swapusage`. Questo mostrerà se il file è crittografato.

### Memory Pressure Logs

Un altro file importante relativo alla memoria nei sistemi MacOS è il **registro della pressione della memoria**. Questi registri si trovano in `/var/log` e contengono informazioni dettagliate sull'uso della memoria del sistema e sugli eventi di pressione. Possono essere particolarmente utili per diagnosticare problemi legati alla memoria o per comprendere come il sistema gestisce la memoria nel tempo.

## Dumping memory with osxpmem

Per eseguire il dump della memoria in una macchina MacOS puoi utilizzare [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Nota**: Le seguenti istruzioni funzioneranno solo per i Mac con architettura Intel. Questo strumento è ora archiviato e l'ultima versione è stata rilasciata nel 2017. Il binario scaricato utilizzando le istruzioni qui sotto è destinato ai chip Intel poiché Apple Silicon non era disponibile nel 2017. Potrebbe essere possibile compilare il binario per l'architettura arm64, ma dovrai provare da solo.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Se trovi questo errore: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` Puoi risolverlo facendo:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Altri errori** potrebbero essere risolti **consentendo il caricamento del kext** in "Sicurezza e Privacy --> Generale", basta **consentirlo**.

Puoi anche usare questo **oneliner** per scaricare l'applicazione, caricare il kext e dumpare la memoria:

{% code overflow="wrap" %}
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
{% endcode %}


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
