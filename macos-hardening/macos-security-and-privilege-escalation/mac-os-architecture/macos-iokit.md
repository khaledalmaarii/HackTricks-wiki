# macOS IOKit

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

* ¿Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata su HackTricks**? O vuoi accedere all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Dai un'occhiata ai [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra esclusiva collezione di [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS e HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) **gruppo Discord** o al [**gruppo telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Condividi i tuoi trucchi di hacking inviando PR a** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **e** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informazioni di base

L'IO Kit è un **framework di driver di dispositivo** orientato agli oggetti open-source nel kernel XNU, gestisce i **driver di dispositivo caricati dinamicamente**. Consente l'aggiunta di codice modulare al kernel al volo, supportando hardware diversificato.

I driver IOKit **esportano fondamentalmente funzioni dal kernel**. I tipi di parametri di queste funzioni sono **predefiniti** e verificati. Inoltre, simile a XPC, IOKit è solo un altro strato sopra **i messaggi Mach**.

Il codice del kernel **IOKit XNU** è open source da Apple su [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit). Inoltre, i componenti IOKit dello spazio utente sono anche open source [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

Tuttavia, **nessun driver IOKit** è open source. Comunque, di tanto in tanto il rilascio di un driver potrebbe contenere simboli che facilitano il debug. Controlla come [**ottenere le estensioni del driver dal firmware qui**](./#ipsw)**.**

È scritto in **C++**. Puoi ottenere i simboli C++ demangled con:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% hint style="danger" %}
Le funzioni esposte da IOKit potrebbero eseguire controlli di sicurezza aggiuntivi quando un client tenta di chiamare una funzione, ma è importante notare che le app sono di solito limitate dal sandbox per quanto riguarda le funzioni IOKit con cui possono interagire.
{% endhint %}

## Driver

In macOS sono situati in:

- **`/System/Library/Extensions`**
- File KEXT incorporati nel sistema operativo OS X.
- **`/Library/Extensions`**
- File KEXT installati da software di terze parti

In iOS sono situati in:

- **`/System/Library/Extensions`**
```bash
#Use kextstat to print the loaded drivers
kextstat
Executing: /usr/bin/kmutil showloaded
No variant specified, falling back to release
Index Refs Address            Size       Wired      Name (Version) UUID <Linked Against>
1  142 0                  0          0          com.apple.kpi.bsd (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
2   11 0                  0          0          com.apple.kpi.dsep (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
3  170 0                  0          0          com.apple.kpi.iokit (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
4    0 0                  0          0          com.apple.kpi.kasan (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
5  175 0                  0          0          com.apple.kpi.libkern (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
6  154 0                  0          0          com.apple.kpi.mach (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
7   88 0                  0          0          com.apple.kpi.private (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
8  106 0                  0          0          com.apple.kpi.unsupported (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
9    2 0xffffff8003317000 0xe000     0xe000     com.apple.kec.Libm (1) 6C1342CC-1D74-3D0F-BC43-97D5AD38200A <5>
10   12 0xffffff8003544000 0x92000    0x92000    com.apple.kec.corecrypto (11.1) F5F1255F-6552-3CF4-A9DB-D60EFDEB4A9A <8 7 6 5 3 1>
```
Fino al numero 9 i driver elencati vengono **caricati all'indirizzo 0**. Ciò significa che non si tratta di veri driver ma **fanno parte del kernel e non possono essere scaricati**.

Per trovare le estensioni specifiche puoi utilizzare:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
Per caricare e scaricare le estensioni del kernel, eseguire:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

L'**IORegistry** è una parte cruciale del framework IOKit in macOS e iOS che funge da database per rappresentare la configurazione hardware e lo stato del sistema. È una **raccolta gerarchica di oggetti che rappresentano tutto l'hardware e i driver** caricati sul sistema e le loro relazioni reciproche.

È possibile ottenere l'IORegistry utilizzando la cli **`ioreg`** per ispezionarlo dalla console (particolarmente utile per iOS).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
È possibile scaricare **`IORegistryExplorer`** dagli **Strumenti Aggiuntivi di Xcode** da [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) e ispezionare il **macOS IORegistry** attraverso un'interfaccia **grafica**.

<figure><img src="../../../.gitbook/assets/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

In IORegistryExplorer, i "piani" vengono utilizzati per organizzare e visualizzare le relazioni tra diversi oggetti nell'IORegistry. Ogni piano rappresenta un tipo specifico di relazione o una particolare vista della configurazione hardware e dei driver del sistema. Ecco alcuni dei piani comuni che potresti incontrare in IORegistryExplorer:

1. **Piano IOService**: Questo è il piano più generale, che visualizza gli oggetti di servizio che rappresentano driver e nubs (canali di comunicazione tra driver). Mostra le relazioni fornitore-cliente tra questi oggetti.
2. **Piano IODeviceTree**: Questo piano rappresenta le connessioni fisiche tra i dispositivi mentre sono collegati al sistema. Viene spesso utilizzato per visualizzare l'gerarchia dei dispositivi connessi tramite bus come USB o PCI.
3. **Piano IOPower**: Visualizza gli oggetti e le loro relazioni in termini di gestione dell'alimentazione. Può mostrare quali oggetti stanno influenzando lo stato di alimentazione degli altri, utile per il debug di problemi legati all'alimentazione.
4. **Piano IOUSB**: Specificamente focalizzato sui dispositivi USB e sulle loro relazioni, mostrando l'gerarchia degli hub USB e dei dispositivi connessi.
5. **Piano IOAudio**: Questo piano serve per rappresentare i dispositivi audio e le loro relazioni all'interno del sistema.
6. ...

## Esempio di Codice di Comunicazione del Driver

Il seguente codice si connette al servizio IOKit `"NomeDelTuoServizioQui"` e chiama la funzione all'interno del selettore 0. Per farlo:

* chiama prima **`IOServiceMatching`** e **`IOServiceGetMatchingServices`** per ottenere il servizio.
* Stabilisce quindi una connessione chiamando **`IOServiceOpen`**.
* E infine chiama una funzione con **`IOConnectCallScalarMethod`** indicando il selettore 0 (il selettore è il numero assegnato alla funzione che si desidera chiamare).
```objectivec
#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>

int main(int argc, const char * argv[]) {
@autoreleasepool {
// Get a reference to the service using its name
CFMutableDictionaryRef matchingDict = IOServiceMatching("YourServiceNameHere");
if (matchingDict == NULL) {
NSLog(@"Failed to create matching dictionary");
return -1;
}

// Obtain an iterator over all matching services
io_iterator_t iter;
kern_return_t kr = IOServiceGetMatchingServices(kIOMasterPortDefault, matchingDict, &iter);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to get matching services");
return -1;
}

// Get a reference to the first service (assuming it exists)
io_service_t service = IOIteratorNext(iter);
if (!service) {
NSLog(@"No matching service found");
IOObjectRelease(iter);
return -1;
}

// Open a connection to the service
io_connect_t connect;
kr = IOServiceOpen(service, mach_task_self(), 0, &connect);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to open service");
IOObjectRelease(service);
IOObjectRelease(iter);
return -1;
}

// Call a method on the service
// Assume the method has a selector of 0, and takes no arguments
kr = IOConnectCallScalarMethod(connect, 0, NULL, 0, NULL, NULL);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to call method");
}

// Cleanup
IOServiceClose(connect);
IOObjectRelease(service);
IOObjectRelease(iter);
}
return 0;
}
```
Ci sono **altre** funzioni che possono essere utilizzate per chiamare le funzioni IOKit oltre a **`IOConnectCallScalarMethod`** come **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`**...

## Inversione del punto di ingresso del driver

Potresti ottenerli ad esempio da un [**immagine del firmware (ipsw)**](./#ipsw). Quindi, caricalo nel tuo decompiler preferito.

Potresti iniziare a decompilare la funzione **`externalMethod`** poiché questa è la funzione del driver che riceverà la chiamata e chiamerà la funzione corretta:

<figure><img src="../../../.gitbook/assets/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (1169).png" alt=""><figcaption></figcaption></figure>

Quella chiamata orribile demagled significa:

{% code overflow="wrap" %}
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

Nota come nella definizione precedente manchi il parametro **`self`**, la buona definizione sarebbe:

{% code overflow="wrap" %}
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

In realtà, puoi trovare la definizione reale su [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388):
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
Con queste informazioni puoi riscrivere Ctrl+Destra -> `Modifica firma della funzione` e impostare i tipi conosciuti:

<figure><img src="../../../.gitbook/assets/image (1174).png" alt=""><figcaption></figcaption></figure>

Il nuovo codice decompilato sarà simile a:

<figure><img src="../../../.gitbook/assets/image (1175).png" alt=""><figcaption></figcaption></figure>

Per il prossimo passo è necessario avere definita la struttura **`IOExternalMethodDispatch2022`**. È open source in [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176), puoi definirla:

<figure><img src="../../../.gitbook/assets/image (1170).png" alt=""><figcaption></figcaption></figure>

Ora, seguendo `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray` puoi vedere molti dati:

<figure><img src="../../../.gitbook/assets/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

Cambia il tipo di dati in **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../.gitbook/assets/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

dopo il cambiamento:

<figure><img src="../../../.gitbook/assets/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

E poiché ora sappiamo che abbiamo un **array di 7 elementi** (controlla il codice decompilato finale), clicca per creare un array di 7 elementi:

<figure><img src="../../../.gitbook/assets/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

Dopo aver creato l'array puoi vedere tutte le funzioni esportate:

<figure><img src="../../../.gitbook/assets/image (1181).png" alt=""><figcaption></figcaption></figure>

{% hint style="success" %}
Se ricordi, per **chiamare** una funzione **esportata** dallo spazio utente non è necessario chiamare il nome della funzione, ma il **numero del selettore**. Qui puoi vedere che il selettore **0** è la funzione **`initializeDecoder`**, il selettore **1** è **`startDecoder`**, il selettore **2** **`initializeEncoder`**...
{% endhint %}
