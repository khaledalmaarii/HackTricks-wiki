# Attacco a xpc\_connection\_get\_audit\_token su macOS

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

**Per ulteriori informazioni consulta il post originale:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Questo è un riassunto:

## Informazioni di base sui messaggi Mach

Se non sai cosa sono i messaggi Mach, inizia controllando questa pagina:

{% content-ref url="../../" %}
[..](../../)
{% endcontent-ref %}

Per il momento ricorda che ([definizione da qui](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
I messaggi Mach vengono inviati su una _porta mach_, che è un canale di comunicazione **singolo ricevitore, multiplo mittente** integrato nel kernel mach. **Più processi possono inviare messaggi** a una porta mach, ma in qualsiasi momento **solo un singolo processo può leggerne**. Proprio come i descrittori di file e i socket, le porte mach sono allocate e gestite dal kernel e i processi vedono solo un numero intero, che possono utilizzare per indicare al kernel quale delle loro porte mach desiderano utilizzare.

## Connessione XPC

Se non sai come viene stabilita una connessione XPC, controlla:

{% content-ref url="../" %}
[..](../)
{% endcontent-ref %}

## Riassunto della vulnerabilità

Ciò che è interessante sapere è che **l'astrazione di XPC è una connessione uno a uno**, ma è basata su una tecnologia che **può avere più mittenti, quindi:**

* Le porte Mach sono un singolo ricevitore, **multiplo mittente**.
* Il token di audit di una connessione XPC è il token di audit **copiato dal messaggio più recentemente ricevuto**.
* Ottenere il **token di audit** di una connessione XPC è fondamentale per molti **controlli di sicurezza**.

Anche se la situazione precedente sembra promettente, ci sono alcuni scenari in cui ciò non causerà problemi ([da qui](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

* I token di audit vengono spesso utilizzati per un controllo di autorizzazione per decidere se accettare una connessione. Poiché ciò avviene utilizzando un messaggio alla porta del servizio, **non è ancora stata stabilita alcuna connessione**. Altri messaggi su questa porta verranno gestiti come richieste di connessione aggiuntive. Quindi eventuali **controlli prima di accettare una connessione non sono vulnerabili** (ciò significa anche che all'interno di `-listener:shouldAcceptNewConnection:` il token di audit è sicuro). Stiamo quindi **cercando connessioni XPC che verifichino azioni specifiche**.
* Gli handler degli eventi XPC vengono gestiti in modo sincrono. Ciò significa che l'handler dell'evento per un messaggio deve essere completato prima di chiamarlo per il successivo, anche su code di invio concorrenti. Quindi all'interno di un **gestore di eventi XPC il token di audit non può essere sovrascritto** da altri messaggi normali (non di risposta!).

Due diversi metodi con cui ciò potrebbe essere sfruttato:

1. Variante1:
* **L'exploit si connette** al servizio **A** e al servizio **B**
* Il servizio **B** può chiamare una **funzionalità privilegiata** in servizio **A** che l'utente non può
* Il servizio **A** chiama **`xpc_connection_get_audit_token`** mentre _**non**_ è all'interno dell'**handler di evento** per una connessione in un **`dispatch_async`**.
* Quindi un **messaggio diverso potrebbe sovrascrivere il Token di Audit** perché viene inviato in modo asincrono al di fuori dell'handler di evento.
* L'exploit passa a **servizio B il diritto di invio a servizio A**.
* Quindi svc **B** invierà effettivamente i **messaggi** a servizio **A**.
* L'**exploit** cerca di **chiamare l'azione privilegiata**. In un RC svc **A** **controlla** l'autorizzazione di questa **azione** mentre **svc B sovrascrive il Token di Audit** (dando all'exploit l'accesso per chiamare l'azione privilegiata).
2. Variante 2:
* Il servizio **B** può chiamare una **funzionalità privilegiata** in servizio **A** che l'utente non può
* L'exploit si connette con **servizio A** che **invia** all'exploit un **messaggio che si aspetta una risposta** in una specifica **porta di risposta**.
* L'exploit invia al **servizio** B un messaggio passando **quella porta di risposta**.
* Quando il servizio **B risponde**, invia il messaggio a servizio **A**, **mentre** l'**exploit** invia un messaggio diverso a servizio **A** cercando di **raggiungere una funzionalità privilegiata** e aspettandosi che la risposta da servizio B sovrascriva il Token di Audit nel momento perfetto (Condizione di Gara).

## Variante 1: chiamare xpc\_connection\_get\_audit\_token al di fuori di un handler di evento <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Scenario:

* Due servizi mach **`A`** e **`B`** a cui possiamo entrambi connetterci (in base al profilo sandbox e ai controlli di autorizzazione prima di accettare la connessione).
* _**A**_ deve avere un **controllo di autorizzazione** per un'azione specifica che **`B`** può superare (ma la nostra app non può).
* Ad esempio, se B ha alcuni **privilegi** o viene eseguito come **root**, potrebbe consentirgli di chiedere ad A di eseguire un'azione privilegiata.
* Per questo controllo di autorizzazione, **`A`** ottiene il token di audit in modo asincrono, ad esempio chiamando `xpc_connection_get_audit_token` da **`dispatch_async`**.

{% hint style="danger" %}
In questo caso un attaccante potrebbe innescare una **Condizione di Gara** creando un **exploit** che **chiede ad A di eseguire un'azione** più volte mentre **B invia messaggi ad `A`**. Quando la CG è **riuscita**, il **token di audit** di **B** verrà copiato in memoria **mentre** la richiesta del nostro **exploit** viene **gestita** da A, dandogli **accesso all'azione privilegiata che solo B poteva richiedere**.
{% endhint %}

Ciò è accaduto con **`A`** come `smd` e **`B`** come `diagnosticd`. La funzione [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) da smb può essere utilizzata per installare un nuovo strumento helper privilegiato (come **root**). Se un **processo in esecuzione come root contatta** **smd**, non verranno eseguiti altri controlli.

Pertanto, il servizio **B** è **`diagnosticd`** perché viene eseguito come **root** e può essere utilizzato per **monitorare** un processo, quindi una volta avviato il monitoraggio, invierà **più messaggi al secondo.**

Per eseguire l'attacco:

1. Inizia una **connessione** al servizio chiamato `smd` utilizzando il protocollo XPC standard.
2. Forma una secondaria **connessione** a `diagnosticd`. Contrariamente alla procedura normale, anziché creare e inviare due nuove porte mach, il diritto di invio della porta client viene sostituito con una duplicata del **diritto di invio** associato alla connessione `smd`.
3. Di conseguenza, i messaggi XPC possono essere inviati a `diagnosticd`, ma le risposte da `diagnosticd` vengono dirottate su `smd`. Per `smd`, sembra che i messaggi sia dall'utente che da `diagnosticd` provengano dalla stessa connessione.

![Immagine che raffigura il processo di exploit](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. Il passo successivo consiste nell'istruire `diagnosticd` ad avviare il monitoraggio di un processo scelto (potenzialmente quello dell'utente). Contestualmente, viene inviata una serie di messaggi di routine 1004 a `smd`. L'intento qui è quello di installare uno strumento con privilegi elevati.
5. Questa azione scatena una condizione di gara all'interno della funzione `handle_bless`. Il tempismo è critico: la chiamata alla funzione `xpc_connection_get_pid` deve restituire il PID del processo dell'utente (poiché lo strumento privilegiato risiede nel bundle dell'applicazione dell'utente). Tuttavia, la funzione `xpc_connection_get_audit_token`, specificamente all'interno della subroutine `connection_is_authorized`, deve fare riferimento al token di audit appartenente a `diagnosticd`.

## Variante 2: inoltro delle risposte

In un ambiente XPC (Comunicazione tra Processi), anche se gli handler degli eventi non vengono eseguiti contemporaneamente, la gestione dei messaggi di risposta ha un comportamento unico. In particolare, esistono due metodi distinti per l'invio di messaggi che si aspettano una risposta:

1. **`xpc_connection_send_message_with_reply`**: Qui, il messaggio XPC viene ricevuto e elaborato su una coda designata.
2. **`xpc_connection_send_message_with_reply_sync`**: Al contrario, in questo metodo, il messaggio XPC viene ricevuto e elaborato sulla coda di dispacci corrente.

Questa distinzione è cruciale perché permette la possibilità di **analizzare i pacchetti di risposta in modo concorrente con l'esecuzione di un gestore di eventi XPC**. In particolare, mentre `_xpc_connection_set_creds` implementa un blocco per proteggere dalla sovrascrittura parziale del token di audit, non estende questa protezione all'intero oggetto di connessione. Di conseguenza, si crea una vulnerabilità in cui il token di audit può essere sostituito durante l'intervallo tra l'analisi di un pacchetto e l'esecuzione del suo gestore di eventi.

Per sfruttare questa vulnerabilità, è necessaria la seguente configurazione:

* Due servizi mach, denominati **`A`** e **`B`**, entrambi in grado di stabilire una connessione.
* Il servizio **`A`** dovrebbe includere un controllo di autorizzazione per un'azione specifica che solo **`B`** può eseguire (l'applicazione dell'utente non può).
* Il servizio **`A`** dovrebbe inviare un messaggio che prevede una risposta.
* L'utente può inviare un messaggio a **`B`** a cui risponderà.

Il processo di sfruttamento comporta i seguenti passaggi:

1. Attendere che il servizio **`A`** invii un messaggio che si aspetta una risposta.
2. Invece di rispondere direttamente a **`A`**, la porta di risposta viene dirottata e utilizzata per inviare un messaggio al servizio **`B`**.
3. Successivamente, viene inviato un messaggio che coinvolge l'azione vietata, con l'aspettativa che venga elaborato in modo concorrente con la risposta da **`B`**.

Di seguito è riportata una rappresentazione visiva dello scenario di attacco descritto:

![https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png](../../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../.gitbook/assets/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Problemi di Scoperta

* **Difficoltà nel Localizzare le Istanze**: La ricerca delle istanze di utilizzo di `xpc_connection_get_audit_token` è stata impegnativa, sia staticamente che dinamicamente.
* **Metodologia**: Frida è stata utilizzata per agganciare la funzione `xpc_connection_get_audit_token`, filtrando le chiamate non originate dagli handler degli eventi. Tuttavia, questo metodo era limitato al processo agganciato e richiedeva un utilizzo attivo.
* **Strumenti di Analisi**: Strumenti come IDA/Ghidra sono stati utilizzati per esaminare i servizi mach raggiungibili, ma il processo era lungo e complicato dalle chiamate che coinvolgevano la cache condivisa dyld.
* **Limitazioni degli Script**: I tentativi di scrivere uno script per l'analisi delle chiamate a `xpc_connection_get_audit_token` dai blocchi `dispatch_async` sono stati ostacolati dalle complessità nel parsing dei blocchi e dalle interazioni con la cache condivisa dyld.

## La correzione <a href="#the-fix" id="the-fix"></a>

* **Segnalazione dei Problemi**: È stata inviata una segnalazione ad Apple dettagliando i problemi generali e specifici trovati all'interno di `smd`.
* **Risposta di Apple**: Apple ha affrontato il problema in `smd` sostituendo `xpc_connection_get_audit_token` con `xpc_dictionary_get_audit_token`.
* **Natura della Correzione**: La funzione `xpc_dictionary_get_audit_token` è considerata sicura poiché recupera il token di audit direttamente dal messaggio mach legato al messaggio XPC ricevuto. Tuttavia, non fa parte dell'API pubblica, simile a `xpc_connection_get_audit_token`.
* **Assenza di una Correzione Più Ampia**: Non è chiaro perché Apple non abbia implementato una correzione più completa, come scartare i messaggi che non si allineano al token di audit salvato della connessione. La possibilità di cambiamenti legittimi del token di audit in determinati scenari (ad esempio, l'uso di `setuid`) potrebbe essere un fattore.
* **Stato Attuale**: Il problema persiste in iOS 17 e macOS 14, rappresentando una sfida per coloro che cercano di identificarlo e comprenderlo.
