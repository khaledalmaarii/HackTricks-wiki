# Attacco xpc\_connection\_get\_audit\_token su macOS

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

**Per ulteriori informazioni consulta il post originale: [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)**. Questo è un riassunto:


## Informazioni di base su Mach Messages

Se non sai cosa sono le Mach Messages, inizia controllando questa pagina:

{% content-ref url="../../../../mac-os-architecture/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../../../../mac-os-architecture/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

Per il momento ricorda che ([definizione da qui](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Le Mach Messages vengono inviate su una _porta Mach_, che è un canale di comunicazione **singolo ricevitore, multiplo mittente** incorporato nel kernel Mach. **Più processi possono inviare messaggi** a una porta Mach, ma in ogni momento **solo un singolo processo può leggerne**. Proprio come i descrittori di file e le socket, le porte Mach vengono allocate e gestite dal kernel e i processi vedono solo un numero intero, che possono utilizzare per indicare al kernel quale delle loro porte Mach desiderano utilizzare.

## Connessione XPC

Se non sai come viene stabilita una connessione XPC, controlla:

{% content-ref url="../" %}
[..](../)
{% endcontent-ref %}

## Riassunto della vulnerabilità

Ciò che è interessante sapere è che **l'astrazione di XPC è una connessione uno a uno**, ma si basa su una tecnologia che **può avere più mittenti, quindi**:

* Le porte Mach sono singolo ricevitore, **multiplo mittente**.
* Il token di audit di una connessione XPC è il token di audit **copiato dal messaggio ricevuto più di recente**.
* Ottenere il **token di audit** di una connessione XPC è fondamentale per molti **controlli di sicurezza**.

Anche se la situazione precedente sembra promettente, ci sono alcuni scenari in cui ciò non causerà problemi ([da qui](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

* I token di audit vengono spesso utilizzati per un controllo di autorizzazione per decidere se accettare una connessione. Poiché ciò avviene utilizzando un messaggio alla porta di servizio, **non è ancora stata stabilita una connessione**. Altri messaggi su questa porta verranno semplicemente gestiti come richieste di connessione aggiuntive. Quindi **i controlli prima di accettare una connessione non sono vulnerabili** (ciò significa anche che all'interno di `-listener:shouldAcceptNewConnection:` il token di audit è sicuro). Stiamo quindi **cercando connessioni XPC che verifichino azioni specifiche**.
* Gli event handler XPC vengono gestiti in modo sincrono. Ciò significa che l'event handler per un messaggio deve essere completato prima di chiamarlo per il successivo, anche su code di invio simultaneo. Quindi all'interno di un **event handler XPC il token di audit non può essere sovrascritto** da altri messaggi normali (non di risposta!).

Ci sono due diversi metodi con cui ciò potrebbe essere sfruttato:

1. Variante 1:
* L'**exploit** si **connette** al servizio **A** e al servizio **B**.
* Il servizio **B** può chiamare una **funzionalità privilegiata** in servizio A a cui l'utente non può accedere.
* Il servizio **A** chiama **`xpc_connection_get_audit_token`** mentre **non è** all'interno dell'**event handler** per una connessione in un **`dispatch_async`**.
* Quindi un **messaggio diverso** potrebbe **sovrascrivere il Token di Audit** perché viene inviato in modo asincrono al di fuori dell'event handler.
* L'exploit passa a **servizio B il diritto di invio a servizio A**.
* Quindi svc **B** invierà effettivamente i messaggi a servizio **A**.
* L'**exploit** cerca di **chiamare l'azione privilegiata**. In un RC svc **A verifica** l'autorizzazione di questa **azione** mentre **svc B sovrascrive il Token di Audit** (dando all'exploit l'accesso per chiamare l'azione privilegiata).
2. Variante 2:
* Il servizio **B** può chiamare una **funzionalità privilegiata** in servizio A a cui l'utente non può accedere.
* L'exploit si connette con **servizio A** che **invia** all'exploit un **messaggio che si aspetta una risposta** in una specifica **porta di risposta**.
* L'exploit invia al **servizio B** un messaggio passando **quella porta di risposta**.
* Quando il servizio **B risponde**, invia il messaggio a servizio **A**, **mentre** l'**exploit** invia un messaggio diverso a servizio A cercando di **raggiungere una funzionalità privilegiata** e aspettando che la risposta da servizio B sovrascriva il Token di Audit nel momento perfetto (Race Condition).

## Variante 1: chiamare xpc\_connection\_get\_audit\_token al di fuori di un event handler <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Scenario:

* Due servizi Mach **`A`** e **`B`** a cui possiamo entrambi connetterci (in base al profilo sandbox e ai controlli di autorizzazione prima di accettare la connessione).
* _**A**_ deve avere un **controllo di autorizzazione** per un'azione specifica che **`B`** può superare (ma la nostra app non può).
* Ad esempio, se B ha alcuni **entitlements** o viene eseguito come **root**, potrebbe consentirgli di chiedere ad A di eseguire un'azione privilegiata.
* Per questo controllo di autorizzazione, **`A`** ottiene il token di audit in modo asincrono, ad esempio chiam
4. Il passo successivo prevede di istruire `diagnosticd` ad avviare il monitoraggio di un processo scelto (potenzialmente quello dell'utente). Contestualmente, viene inviata una serie di messaggi di routine 1004 a `smd`. L'intento qui è quello di installare uno strumento con privilegi elevati.
5. Questa azione scatena una condizione di gara all'interno della funzione `handle_bless`. Il tempismo è critico: la chiamata alla funzione `xpc_connection_get_pid` deve restituire l'ID del processo dell'utente (poiché lo strumento privilegiato risiede nel bundle dell'app dell'utente). Tuttavia, la funzione `xpc_connection_get_audit_token`, in particolare all'interno della subroutine `connection_is_authorized`, deve fare riferimento al token di audit appartenente a `diagnosticd`.

## Variante 2: inoltro delle risposte

In un ambiente di comunicazione tra processi XPC (Cross-Process Communication), sebbene gli event handler non vengano eseguiti contemporaneamente, la gestione dei messaggi di risposta ha un comportamento unico. In particolare, esistono due metodi distinti per l'invio di messaggi che si aspettano una risposta:

1. **`xpc_connection_send_message_with_reply`**: Qui, il messaggio XPC viene ricevuto e elaborato in una coda designata.
2. **`xpc_connection_send_message_with_reply_sync`**: Al contrario, in questo metodo, il messaggio XPC viene ricevuto e elaborato nella coda di dispatch corrente.

Questa distinzione è cruciale perché consente la possibilità di **analizzare i pacchetti di risposta contemporaneamente all'esecuzione di un event handler XPC**. In particolare, sebbene `_xpc_connection_set_creds` implementi un blocco per proteggere da sovrascritture parziali del token di audit, non estende questa protezione all'intero oggetto di connessione. Di conseguenza, si crea una vulnerabilità in cui il token di audit può essere sostituito durante l'intervallo tra l'analisi di un pacchetto e l'esecuzione del suo event handler.

Per sfruttare questa vulnerabilità, è necessaria la seguente configurazione:

- Due servizi mach, denominati **`A`** e **`B`**, entrambi in grado di stabilire una connessione.
- Il servizio **`A`** dovrebbe includere un controllo di autorizzazione per un'azione specifica che solo **`B`** può eseguire (l'applicazione dell'utente non può).
- Il servizio **`A`** dovrebbe inviare un messaggio che si aspetta una risposta.
- L'utente può inviare un messaggio a **`B`** a cui risponderà.

Il processo di sfruttamento prevede i seguenti passaggi:

1. Attendere che il servizio **`A`** invii un messaggio che si aspetta una risposta.
2. Invece di rispondere direttamente a **`A`**, la porta di risposta viene dirottata e utilizzata per inviare un messaggio a **`B`**.
3. Successivamente, viene inviato un messaggio che coinvolge l'azione vietata, con l'aspettativa che venga elaborato contemporaneamente alla risposta da **`B`**.

Di seguito è riportata una rappresentazione visiva dello scenario di attacco descritto:

![https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png](../../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1).png)


<figure><img src="../../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Problemi di scoperta

- **Difficoltà nella localizzazione delle istanze**: La ricerca delle istanze di utilizzo di `xpc_connection_get_audit_token` è stata difficile, sia staticamente che dinamicamente.
- **Metodologia**: È stato utilizzato Frida per agganciare la funzione `xpc_connection_get_audit_token`, filtrando le chiamate non originate dagli event handler. Tuttavia, questo metodo era limitato al processo agganciato e richiedeva un utilizzo attivo.
- **Strumenti di analisi**: Sono stati utilizzati strumenti come IDA/Ghidra per esaminare i servizi mach raggiungibili, ma il processo è stato lungo e complicato dalle chiamate che coinvolgono la cache condivisa dyld.
- **Limitazioni degli script**: I tentativi di scrivere uno script per l'analisi delle chiamate a `xpc_connection_get_audit_token` dai blocchi `dispatch_async` sono stati ostacolati dalla complessità del parsing dei blocchi e dalle interazioni con la cache condivisa dyld.

## La soluzione <a href="#the-fix" id="the-fix"></a>

- **Segnalazione dei problemi**: È stata inviata una segnalazione ad Apple in cui sono stati descritti i problemi generali e specifici riscontrati in `smd`.
- **Risposta di Apple**: Apple ha risolto il problema in `smd` sostituendo `xpc_connection_get_audit_token` con `xpc_dictionary_get_audit_token`.
- **Natura della soluzione**: La funzione `xpc_dictionary_get_audit_token` è considerata sicura in quanto recupera direttamente il token di audit dal messaggio mach legato al messaggio XPC ricevuto. Tuttavia, non fa parte dell'API pubblica, come `xpc_connection_get_audit_token`.
- **Assenza di una soluzione più ampia**: Non è chiaro perché Apple non abbia implementato una soluzione più completa, come scartare i messaggi che non corrispondono al token di audit salvato della connessione. La possibilità di modifiche legittime al token di audit in determinati scenari (ad esempio, l'uso di `setuid`) potrebbe essere un fattore.
- **Stato attuale**: Il problema persiste in iOS 17 e macOS 14, rappresentando una sfida per coloro che cercano di identificarlo e comprenderlo.

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) **e** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
