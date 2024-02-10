# Iniezione di thread su macOS tramite porta di attività

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Codice

* [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
* [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)


## 1. Hijacking del thread

Inizialmente, la funzione **`task_threads()`** viene invocata sulla porta del task per ottenere un elenco di thread dal task remoto. Viene selezionato un thread da dirottare. Questo approccio si discosta dai metodi di iniezione di codice convenzionali in quanto la creazione di un nuovo thread remoto è vietata a causa della nuova mitigazione che blocca `thread_create_running()`.

Per controllare il thread, viene chiamata la funzione **`thread_suspend()`**, interrompendo la sua esecuzione.

Le uniche operazioni consentite sul thread remoto riguardano l'**arresto** e l'**avvio** dello stesso, il **recupero** e la **modifica** dei suoi valori di registro. Le chiamate di funzione remote vengono avviate impostando i registri `x0` a `x7` agli **argomenti**, configurando **`pc`** per puntare alla funzione desiderata e attivando il thread. Per garantire che il thread non si blocchi dopo il ritorno, è necessario rilevare il ritorno.

Una strategia prevede la **registrazione di un gestore di eccezioni** per il thread remoto utilizzando `thread_set_exception_ports()`, impostando il registro `lr` su un indirizzo non valido prima della chiamata alla funzione. Ciò provoca un'eccezione dopo l'esecuzione della funzione, inviando un messaggio alla porta delle eccezioni, consentendo l'ispezione dello stato del thread per recuperare il valore di ritorno. In alternativa, come adottato dall'exploit triple\_fetch di Ian Beer, `lr` viene impostato per eseguire un loop all'infinito. I registri del thread vengono quindi monitorati continuamente fino a quando **`pc` punta a quell'istruzione**.

## 2. Porte Mach per la comunicazione

La fase successiva prevede l'instaurazione di porte Mach per facilitare la comunicazione con il thread remoto. Queste porte sono fondamentali per il trasferimento di diritti di invio e ricezione arbitrari tra i task.

Per la comunicazione bidirezionale, vengono create due porte Mach di ricezione: una nel task locale e l'altra nel task remoto. Successivamente, viene trasferito un diritto di invio per ogni porta al task corrispondente, consentendo lo scambio di messaggi.

Concentrandosi sulla porta locale, il diritto di ricezione è detenuto dal task locale. La porta viene creata con `mach_port_allocate()`. La sfida consiste nel trasferire un diritto di invio a questa porta nel task remoto.

Una strategia prevede di sfruttare `thread_set_special_port()` per inserire un diritto di invio alla porta locale nella `THREAD_KERNEL_PORT` del thread remoto. Quindi, viene istruito il thread remoto a chiamare `mach_thread_self()` per recuperare il diritto di invio.

Per la porta remota, il processo è essenzialmente invertito. Al thread remoto viene indicato di generare una porta Mach tramite `mach_reply_port()` (poiché `mach_port_allocate()` non è adatto a causa del suo meccanismo di restituzione). Dopo la creazione della porta, viene invocato `mach_port_insert_right()` nel thread remoto per stabilire un diritto di invio. Questo diritto viene quindi nascosto nel kernel utilizzando `thread_set_special_port()`. Nel task locale, viene utilizzato `thread_get_special_port()` sul thread remoto per acquisire un diritto di invio alla nuova porta Mach allocata nel task remoto.

Il completamento di questi passaggi porta all'instaurazione di porte Mach, gettando le basi per la comunicazione bidirezionale.

## 3. Primitive di base per la lettura/scrittura di memoria

In questa sezione, l'attenzione è rivolta all'utilizzo della primitiva di esecuzione per stabilire primitive di base per la lettura e la scrittura di memoria. Questi passaggi iniziali sono cruciali per ottenere un maggiore controllo sul processo remoto, anche se le primitive in questa fase non serviranno a molti scopi. Presto, saranno aggiornate a versioni più avanzate.

### Lettura e scrittura di memoria utilizzando la primitiva di esecuzione

L'obiettivo è eseguire la lettura e la scrittura di memoria utilizzando funzioni specifiche. Per la lettura della memoria, vengono utilizzate funzioni che assomigliano alla seguente struttura:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
E per scrivere in memoria, vengono utilizzate funzioni simili a questa struttura:
```c
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
Queste funzioni corrispondono alle istruzioni assembly fornite:
```
_read_func:
ldr x0, [x0]
ret
_write_func:
str x1, [x0]
ret
```
### Identificazione delle funzioni adatte

Una scansione delle librerie comuni ha rivelato candidati appropriati per queste operazioni:

1. **Lettura della memoria:**
La funzione `property_getName()` della [libreria Objective-C runtime](https://opensource.apple.com/source/objc4/objc4-723/runtime/objc-runtime-new.mm.auto.html) è identificata come una funzione adatta per la lettura della memoria. La funzione è descritta di seguito:
```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```
Questa funzione agisce efficacemente come la `read_func` restituendo il primo campo di `objc_property_t`.

2. **Scrittura di memoria:**
Trovare una funzione predefinita per la scrittura di memoria è più difficile. Tuttavia, la funzione `_xpc_int64_set_value()` di libxpc è un candidato adatto con la seguente disassemblazione:
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
Per eseguire una scrittura a 64 bit in un indirizzo specifico, la chiamata remota è strutturata come segue:
```c
_xpc_int64_set_value(address - 0x18, value)
```
Con queste primitive stabilite, il palcoscenico è pronto per creare una memoria condivisa, segnando un significativo progresso nel controllo del processo remoto.

## 4. Configurazione della memoria condivisa

L'obiettivo è stabilire una memoria condivisa tra i task locali e remoti, semplificando il trasferimento dei dati e agevolando la chiamata di funzioni con argomenti multipli. L'approccio prevede di sfruttare `libxpc` e il suo tipo di oggetto `OS_xpc_shmem`, che si basa su voci di memoria Mach.

### Panoramica del processo:

1. **Assegnazione della memoria**:
- Assegnare la memoria per la condivisione utilizzando `mach_vm_allocate()`.
- Utilizzare `xpc_shmem_create()` per creare un oggetto `OS_xpc_shmem` per la regione di memoria allocata. Questa funzione gestirà la creazione dell'entry di memoria Mach e memorizzerà il diritto di invio Mach all'offset `0x18` dell'oggetto `OS_xpc_shmem`.

2. **Creazione della memoria condivisa nel processo remoto**:
- Allocare memoria per l'oggetto `OS_xpc_shmem` nel processo remoto con una chiamata remota a `malloc()`.
- Copiare il contenuto dell'oggetto `OS_xpc_shmem` locale nel processo remoto. Tuttavia, questa copia iniziale avrà nomi di entry di memoria Mach errati all'offset `0x18`.

3. **Correzione dell'entry di memoria Mach**:
- Utilizzare il metodo `thread_set_special_port()` per inserire un diritto di invio per l'entry di memoria Mach nel task remoto.
- Correggere il campo dell'entry di memoria Mach all'offset `0x18` sovrascrivendolo con il nome dell'entry di memoria remota.

4. **Finalizzazione della configurazione della memoria condivisa**:
- Validare l'oggetto `OS_xpc_shmem` remoto.
- Stabilire la mappatura della memoria condivisa con una chiamata remota a `xpc_shmem_remote()`.

Seguendo questi passaggi, la memoria condivisa tra i task locali e remoti verrà configurata in modo efficiente, consentendo trasferimenti di dati semplici e l'esecuzione di funzioni che richiedono argomenti multipli.

## Esempi di codice aggiuntivi

Per l'allocazione della memoria e la creazione dell'oggetto di memoria condivisa:
```c
mach_vm_allocate();
xpc_shmem_create();
```
Per creare e correggere l'oggetto di memoria condivisa nel processo remoto:
```c
malloc(); // for allocating memory remotely
thread_set_special_port(); // for inserting send right
```
Ricorda di gestire correttamente i dettagli delle porte Mach e dei nomi delle voci di memoria per garantire il corretto funzionamento della configurazione della memoria condivisa.


## 5. Ottenere il pieno controllo

Una volta stabilita con successo la memoria condivisa e acquisita la capacità di esecuzione arbitraria, abbiamo essenzialmente ottenuto il pieno controllo sul processo target. Le funzionalità chiave che consentono questo controllo sono:

1. **Operazioni di memoria arbitrarie**:
- Eseguire letture di memoria arbitrarie invocando `memcpy()` per copiare dati dalla regione condivisa.
- Eseguire scritture di memoria arbitrarie utilizzando `memcpy()` per trasferire dati alla regione condivisa.

2. **Gestione delle chiamate di funzione con argomenti multipli**:
- Per le funzioni che richiedono più di 8 argomenti, disporre gli argomenti aggiuntivi nello stack in conformità con la convenzione di chiamata.

3. **Trasferimento di porte Mach**:
- Trasferire porte Mach tra task tramite messaggi Mach tramite porte precedentemente stabilite.

4. **Trasferimento di descrittori di file**:
- Trasferire descrittori di file tra processi utilizzando fileport, una tecnica evidenziata da Ian Beer in `triple_fetch`.

Questo controllo completo è racchiuso nella libreria [threadexec](https://github.com/bazad/threadexec), che fornisce un'implementazione dettagliata e un'API user-friendly per l'interazione con il processo vittima.

## Considerazioni importanti:

- Assicurarsi di utilizzare correttamente `memcpy()` per le operazioni di lettura/scrittura di memoria al fine di mantenere la stabilità del sistema e l'integrità dei dati.
- Quando si trasferiscono porte Mach o descrittori di file, seguire i protocolli appropriati e gestire le risorse in modo responsabile per evitare perdite o accessi non intenzionali.

Seguendo queste linee guida e utilizzando la libreria `threadexec`, è possibile gestire ed interagire con i processi a un livello granulare, ottenendo il pieno controllo sul processo target.

## Riferimenti
* [https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
