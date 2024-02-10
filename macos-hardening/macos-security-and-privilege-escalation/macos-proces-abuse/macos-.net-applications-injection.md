# Iniezione di applicazioni .Net su macOS

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

**Questo è un riassunto del post [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/). Consultalo per ulteriori dettagli!**

## Debugging di .NET Core <a href="#net-core-debugging" id="net-core-debugging"></a>

### **Avvio di una sessione di debug** <a href="#net-core-debugging" id="net-core-debugging"></a>

La gestione della comunicazione tra il debugger e il debuggee in .NET è gestita da [**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp). Questo componente configura due named pipe per ogni processo .NET, come si può vedere in [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127), che vengono iniziate tramite [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27). Queste pipe sono suffisse con **`-in`** e **`-out`**.

Visitando la directory **`$TMPDIR`** dell'utente, è possibile trovare FIFO di debug disponibili per le applicazioni .Net.

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259) è responsabile della gestione della comunicazione da parte di un debugger. Per avviare una nuova sessione di debug, un debugger deve inviare un messaggio tramite la pipe `out` che inizia con una struttura `MessageHeader`, dettagliata nel codice sorgente di .NET:
```c
struct MessageHeader {
MessageType   m_eType;        // Message type
DWORD         m_cbDataBlock;  // Size of following data block (can be zero)
DWORD         m_dwId;         // Message ID from sender
DWORD         m_dwReplyId;    // Reply-to Message ID
DWORD         m_dwLastSeenId; // Last seen Message ID by sender
DWORD         m_dwReserved;   // Reserved for future (initialize to zero)
union {
struct {
DWORD         m_dwMajorVersion;   // Requested/accepted protocol version
DWORD         m_dwMinorVersion;
} VersionInfo;
...
} TypeSpecificData;
BYTE          m_sMustBeZero[8];
}
```
Per richiedere una nuova sessione, questa struttura viene popolata nel seguente modo, impostando il tipo di messaggio su `MT_SessionRequest` e la versione del protocollo alla versione corrente:
```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Configure the message type and version
sSendHeader.m_eType = MT_SessionRequest;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```
Quest'intestazione viene quindi inviata al target utilizzando la chiamata di sistema `write`, seguita dalla struttura `sessionRequestData` che contiene un GUID per la sessione:
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
Un'operazione di lettura sul tubo `out` conferma il successo o il fallimento dell'instaurazione della sessione di debug:
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## Lettura della memoria
Una volta stabilita una sessione di debug, la memoria può essere letta utilizzando il tipo di messaggio [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896). La funzione readMemory è dettagliata, eseguendo i passaggi necessari per inviare una richiesta di lettura e recuperare la risposta:
```c
bool readMemory(void *addr, int len, unsigned char **output) {
// Allocation and initialization
...
// Write header and read response
...
// Read the memory from the debuggee
...
return true;
}
```
La prova di concetto (POC) completa è disponibile [qui](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b).

## Scrittura in memoria

Allo stesso modo, la memoria può essere scritta utilizzando la funzione `writeMemory`. Il processo prevede di impostare il tipo di messaggio su `MT_WriteMemory`, specificare l'indirizzo e la lunghezza dei dati, e quindi inviare i dati:
```c
bool writeMemory(void *addr, int len, unsigned char *input) {
// Increment IDs, set message type, and specify memory location
...
// Write header and data, then read the response
...
// Confirm memory write was successful
...
return true;
}
```
Il POC associato è disponibile [qui](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5).

## Esecuzione del codice .NET Core <a href="#net-core-code-execution" id="net-core-code-execution"></a>

Per eseguire il codice, è necessario identificare una regione di memoria con le autorizzazioni rwx, che può essere fatto utilizzando vmmap -pages:
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
È necessario individuare un punto in cui sovrascrivere un puntatore a una funzione e, in .NET Core, ciò può essere fatto mirando alla **Dynamic Function Table (DFT)**. Questa tabella, descritta in [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h), viene utilizzata dal runtime per le funzioni helper di compilazione JIT.

Per i sistemi x64, è possibile utilizzare la ricerca della firma per trovare un riferimento al simbolo `_hlpDynamicFuncTable` in `libcorclr.dll`.

La funzione di debug `MT_GetDCB` fornisce informazioni utili, tra cui l'indirizzo di una funzione helper, `m_helperRemoteStartAddr`, che indica la posizione di `libcorclr.dll` nella memoria del processo. Questo indirizzo viene quindi utilizzato per avviare una ricerca della DFT e sovrascrivere un puntatore a una funzione con l'indirizzo del codice shell.

Il codice POC completo per l'iniezione in PowerShell è accessibile [qui](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6).

## Riferimenti

* [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository github di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
