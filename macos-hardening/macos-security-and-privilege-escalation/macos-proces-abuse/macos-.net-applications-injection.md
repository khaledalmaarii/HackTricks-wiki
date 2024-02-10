# macOS .Net Anwendungen Injection

<details>

<summary>Lernen Sie AWS-Hacking von Grund auf mit <a href="https://training.hacktricks.xyz/courses/arte">htARTE (HackTricks AWS Red Team Expert)</a>!</summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

- Wenn Sie Ihr Unternehmen in HackTricks bewerben möchten oder HackTricks als PDF herunterladen möchten, überprüfen Sie die [ABONNEMENTPLÄNE](https://github.com/sponsors/carlospolop)!
- Holen Sie sich das offizielle PEASS & HackTricks-Merchandise
- Entdecken Sie die PEASS-Familie, unsere Sammlung exklusiver NFTs
- Treten Sie der Discord-Gruppe oder der Telegram-Gruppe bei oder folgen Sie uns auf Twitter @carlospolopm.
- Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die HackTricks- und HackTricks Cloud-GitHub-Repositories senden.

</details>

**Dies ist eine Zusammenfassung des Beitrags [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/). Überprüfen Sie ihn für weitere Details!**

## .NET Core Debugging <a href="#net-core-debugging" id="net-core-debugging"></a>

### **Einrichten einer Debugging-Sitzung** <a href="#net-core-debugging" id="net-core-debugging"></a>

Die Kommunikation zwischen Debugger und Debuggee in .NET wird von [**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp) verwaltet. Dieses Komponente richtet pro .NET-Prozess zwei benannte Pipes ein, wie in [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127) zu sehen ist, die über [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27) initiiert werden. Diese Pipes sind mit **`-in`** und **`-out`** suffixiert.

Wenn man das Verzeichnis **`$TMPDIR`** des Benutzers besucht, findet man Debugging-FIFOs, die für das Debuggen von .Net-Anwendungen verfügbar sind.

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259) ist für die Verwaltung der Kommunikation von einem Debugger verantwortlich. Um eine neue Debugging-Sitzung zu starten, muss ein Debugger eine Nachricht über die `out`-Pipe senden, die mit einer `MessageHeader`-Struktur beginnt, die im .NET-Quellcode detailliert beschrieben ist:
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
Um eine neue Sitzung anzufordern, wird diese Struktur wie folgt ausgefüllt, wobei der Nachrichtentyp auf `MT_SessionRequest` und die Protokollversion auf die aktuelle Version gesetzt wird:
```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Configure the message type and version
sSendHeader.m_eType = MT_SessionRequest;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```
Dieser Header wird dann über das `write`-Syscall an das Ziel gesendet, gefolgt von der `sessionRequestData`-Struktur, die eine GUID für die Sitzung enthält:
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
Eine Leseoperation auf der `out`-Pipe bestätigt den Erfolg oder Misserfolg des Debugging-Sitzungsaufbaus:
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## Lesen des Speichers
Sobald eine Debugging-Sitzung hergestellt ist, kann der Speicher mithilfe des [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896)-Nachrichtentyps gelesen werden. Die Funktion `readMemory` ist detailliert beschrieben und führt die erforderlichen Schritte aus, um eine Leseanfrage zu senden und die Antwort abzurufen:
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
Der vollständige Proof of Concept (POC) ist [hier](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b) verfügbar.

## Schreiben von Speicher

Ebenso kann Speicher mithilfe der Funktion `writeMemory` geschrieben werden. Der Prozess besteht darin, den Nachrichtentyp auf `MT_WriteMemory` festzulegen, die Adresse und Länge der Daten anzugeben und dann die Daten zu senden:
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
Der dazugehörige POC ist [hier](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5) verfügbar.

## Ausführung von .NET Core-Code <a href="#net-core-code-execution" id="net-core-code-execution"></a>

Um Code auszuführen, muss man einen Speicherbereich mit rwx-Berechtigungen identifizieren, was mit vmmap -pages durchgeführt werden kann:
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
Um eine Stelle zum Überschreiben eines Funktionszeigers zu finden, ist es notwendig, das **Dynamic Function Table (DFT)** in .NET Core anzuzielen. Diese Tabelle, die in [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h) detailliert beschrieben ist, wird vom Laufzeitsystem für JIT-Kompilierungshilfsfunktionen verwendet.

Für x64-Systeme kann die Signatursuche verwendet werden, um eine Referenz auf das Symbol `_hlpDynamicFuncTable` in `libcorclr.dll` zu finden.

Die Debugger-Funktion `MT_GetDCB` liefert nützliche Informationen, einschließlich der Adresse einer Hilfsfunktion, `m_helperRemoteStartAddr`, die den Speicherort von `libcorclr.dll` im Prozessspeicher angibt. Diese Adresse wird dann verwendet, um nach dem DFT zu suchen und einen Funktionszeiger mit der Adresse des Shellcodes zu überschreiben.

Der vollständige POC-Code für die Injektion in PowerShell ist [hier](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6) verfügbar.

## Referenzen

* [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) **bei oder folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) **und** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **GitHub-Repositories senden.**

</details>
