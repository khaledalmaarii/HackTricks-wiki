# macOS .Net-Anwendungen Injection

{% hint style="success" %}
Lernen & üben Sie AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos senden.

</details>
{% endhint %}

**Dies ist eine Zusammenfassung des Beitrags [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/). Überprüfen Sie ihn für weitere Details!**

## .NET Core Debugging <a href="#net-core-debugging" id="net-core-debugging"></a>

### **Einrichten einer Debugging-Sitzung** <a href="#net-core-debugging" id="net-core-debugging"></a>

Die Handhabung der Kommunikation zwischen Debugger und Debuggee in .NET wird von [**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp) verwaltet. Diese Komponente richtet zwei benannte Pipes pro .NET-Prozess ein, wie in [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127) zu sehen ist, die über [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27) initiiert werden. Diese Pipes sind mit **`-in`** und **`-out`** suffixiert.

Durch den Besuch des **`$TMPDIR`** des Benutzers kann man Debugging-FIFOs finden, die für das Debuggen von .Net-Anwendungen verfügbar sind.

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259) ist verantwortlich für die Verwaltung der Kommunikation von einem Debugger. Um eine neue Debugging-Sitzung zu initiieren, muss ein Debugger eine Nachricht über die `out`-Pipe senden, die mit einer `MessageHeader`-Struktur beginnt, die im .NET-Quellcode detailliert beschrieben ist:
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
Dieser Header wird dann über den `write` syscall an das Ziel gesendet, gefolgt von der `sessionRequestData` Struktur, die eine GUID für die Sitzung enthält:
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
Ein Lesevorgang auf dem `out`-Pipe bestätigt den Erfolg oder Misserfolg der Einrichtung der Debugging-Sitzung:
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## Lesen des Speichers
Sobald eine Debugging-Sitzung eingerichtet ist, kann der Speicher mit dem [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896) Nachrichtentyp gelesen werden. Die Funktion readMemory ist detailliert und führt die notwendigen Schritte aus, um eine Leseanforderung zu senden und die Antwort abzurufen:
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

## Schreiben in den Speicher

Ähnlich kann der Speicher mit der Funktion `writeMemory` beschrieben werden. Der Prozess umfasst das Setzen des Nachrichtentyps auf `MT_WriteMemory`, das Festlegen der Adresse und der Länge der Daten und das anschließende Senden der Daten:
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
Der zugehörige POC ist [hier](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5) verfügbar.

## .NET Core Codeausführung <a href="#net-core-code-execution" id="net-core-code-execution"></a>

Um Code auszuführen, muss man einen Speicherbereich mit rwx-Berechtigungen identifizieren, was mit vmmap -pages: durchgeführt werden kann.
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
Einen Ort zu finden, um einen Funktionszeiger zu überschreiben, ist notwendig, und in .NET Core kann dies durch das Anvisieren der **Dynamic Function Table (DFT)** erfolgen. Diese Tabelle, die in [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h) detailliert beschrieben ist, wird von der Laufzeit für JIT-Kompilierungs-Hilfsfunktionen verwendet.

Für x64-Systeme kann die Signatur-Suche verwendet werden, um einen Verweis auf das Symbol `_hlpDynamicFuncTable` in `libcorclr.dll` zu finden.

Die Debugger-Funktion `MT_GetDCB` liefert nützliche Informationen, einschließlich der Adresse einer Hilfsfunktion, `m_helperRemoteStartAddr`, die den Standort von `libcorclr.dll` im Prozessspeicher angibt. Diese Adresse wird dann verwendet, um eine Suche nach der DFT zu starten und einen Funktionszeiger mit der Adresse des Shellcodes zu überschreiben.

Der vollständige POC-Code für die Injektion in PowerShell ist [hier](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6) zugänglich.

## References

* [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)

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
