# macOS .Net Toepassingsinspuiting

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

**Hierdie is 'n opsomming van die berig [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/). Kyk daarvoor vir verdere besonderhede!**

## .NET Core-afstelwerk <a href="#net-core-debugging" id="net-core-debugging"></a>

### **Vestiging van 'n afstel-sessie** <a href="#net-core-debugging" id="net-core-debugging"></a>

Die hantering van kommunikasie tussen die afsteler en die afstelobjek in .NET word bestuur deur [**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp). Hierdie komponent stel twee genoemde pype per .NET-proses op soos gesien in [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127), wat geïnisieer word via [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27). Hierdie pype word gesuffix met **`-in`** en **`-out`**.

Deur die gebruiker se **`$TMPDIR`** te besoek, kan daar afstelpype gevind word wat beskikbaar is vir die afstel van .Net-toepassings.

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259) is verantwoordelik vir die bestuur van kommunikasie vanaf 'n afsteler. Om 'n nuwe afstel-sessie te begin, moet 'n afsteler 'n boodskap stuur via die `out`-pyp wat begin met 'n `MessageHeader`-struktuur, wat in die .NET-bronkode in detail beskryf word:
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
Om 'n nuwe sessie aan te vra, word hierdie struktuur soos volg gevul, deur die boodskap tipe te stel as `MT_SessionRequest` en die protokol weergawe as die huidige weergawe:
```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Configure the message type and version
sSendHeader.m_eType = MT_SessionRequest;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```
Hierdie kop is dan oorgestuur na die teiken deur die `write` syscall, gevolg deur die `sessionRequestData` struktuur wat 'n GUID vir die sessie bevat:
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
'n Leesoperasie op die `out` pyp bevestig die sukses of mislukking van die opsporingsessie vestiging:
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## Lees van Geheue
Sodra 'n foutopsporingsessie tot stand gebring is, kan geheue gelees word deur die [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896) boodskapstipe te gebruik. Die funksie readMemory word in detail beskryf en voer die nodige stappe uit om 'n leesversoek te stuur en die antwoord te ontvang:
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
Die volledige bewys van konsep (POC) is beskikbaar [hier](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b).

## Skryf van Geheue

Op dieselfde manier kan geheue geskryf word met behulp van die `writeMemory`-funksie. Die proses behels die instelling van die boodskap tipe na `MT_WriteMemory`, die spesifisering van die adres en lengte van die data, en dan die stuur van die data:
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
Die betrokke POC is beskikbaar [hier](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5).

## .NET Core Kode-uitvoering <a href="#net-core-code-execution" id="net-core-code-execution"></a>

Om kode uit te voer, moet 'n geheuegebied met rwx-permissies geïdentifiseer word, wat gedoen kan word deur gebruik te maak van vmmap -pages:
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
Die opsporing van 'n plek om 'n funksie-aanwyservariabele te oorskryf, is noodsaaklik, en in .NET Core kan dit gedoen word deur die **Dinamiese Funksie Tabel (DFT)** te teiken. Hierdie tabel, wat in [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h) beskryf word, word deur die uitvoeringstyd gebruik vir JIT-samestellingshulpfunksies.

Vir x64-stelsels kan handtekeningsoektog gebruik word om 'n verwysing na die simbool `_hlpDynamicFuncTable` in `libcorclr.dll` te vind.

Die `MT_GetDCB`-ontlederfunksie verskaf nuttige inligting, insluitend die adres van 'n hulpfunksie, `m_helperRemoteStartAddr`, wat die ligging van `libcorclr.dll` in die prosesgeheue aandui. Hierdie adres word dan gebruik om 'n soektog na die DFT te begin en 'n funksie-aanwyser met die adres van die skulpkode te oorskryf.

Die volledige POC-kode vir inspuiting in PowerShell is beskikbaar [hier](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6).

## Verwysings

* [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks in PDF aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
