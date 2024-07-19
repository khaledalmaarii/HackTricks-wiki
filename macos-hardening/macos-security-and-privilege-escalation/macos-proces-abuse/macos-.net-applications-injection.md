# macOS .Net Applications Injection

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

**Ovo je sažetak posta [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/). Proverite ga za dalje detalje!**

## .NET Core Debugging <a href="#net-core-debugging" id="net-core-debugging"></a>

### **Usmeravanje Debugging Sesije** <a href="#net-core-debugging" id="net-core-debugging"></a>

Upravljanje komunikacijom između debagera i debuggee u .NET-u se vrši putem [**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp). Ova komponenta postavlja dve imenovane cevi po .NET procesu, kao što se može videti u [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127), koje se iniciraju putem [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27). Ove cevi su sa sufiksima **`-in`** i **`-out`**.

Posetom korisničkom **`$TMPDIR`**, mogu se pronaći debugging FIFO-ovi dostupni za debugging .Net aplikacija.

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259) je odgovoran za upravljanje komunikacijom iz debagera. Da bi se započela nova debugging sesija, debager mora poslati poruku putem `out` cevi koja počinje sa `MessageHeader` strukturom, detaljno opisanu u .NET izvoru:
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
Da biste zatražili novu sesiju, ova struktura se popunjava na sledeći način, postavljajući tip poruke na `MT_SessionRequest` i verziju protokola na trenutnu verziju:
```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Configure the message type and version
sSendHeader.m_eType = MT_SessionRequest;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```
Ova glava se zatim šalje cilju koristeći `write` syscall, nakon čega sledi `sessionRequestData` struktura koja sadrži GUID za sesiju:
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
Operacija čitanja na `out` cevi potvrđuje uspeh ili neuspeh uspostavljanja sesije debagovanja:
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## Читање Мемоарије
Када се успостави сесија дебаговања, меморија се може читати користећи [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896) тип поруке. Функција readMemory је детаљно објашњена, извршавајући неопходне кораке за слање захтева за читање и преузимање одговора:
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
Kompletan dokaz koncepta (POC) je dostupan [ovde](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b).

## Pisanje u Memoriju

Slično tome, memorija se može pisati koristeći funkciju `writeMemory`. Proces uključuje postavljanje tipa poruke na `MT_WriteMemory`, određivanje adrese i dužine podataka, a zatim slanje podataka:
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
Povezani POC je dostupan [ovde](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5).

## .NET Core Izvršavanje Koda <a href="#net-core-code-execution" id="net-core-code-execution"></a>

Da bi se izvršio kod, potrebno je identifikovati memorijsku oblast sa rwx dozvolama, što se može uraditi koristeći vmmap -pages:
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
Lociranje mesta za prepisivanje pokazivača funkcije je neophodno, a u .NET Core, to se može uraditi ciljanjem na **Dynamic Function Table (DFT)**. Ova tabela, detaljno opisana u [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h), koristi se od strane runtime-a za JIT kompajlaciju pomoćnih funkcija.

Za x64 sisteme, pretraživanje potpisa može se koristiti za pronalaženje reference na simbol `_hlpDynamicFuncTable` u `libcorclr.dll`.

Debugger funkcija `MT_GetDCB` pruža korisne informacije, uključujući adresu pomoćne funkcije, `m_helperRemoteStartAddr`, koja ukazuje na lokaciju `libcorclr.dll` u memoriji procesa. Ova adresa se zatim koristi za započinjanje pretrage za DFT i prepisivanje pokazivača funkcije sa adresom shellcode-a.

Puni POC kod za injekciju u PowerShell je dostupan [ovde](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6).

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
