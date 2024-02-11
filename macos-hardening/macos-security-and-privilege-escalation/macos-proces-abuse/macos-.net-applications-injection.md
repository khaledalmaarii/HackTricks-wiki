# Wstrzykiwanie aplikacji .Net w macOS

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

**To jest streszczenie postu [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/). Sprawdź go, aby uzyskać więcej szczegółów!**

## Debugowanie .NET Core <a href="#net-core-debugging" id="net-core-debugging"></a>

### **Ustanawianie sesji debugowania** <a href="#net-core-debugging" id="net-core-debugging"></a>

Komunikacja między debugerem a debugowanym programem w .NET jest zarządzana przez [**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp). Ten komponent ustawia dwa nazwane potoki dla każdego procesu .NET, jak widać w [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127), które są inicjowane za pomocą [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27). Te potoki mają przyrostki **`-in`** i **`-out`**.

Przez odwiedzenie folderu **`$TMPDIR`** użytkownik może znaleźć dostępne potoki debugowania dla aplikacji .Net.

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259) jest odpowiedzialny za zarządzanie komunikacją z debugerem. Aby rozpocząć nową sesję debugowania, debuger musi wysłać wiadomość za pomocą potoku `out`, zaczynając od struktury `MessageHeader`, szczegółowo opisanej w kodzie źródłowym .NET:
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
Aby poprosić o nową sesję, ta struktura jest wypełniana w następujący sposób, ustawiając typ wiadomości na `MT_SessionRequest` i wersję protokołu na bieżącą wersję:
```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Configure the message type and version
sSendHeader.m_eType = MT_SessionRequest;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```
Ten nagłówek jest następnie wysyłany do celu za pomocą wywołania systemowego `write`, a następnie struktura `sessionRequestData` zawierająca GUID sesji:
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
Operacja odczytu na rurze `out` potwierdza powodzenie lub niepowodzenie ustanowienia sesji debugowania:
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## Odczytywanie pamięci
Po ustanowieniu sesji debugowania, pamięć można odczytać za pomocą typu wiadomości [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896). Funkcja readMemory jest szczegółowo opisana i wykonuje niezbędne kroki, aby wysłać żądanie odczytu i odebrać odpowiedź:
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
Pełny dowód koncepcji (POC) jest dostępny [tutaj](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b).

## Zapisywanie do pamięci

Podobnie, pamięć można zapisać za pomocą funkcji `writeMemory`. Proces polega na ustawieniu typu wiadomości na `MT_WriteMemory`, określeniu adresu i długości danych, a następnie wysłaniu danych:
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
Powiązany POC jest dostępny [tutaj](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5).

## Wykonanie kodu .NET Core <a href="#net-core-code-execution" id="net-core-code-execution"></a>

Aby wykonać kod, należy zidentyfikować obszar pamięci z uprawnieniami rwx, co można zrobić za pomocą polecenia vmmap -pages:
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
Zlokalizowanie miejsca do nadpisania wskaźnika funkcji jest konieczne, a w .NET Core można to zrobić, docelowo kierując się do **Dynamic Function Table (DFT)**. Ta tabela, szczegółowo opisana w [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h), jest używana przez środowisko wykonawcze do funkcji pomocniczych kompilacji JIT.

Dla systemów x64 można użyć metody poszukiwania sygnatury, aby znaleźć odniesienie do symbolu `_hlpDynamicFuncTable` w `libcorclr.dll`.

Funkcja debugera `MT_GetDCB` dostarcza przydatnych informacji, w tym adresu funkcji pomocniczej `m_helperRemoteStartAddr`, wskazującego na lokalizację `libcorclr.dll` w pamięci procesu. Ten adres jest następnie używany do rozpoczęcia poszukiwania DFT i nadpisania wskaźnika funkcji adresem kodu shell.

Pełny kod POC do wstrzykiwania w PowerShell jest dostępny [tutaj](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6).

## Odwołania

* [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Uzyskaj [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi trikami hakerskimi, przesyłając PR do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
