# Впровадження додатків .Net для macOS

<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Інші способи підтримки HackTricks:

* Якщо ви хочете побачити вашу **компанію рекламовану на HackTricks** або **завантажити HackTricks у форматі PDF**, перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Отримайте [**офіційний PEASS & HackTricks мерч**](https://peass.creator-spring.com)
* Відкрийте для себе [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Поділіться своїми хакерськими трюками, надсилайте PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) **та** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **репозиторіїв на GitHub**.

</details>

**Це краткий огляд публікації [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/). Перевірте його для отримання додаткових деталей!**

## Відлагодження .NET Core <a href="#net-core-debugging" id="net-core-debugging"></a>

### **Встановлення сеансу відлагодження** <a href="#net-core-debugging" id="net-core-debugging"></a>

Обробка комунікації між відлагоджувачем та відлагоджуваним в .NET керується [**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp). Цей компонент налаштовує два іменовані канали для кожного процесу .NET, як показано в [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127), які ініціюються через [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27). Ці канали мають суфікси **`-in`** та **`-out`**.

Відвідавши **`$TMPDIR`** користувача, можна знайти доступні для відлагодження FIFO для додатків .Net.

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259) відповідає за управління комунікацією від відлагоджувача. Для ініціювання нового сеансу відлагодження відлагоджувач повинен надіслати повідомлення через канал `out`, починаючи з структури `MessageHeader`, детально описаної в вихідному коді .NET:
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
Для запиту нової сесії ця структура заповнюється наступним чином, встановлюючи тип повідомлення на `MT_SessionRequest` та версію протоколу на поточну версію:
```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Configure the message type and version
sSendHeader.m_eType = MT_SessionRequest;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```
Цей заголовок потім надсилається на цільовий об'єкт за допомогою системного виклику `write`, за яким слідує структура `sessionRequestData`, що містить GUID для сеансу:
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
Операція читання на каналі `out` підтверджує успішне або невдачне встановлення сеансу налагодження:
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## Читання пам'яті
Після встановлення сеансу налагодження, пам'ять можна читати за допомогою типу повідомлення [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896). Функція readMemory детально описана, виконуючи необхідні кроки для відправлення запиту на читання та отримання відповіді:
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
Повний доказ концепції (POC) доступний [тут](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b).

## Запис у пам'ять

Аналогічно, пам'ять можна записати за допомогою функції `writeMemory`. Процес включає встановлення типу повідомлення на `MT_WriteMemory`, вказівку адреси та довжини даних, а потім відправлення даних:
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
Асоційований POC доступний [тут](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5).

## Виконання коду .NET Core <a href="#net-core-code-execution" id="net-core-code-execution"></a>

Для виконання коду потрібно ідентифікувати область пам'яті з дозволами rwx, що можна зробити за допомогою vmmap -pages:
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
Знаходження місця для перезапису вказівника функції є необхідним, і в .NET Core це можна зробити, спрямовуючись на **Dynamic Function Table (DFT)**. Ця таблиця, детально описана в [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h), використовується рантаймом для функцій-помічників компіляції JIT.

Для систем x64 можна використовувати пошук сигнатури для знаходження посилання на символ `_hlpDynamicFuncTable` в `libcorclr.dll`.

Функція відладки `MT_GetDCB` надає корисну інформацію, включаючи адресу функції-помічника `m_helperRemoteStartAddr`, що вказує на місце розташування `libcorclr.dll` в пам'яті процесу. Цю адресу потім використовують для початку пошуку DFT та перезапису вказівника функції адресою shellcode.

Повний код POC для впровадження в PowerShell доступний [тут](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6).

## Посилання

* [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)

<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Інші способи підтримки HackTricks:

* Якщо ви хочете побачити **рекламу вашої компанії на HackTricks** або **завантажити HackTricks у PDF**, перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Отримайте [**офіційний мерч PEASS & HackTricks**](https://peass.creator-spring.com)
* Відкрийте для себе [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Поділіться своїми хакерськими трюками, надсилайте PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github репозиторіїв.

</details>
