# macOS .Net Uygulamaları Enjeksiyonu

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter**'da **bizi takip edin** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

**Bu, [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/) adresindeki gönderinin bir özetidir. Daha fazla ayrıntı için kontrol edin!**

## .NET Core Hata Ayıklama <a href="#net-core-debugging" id="net-core-debugging"></a>

### **Hata Ayıklama Oturumu Kurma** <a href="#net-core-debugging" id="net-core-debugging"></a>

.NET'te hata ayıklayıcı ile hata ayıklanan arasındaki iletişimin yönetimi [**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp) tarafından yapılmaktadır. Bu bileşen, [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127) adresinde görüldüğü gibi her .NET işlemi için iki adlandırılmış boru hattı kurar ve bunlar [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27) aracılığıyla başlatılır. Bu boru hatları **`-in`** ve **`-out`** ile sonlandırılır.

Kullanıcının **`$TMPDIR`** dizinine giderek, .Net uygulamalarını hata ayıklamak için mevcut olan hata ayıklama FIFO'larını bulabilirsiniz.

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259) hata ayıklayıcıdan gelen iletişimi yönetmekten sorumludur. Yeni bir hata ayıklama oturumu başlatmak için, bir hata ayıklayıcı `out` boru hattı aracılığıyla `MessageHeader` yapısıyla başlayan bir mesaj göndermelidir; bu yapı .NET kaynak kodunda ayrıntılı olarak açıklanmıştır:
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
Yeni bir oturum talep etmek için, bu yapı aşağıdaki gibi doldurulur, mesaj türü `MT_SessionRequest` ve protokol sürümü mevcut sürüm olarak ayarlanır:
```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Configure the message type and version
sSendHeader.m_eType = MT_SessionRequest;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```
Bu başlık daha sonra `write` syscall'ı kullanılarak hedefe gönderilir, ardından oturum için bir GUID içeren `sessionRequestData` yapısı gelir:
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
`out` borusundaki bir okuma işlemi, hata ayıklama oturumu kurulumunun başarıyla tamamlandığını veya başarısız olduğunu doğrular:
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## Belleği Okuma
Bir hata ayıklama oturumu kurulduktan sonra, bellek [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896) mesaj türü kullanılarak okunabilir. readMemory fonksiyonu, bir okuma isteği göndermek ve yanıtı almak için gerekli adımları gerçekleştiren ayrıntılı bir işlemdir:
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
Tam kanıt konsepti (POC) [burada](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b) mevcuttur.

## Belleğe Yazma

Benzer şekilde, bellek `writeMemory` fonksiyonu kullanılarak yazılabilir. Süreç, mesaj türünü `MT_WriteMemory` olarak ayarlamayı, verinin adresini ve uzunluğunu belirtmeyi ve ardından veriyi göndermeyi içerir:
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
İlgili POC [burada](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5) mevcuttur.

## .NET Core Kod Çalıştırma <a href="#net-core-code-execution" id="net-core-code-execution"></a>

Kod çalıştırmak için, rwx izinlerine sahip bir bellek bölgesi tanımlanmalıdır; bu, vmmap -pages: kullanılarak yapılabilir.
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
Bir işlev işaretçisini geçersiz kılmak için bir yer bulmak gereklidir ve .NET Core'da bu, **Dynamic Function Table (DFT)** hedeflenerek yapılabilir. Bu tablo, [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h) dosyasında detaylandırılmıştır ve çalışma zamanı tarafından JIT derleme yardımcı işlevleri için kullanılır.

x64 sistemler için, `_hlpDynamicFuncTable` sembolüne bir referans bulmak için imza avcılığı kullanılabilir `libcorclr.dll` içinde.

`MT_GetDCB` hata ayıklayıcı işlevi, `libcorclr.dll`'nin işlem belleğindeki konumunu gösteren bir yardımcı işlevin adresi olan `m_helperRemoteStartAddr` dahil olmak üzere yararlı bilgiler sağlar. Bu adres daha sonra DFT'yi aramak ve bir işlev işaretçisini shellcode'un adresi ile geçersiz kılmak için kullanılır.

PowerShell'e enjeksiyon için tam POC kodu [buradan](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6) erişilebilir.

## Referanslar

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
