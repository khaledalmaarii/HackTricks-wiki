# macOS .Net Uygulamaları Enjeksiyonu

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahramana dönüştürmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek** paylaşın.

</details>

**Bu, [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/) adresindeki yazının özeti. Daha fazla ayrıntı için kontrol edin!**

## .NET Core Hata Ayıklama <a href="#net-core-debugging" id="net-core-debugging"></a>

### **Bir Hata Ayıklama Oturumu Kurma** <a href="#net-core-debugging" id="net-core-debugging"></a>

.NET'te hata ayıklama aracı ve hata ayıklanan arasındaki iletişim [**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp) tarafından yönetilir. Bu bileşen, her .NET işlemi için [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127) adresinde görüldüğü gibi iki adet isimlendirilmiş pipe kurar. Bu borular **`-in`** ve **`-out`** ile sonlandırılır.

Kullanıcının **`$TMPDIR`**'sini ziyaret ederek, .Net uygulamalarını hata ayıklamak için kullanılabilen hata ayıklama FIFO'larını bulabilirsiniz.

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259), bir hata ayıklama aracından gelen iletişimi yönetmekten sorumludur. Yeni bir hata ayıklama oturumu başlatmak için, bir hata ayıklama aracı, .NET kaynak kodunda detayları verilen `MessageHeader` yapısını içeren bir mesajı `out` boruya göndermelidir:
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
Yeni bir oturum isteği yapmak için, bu yapı aşağıdaki gibi doldurulur, mesaj türü `MT_SessionRequest` olarak ve protokol sürümü mevcut sürüm olarak ayarlanır:
```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Configure the message type and version
sSendHeader.m_eType = MT_SessionRequest;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```
Bu başlık daha sonra `write` sistem çağrısı kullanılarak hedefe gönderilir ve ardından oturum için bir GUID içeren `sessionRequestData` yapısı gönderilir:
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
`out` boru üzerinde yapılan bir okuma işlemi, hata ayıklama oturumunun başarılı olup olmadığını doğrular.
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## Bellek Okuma
Bir hata ayıklama oturumu oluşturulduğunda, bellek [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896) mesaj türünü kullanarak okunabilir. readMemory işlevi, bir okuma isteği göndermek ve yanıtı almak için gerekli adımları ayrıntılı olarak gerçekleştirir:
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
Tam kanıt (POC) [burada](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b) bulunmaktadır.

## Belleğe Yazma

Benzer şekilde, belleğe yazma işlemi `writeMemory` fonksiyonu kullanılarak gerçekleştirilir. İşlem, mesaj türünün `MT_WriteMemory` olarak ayarlanması, verinin adresi ve uzunluğunun belirtilmesi ve ardından verinin gönderilmesini içerir:
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
İlgili POC [burada](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5) bulunabilir.

## .NET Core Kodu Yürütme <a href="#net-core-code-execution" id="net-core-code-execution"></a>

Kod yürütmek için, rwx izinlerine sahip bir bellek bölgesi belirlemek gerekmektedir. Bu, vmmap -pages kullanılarak yapılabilir:
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
Bir işlev işaretçisini üzerine yazmak için bir yer bulmak gereklidir ve .NET Core'da bunu yapmanın bir yolu **Dynamic Function Table (DFT)**'ye hedef alarak yapmaktır. Bu tablo, JIT derleme yardımcı işlevleri için çalışma zamanı tarafından kullanılan [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h) dosyasında detaylı olarak açıklanmıştır.

x64 sistemler için, `libcorclr.dll` içindeki `_hlpDynamicFuncTable` sembolüne bir referans bulmak için imza avı kullanılabilir.

`MT_GetDCB` hata ayıklama işlevi, `m_helperRemoteStartAddr` adlı bir yardımcı işlevin adresi de dahil olmak üzere yararlı bilgiler sağlar. Bu adres, DFT'nin konumunu ve bir işlev işaretçisini kabuk kodunun adresiyle üzerine yazmak için kullanılır.

PowerShell'e enjeksiyon için tam POC kodu [buradan](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6) erişilebilir.

## Referanslar

* [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin!</summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin.
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'i keşfedin.
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi Twitter'da takip edin 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live).
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR göndererek paylaşın.

</details>
