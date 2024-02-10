# macOS XPC Bağlantı Süreci Kontrolü

<details>

<summary><strong>AWS hackleme becerilerini sıfırdan ileri seviyeye öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* Hacking hilelerinizi **HackTricks** ve **HackTricks Cloud** github depolarına **PR göndererek** paylaşın.

</details>

## XPC Bağlantı Süreci Kontrolü

Bir XPC hizmetine bağlantı kurulduğunda, sunucu bağlantının izin verilip verilmediğini kontrol eder. Genellikle şu kontrolleri yapar:

1. Bağlanan **işlem Apple tarafından imzalanmış** bir sertifika ile mi imzalanmış (yalnızca Apple tarafından verilen)?
* Bu **doğrulanmazsa**, saldırgan herhangi bir diğer kontrolle eşleşecek bir **sahte sertifika** oluşturabilir.
2. Bağlanan işlem **kuruluşun sertifikası** ile mi imzalanmış (takım kimliği doğrulaması)?
* Bu **doğrulanmazsa**, Apple'dan herhangi bir geliştirici sertifikası, hizmete bağlanmak için kullanılabilir.
3. Bağlanan işlemde **uygun bir paket kimliği** bulunuyor mu?
* Bu **doğrulanmazsa**, aynı kuruluş tarafından imzalanmış herhangi bir araç, XPC hizmetiyle etkileşimde bulunmak için kullanılabilir.
4. (4 veya 5) Bağlanan işlemin **uygun bir yazılım sürüm numarası** var mı?
* Bu **doğrulanmazsa**, diğer kontroller yerinde olsa bile, eski, güvenlik açıklarına sahip istemciler, işlem enjeksiyonuna karşı savunmasız bir şekilde XPC hizmetine bağlanmak için kullanılabilir.
5. (4 veya 5) Bağlanan işlemin tehlikeli yetkilendirmelere sahip olmayan sertleştirilmiş çalışma zamanı olup olmadığı kontrol edilir (örneğin, keyfi kitaplıkları yüklemeye veya DYLD ortam değişkenlerini kullanmaya izin verenler).
1. Bu **doğrulanmazsa**, istemci **kod enjeksiyonuna karşı savunmasız** olabilir.
6. Bağlanan işlemin, hizmete bağlanmasına izin veren bir **yetkilendirme**ye sahip olup olmadığı kontrol edilir. Bu, Apple ikili dosyaları için geçerlidir.
7. **Doğrulama**, bağlanan **istemcinin denetim belirteci**ne dayanmalıdır, **işlem kimliği (PID)** yerine. Çünkü ilkini kullanmak, **PID yeniden kullanım saldırılarına** karşı korur.
* Geliştiriciler nadiren denetim belirteci API çağını kullanır çünkü bu **özel** bir çağrıdır, bu yüzden Apple herhangi bir zamanda **değiştirebilir**. Ayrıca, özel API kullanımı Mac App Store uygulamalarında izin verilmez.
* **`processIdentifier`** yöntemi kullanılıyorsa, savunmasız olabilir
* En son [belirli durumlarda savunmasız olabilen](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/) **`xpc_connection_get_audit_token`** yerine **`xpc_dictionary_get_audit_token`** kullanılmalıdır.

### İletişim Saldırıları

PID yeniden kullanım saldırısı hakkında daha fazla bilgi için kontrol edin:

{% content-ref url="macos-pid-reuse.md" %}
[macos-pid-reuse.md](macos-pid-reuse.md)
{% endcontent-ref %}

**`xpc_connection_get_audit_token`** saldırısı hakkında daha fazla bilgi için kontrol edin:

{% content-ref url="macos-xpc_connection_get_audit_token-attack.md" %}
[macos-xpc\_connection\_get\_audit\_token-attack.md](macos-xpc\_connection\_get\_audit\_token-attack.md)
{% endcontent-ref %}

### Trustcache - Düşürme Saldırılarına Karşı Önlem

Trustcache, Apple Silicon makinelerinde tanıtılan bir savunma yöntemidir ve yalnızca değiştirilmemiş izin verilen ikili dosyaların çalıştırılmasına izin veren bir CDHSAH veritabanını depolar. Bu, düşürme sürümlerinin yürütülmesini engeller.

### Kod Örnekleri

Sunucu, bu **doğrulamayı** **`shouldAcceptNewConnection`** adlı bir işlevde uygular.

{% code overflow="wrap" %}
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
{% endcode %}

NSXPCConnection nesnesinin **özel** bir **`auditToken`** özelliği (kullanılması gereken ancak değişebilecek olan) ve **genel** bir **`processIdentifier`** özelliği (kullanılmaması gereken) bulunmaktadır.

Bağlantı kurulan işlem şu şekilde doğrulanabilir:

{% code overflow="wrap" %}
```objectivec
[...]
SecRequirementRef requirementRef = NULL;
NSString requirementString = @"anchor apple generic and identifier \"xyz.hacktricks.service\" and certificate leaf [subject.CN] = \"TEAMID\" and info [CFBundleShortVersionString] >= \"1.0\"";
/* Check:
- Signed by a cert signed by Apple
- Check the bundle ID
- Check the TEAMID of the signing cert
- Check the version used
*/

// Check the requirements with the PID (vulnerable)
SecRequirementCreateWithString(requirementString, kSecCSDefaultFlags, &requirementRef);
SecCodeCheckValidity(code, kSecCSDefaultFlags, requirementRef);

// Check the requirements wuing the auditToken (secure)
SecTaskRef taskRef = SecTaskCreateWithAuditToken(NULL, ((ExtendedNSXPCConnection*)newConnection).auditToken);
SecTaskValidateForRequirement(taskRef, (__bridge CFStringRef)(requirementString))
```
{% endcode %}

Eğer bir geliştirici istemci sürümünü kontrol etmek istemiyorsa, en azından istemcinin işlem enjeksiyonuna karşı savunmasız olmadığını kontrol edebilir:

{% code overflow="wrap" %}
```objectivec
[...]
CFDictionaryRef csInfo = NULL;
SecCodeCopySigningInformation(code, kSecCSDynamicInformation, &csInfo);
uint32_t csFlags = [((__bridge NSDictionary *)csInfo)[(__bridge NSString *)kSecCodeInfoStatus] intValue];
const uint32_t cs_hard = 0x100;        // don't load invalid page.
const uint32_t cs_kill = 0x200;        // Kill process if page is invalid
const uint32_t cs_restrict = 0x800;    // Prevent debugging
const uint32_t cs_require_lv = 0x2000; // Library Validation
const uint32_t cs_runtime = 0x10000;   // hardened runtime
if ((csFlags & (cs_hard | cs_require_lv)) {
return Yes; // Accept connection
}
```
{% endcode %}

<details>

<summary><strong>AWS hackleme becerilerini sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* Hacking hilelerinizi [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR göndererek paylaşın.

</details>
