# macOS XPC Bağlantı Süreci Kontrolü

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Ekip Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Ekip Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter**'da **bizi takip edin** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

## XPC Bağlantı Süreci Kontrolü

Bir XPC hizmetine bağlantı kurulduğunda, sunucu bağlantının izinli olup olmadığını kontrol eder. Genellikle gerçekleştireceği kontroller şunlardır:

1. Bağlanan **sürecin Apple imzalı** bir sertifika ile imzalanıp imzalanmadığını kontrol edin (sadece Apple tarafından verilir).
* Eğer bu **doğrulanmazsa**, bir saldırgan **herhangi bir diğer kontrolle eşleşen sahte bir sertifika** oluşturabilir.
2. Bağlanan sürecin **kuruluşun sertifikasıyla** imzalanıp imzalanmadığını kontrol edin (takım ID doğrulaması).
* Eğer bu **doğrulanmazsa**, Apple'dan alınan **herhangi bir geliştirici sertifikası** imzalamak için kullanılabilir ve hizmete bağlanabilir.
3. Bağlanan sürecin **uygun bir paket kimliğine** sahip olup olmadığını kontrol edin.
* Eğer bu **doğrulanmazsa**, **aynı kuruluş tarafından imzalanmış** herhangi bir araç XPC hizmeti ile etkileşimde bulunmak için kullanılabilir.
4. (4 veya 5) Bağlanan sürecin **uygun bir yazılım sürüm numarasına** sahip olup olmadığını kontrol edin.
* Eğer bu **doğrulanmazsa**, eski, güvensiz istemciler, süreç enjeksiyonuna karşı savunmasız olarak XPC hizmetine bağlanmak için kullanılabilir.
5. (4 veya 5) Bağlanan sürecin tehlikeli yetkilere sahip olmadan **sertleştirilmiş çalışma zamanı** olup olmadığını kontrol edin (örneğin, rastgele kütüphaneleri yüklemeye veya DYLD ortam değişkenlerini kullanmaya izin verenler gibi).
1. Eğer bu **doğrulanmazsa**, istemci **kod enjeksiyonuna karşı savunmasız** olabilir.
6. Bağlanan sürecin hizmete bağlanmasına izin veren bir **yetkiye** sahip olup olmadığını kontrol edin. Bu, Apple ikili dosyaları için geçerlidir.
7. **Doğrulama**, bağlanan **istemcinin denetim belirtecine** **dayanmalıdır** ve bunun yerine süreç ID'sine (**PID**) dayanmalıdır, çünkü bu, **PID yeniden kullanım saldırılarını** önler.
* Geliştiriciler **denetim belirteci** API çağrısını nadiren kullanır çünkü bu **özel** bir çağrıdır, bu nedenle Apple istediği zaman **değiştirebilir**. Ayrıca, özel API kullanımı Mac App Store uygulamalarında yasaklanmıştır.
* **`processIdentifier`** yöntemi kullanılıyorsa, savunmasız olabilir.
* **`xpc_dictionary_get_audit_token`** yerine **`xpc_connection_get_audit_token`** kullanılmalıdır, çünkü sonuncusu belirli durumlarda [savunmasız olabilir](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).

### İletişim Saldırıları

PID yeniden kullanım saldırısı hakkında daha fazla bilgi için kontrol edin:

{% content-ref url="macos-pid-reuse.md" %}
[macos-pid-reuse.md](macos-pid-reuse.md)
{% endcontent-ref %}

**`xpc_connection_get_audit_token`** saldırısı hakkında daha fazla bilgi için kontrol edin:

{% content-ref url="macos-xpc_connection_get_audit_token-attack.md" %}
[macos-xpc\_connection\_get\_audit\_token-attack.md](macos-xpc\_connection\_get\_audit\_token-attack.md)
{% endcontent-ref %}

### Trustcache - Aşağı Dönüş Saldırıları Önleme

Trustcache, yalnızca izin verilen değiştirilmemiş ikili dosyaların çalıştırılmasını sağlayan Apple Silicon makinelerinde tanıtılan savunma yöntemidir. Bu, aşağı sürüm versiyonlarının çalıştırılmasını önler.

### Kod Örnekleri

Sunucu bu **doğrulamayı** **`shouldAcceptNewConnection`** adlı bir işlevde uygulayacaktır.

{% code overflow="wrap" %}
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
{% endcode %}

NSXPCConnection nesnesinin **özel** bir özelliği **`auditToken`** (kullanılması gereken ama değişebilecek olan) ve **genel** bir özelliği **`processIdentifier`** (kullanılmaması gereken) vardır.

Bağlanan süreç, şu şekilde doğrulanabilir:

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

Eğer bir geliştirici istemcinin sürümünü kontrol etmek istemiyorsa, en azından istemcinin işlem enjeksiyonuna karşı savunmasız olmadığını kontrol edebilir:

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

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Ekip Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Ekip Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
