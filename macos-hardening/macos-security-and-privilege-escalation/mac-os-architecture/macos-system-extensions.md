# macOS Sistem Uzantıları

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimizden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

## Sistem Uzantıları / Uç Nokta Güvenlik Çerçevesi

Kernel Uzantılarının aksine, **Sistem Uzantıları kernel alanı yerine kullanıcı alanında çalışır**, uzantı arızası nedeniyle sistem çökmesi riskini azaltır.

<figure><img src="../../../.gitbook/assets/image (1) (3) (1) (1).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

Üç tür sistem uzantısı vardır: **DriverKit** Uzantıları, **Network** Uzantıları ve **Endpoint Security** Uzantıları.

### **DriverKit Uzantıları**

DriverKit, **donanım desteği sağlayan** kernel uzantılarının yerine geçen bir sistemdir. USB, Seri, NIC ve HID sürücüleri gibi cihaz sürücülerinin kernel alanı yerine kullanıcı alanında çalışmasına izin verir. DriverKit çerçevesi, belirli I/O Kit sınıflarının kullanıcı alanı sürümlerini içerir ve kernel, normal I/O Kit olaylarını kullanıcı alanına yönlendirerek bu sürücülerin çalışması için daha güvenli bir ortam sunar.

### **Network Uzantıları**

Network Uzantıları, ağ davranışlarını özelleştirmek için yetenek sağlar. Birkaç tür Network Uzantısı vardır:

* **App Proxy**: Bu, bağlantılara (veya akışlara) dayalı olarak ağ trafiğini işleyen, özel bir VPN protokolü uygulayan bir VPN istemcisi oluşturmak için kullanılır.
* **Packet Tunnel**: Bu, bireysel paketlere dayalı olarak ağ trafiğini işleyen, özel bir VPN protokolü uygulayan bir VPN istemcisi oluşturmak için kullanılır.
* **Filter Data**: Bu, ağ "akışlarını" filtrelemek için kullanılır. Ağ verilerini akış düzeyinde izleyebilir veya değiştirebilir.
* **Filter Packet**: Bu, bireysel ağ paketlerini filtrelemek için kullanılır. Ağ verilerini paket düzeyinde izleyebilir veya değiştirebilir.
* **DNS Proxy**: Bu, özel bir DNS sağlayıcı oluşturmak için kullanılır. DNS isteklerini ve yanıtlarını izlemek veya değiştirmek için kullanılabilir.

## Uç Nokta Güvenlik Çerçevesi

Endpoint Security, Apple'ın macOS'ta sağladığı bir çerçevedir ve sistem güvenliği için bir dizi API sağlar. **Kötü amaçlı etkinlikleri tespit etmek ve korumak için sistem etkinliğini izlemek ve kontrol etmek için güvenlik sağlayıcıları ve geliştiriciler tarafından kullanılması amaçlanmıştır**.

Bu çerçeve, işlem yürütmeleri, dosya sistemi olayları, ağ ve kernel olayları gibi sistem etkinliklerini izlemek ve kontrol etmek için bir dizi API sağlar.

Bu çerçevenin çekirdeği, bir Kernel Uzantısı (KEXT) olarak uygulanır ve **`/System/Library/Extensions/EndpointSecurity.kext`** konumunda bulunur. Bu KEXT, birkaç temel bileşenden oluşur:

* **EndpointSecurityDriver**: Bu, çekirdek uzantısının "giriş noktası" olarak hareket eder. İşletim sistemi ile Endpoint Security çerçevesi arasındaki ana etkileşim noktasıdır.
* **EndpointSecurityEventManager**: Bu bileşen, çekirdek kancalarını uygulamaktan sorumludur. Çekirdek kancaları, sistem çağrılarını engelleyerek çerçevenin sistem olaylarını izlemesine olanak tanır.
* **EndpointSecurityClientManager**: Bu, kullanıcı alanı istemcileriyle iletişimi yönetir, hangi istemcilerin bağlı olduğunu ve olay bildirimleri alması gerektiğini takip eder.
* **EndpointSecurityMessageManager**: Bu, kullanıcı alanı istemcilerine mesajlar ve olay bildirimleri gönderir.

Endpoint Security çerçevesinin izleyebileceği olaylar şunlara ayrılır:

* Dosya olayları
* İşlem olayları
* Soket olayları
* Kernel olayları (bir kernel uzantısının yüklenmesi/boşaltılması veya bir I/O Kit cihazının açılması gibi)

### Uç Nokta Güvenlik Çerçevesi Mimarisi

<figure><img src="../../../.gitbook/assets/image (3) (8).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

Endpoint Security çerçevesiyle **kullanıcı alanı iletişimi**, IOUserClient sınıfı aracılığıyla gerçekleşir. Arayanın türüne bağlı olarak iki farklı alt sınıf kullanılır:

* **EndpointSecurityDriverClient**: Bu, yalnızca sistem süreci `endpointsecurityd` tarafından tutulan `com.apple.private.endpoint-security.manager` yetkisine sahiptir.
* **EndpointSecurityExternalClient**: Bu, `com.apple.developer.endpoint-security.client` yetkisine ihtiyaç duyar. Bu genellikle Endpoint Security çerçevesiyle etkileşimde bulunması gereken üçüncü taraf güvenlik yazılımı tarafından kullanılır.

Endpoint Security Uzantıları:**`libEndpointSecurity.dylib`**, sistem uzantılarının çekirdek ile iletişim kurmak için kullandığı C kütüphanesidir. Bu kütüphane, Endpoint Security KEXT ile iletişim kurmak için I/O Kit (`IOKit`) kullanır.

**`endpointsecurityd`**, uç nokta güvenlik sistem uzantılarını yöneten ve başlatan önemli bir sistem hizmetidir, özellikle erken başlatma sürecinde. Bu erken başlatma işlemi, `Info.plist` dosyasında **`NSEndpointSecurityEarlyBoot`** olarak işaretlenen **yalnızca sistem uzantıları** tarafından alınır.

Başka bir sistem hizmeti olan **`sysextd`**, sistem uzantılarını doğrular ve uygun sistem konumlarına taşır. Ardından, ilgili hizmete uzantının yüklenmesini ister. **`SystemExtensions.framework`**, sistem uzantılarını etkinleştirme ve devre dışı bırakma işlemlerinden sorumludur.

## ESF'nin Atlanması

ESF, bir kırmızı takım üyesini tespit etmeye çalışacak güvenlik araçları tarafından kullanılır, bu yüzden bunun nasıl atlatılabileceğiyle ilgili herhangi bir bilgi ilgi çekicidir.

### CVE-2021-30965

Mesele, güvenlik uygulamasının **Tam Disk Erişimi izinlerine** sahip olması gerektiğidir. Bu nedenle, bir saldırgan bunu kaldırabilirse, yazılımın çalışmasını engelleyebilir:
```bash
tccutil reset All
```
Bu bypass ve ilgili olanlar hakkında **daha fazla bilgi** için [#OBTS v5.0: "EndpointSecurity' nin Achilles Topuğu" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI) adlı sunumu kontrol edin.

Sonunda, bu sorun, **`tccd`** tarafından yönetilen güvenlik uygulamasına yeni izin **`kTCCServiceEndpointSecurityClient`** verilerek çözüldü, böylece `tccutil` izinlerini temizlemedi ve çalışmasını engellemedi.

## Referanslar

* [**OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight**](https://www.youtube.com/watch?v=jaVkpM1UqOs)
* [**https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html**](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya HackTricks'i **PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'i keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* Hacking hilelerinizi **HackTricks** ve **HackTricks Cloud** github reposuna PR göndererek paylaşın.

</details>
