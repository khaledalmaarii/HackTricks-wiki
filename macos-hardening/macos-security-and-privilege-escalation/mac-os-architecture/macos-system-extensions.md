# macOS Sistem Uzantıları

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini edinin**](https://peass.creator-spring.com)
* [**PEASS Ailesi'ni keşfedin**](https://opensea.io/collection/the-peass-family), özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR göndererek HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

## Sistem Uzantıları / Uç Nokta Güvenlik Çerçevesi

**Sistem Uzantıları**, Kernel Uzantıları'nın aksine **kullanıcı alanında çalışır**, böylece uzantı arızası nedeniyle sistem çökme riskini azaltır.

<figure><img src="../../../.gitbook/assets/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

Üç tür sistem uzantısı vardır: **DriverKit** Uzantıları, **Ağ** Uzantıları ve **Uç Nokta Güvenlik** Uzantıları.

### **DriverKit Uzantıları**

DriverKit, **donanım desteği sağlayan** kernel uzantılarının yerine geçen bir yapıdır. USB, Seri, NIC ve HID sürücüleri gibi aygıt sürücülerinin kernel alanı yerine kullanıcı alanında çalışmasına izin verir. DriverKit çerçevesi, belirli I/O Kit sınıflarının kullanıcı alanı sürümlerini içerir ve çekirdek, normal I/O Kit olaylarını kullanıcı alanına ileterek bu sürücülerin çalışması için daha güvenli bir ortam sunar.

### **Ağ Uzantıları**

Ağ Uzantıları, ağ davranışlarını özelleştirmeyi sağlar. Birkaç tür Ağ Uzantısı bulunmaktadır:

* **Uygulama Proxy**: Bu, bağlantılar (veya akışlar) yerine bireysel paketlere dayalı ağ trafiğini işleyen özel bir VPN istemcisi oluşturmak için kullanılır.
* **Paket Tüneli**: Bu, bireysel paketlere dayalı ağ trafiğini işleyen özel bir VPN istemcisi oluşturmak için kullanılır.
* **Veri Filtresi**: Bu, ağ "akışlarını" filtrelemek için kullanılır. Ağ verilerini akış düzeyinde izleyebilir veya değiştirebilir.
* **Paket Filtresi**: Bu, bireysel ağ paketlerini filtrelemek için kullanılır. Ağ verilerini paket düzeyinde izleyebilir veya değiştirebilir.
* **DNS Proxy**: Bu, özel bir DNS sağlayıcı oluşturmak için kullanılır. DNS isteklerini ve yanıtlarını izlemek veya değiştirmek için kullanılabilir.

## Uç Nokta Güvenlik Çerçevesi

Uç Nokta Güvenliği, Apple'ın macOS'ta sağladığı bir çerçevedir ve sistem güvenliği için bir dizi API sağlar. **Kötü niyetli faaliyetleri tanımlamak ve korumak için ürünler geliştirmek isteyen güvenlik satıcıları ve geliştiriciler tarafından kullanılması amaçlanmıştır**.

Bu çerçeve, işlem yürütmeleri, dosya sistemi olayları, ağ ve çekirdek olayları gibi **sistem etkinliklerini izlemek ve kontrol etmek için bir dizi API sağlar**.

Bu çerçevenin çekirdeği, **`/System/Library/Extensions/EndpointSecurity.kext`** konumunda bulunan bir Kernel Uzantısı (KEXT) olarak uygulanmıştır. Bu KEXT'in birkaç temel bileşeni bulunmaktadır:

* **EndpointSecurityDriver**: Bu, çekirdek uzantısının "giriş noktası" olarak hareket eder. İşletim sistemi ile Uç Nokta Güvenlik çerçevesi arasındaki ana etkileşim noktasıdır.
* **EndpointSecurityEventManager**: Bu bileşen, çekirdek kancalarını uygulamaktan sorumludur. Çekirdek kancaları, çerçevenin sistem çağrılarını engelleyerek sistem olaylarını izlemesine olanak tanır.
* **EndpointSecurityClientManager**: Bu, kullanıcı alanı istemcileriyle iletişimi yönetir, hangi istemcilerin bağlı olduğunu ve olay bildirimleri alması gerektiğini takip eder.
* **EndpointSecurityMessageManager**: Bu, mesajları ve olay bildirimlerini kullanıcı alanı istemcilerine gönderir.

Uç Nokta Güvenlik çerçevesinin izleyebileceği olaylar şunlara ayrılır:

* Dosya olayları
* İşlem olayları
* Soket olayları
* Çekirdek olayları (örneğin bir çekirdek uzantısını yükleme/boşaltma veya bir I/O Kit cihazını açma)

### Uç Nokta Güvenlik Çerçevesi Mimarisi

<figure><img src="../../../.gitbook/assets/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

Uç Nokta Güvenlik çerçevesiyle **kullanıcı alanı iletişimi**, IOUserClient sınıfı aracılığıyla gerçekleşir. Çağrı türüne bağlı olarak iki farklı alt sınıf kullanılır:

* **EndpointSecurityDriverClient**: Bu, yalnızca sistem işlemi `endpointsecurityd` tarafından tutulan `com.apple.private.endpoint-security.manager` yetkisini gerektirir.
* **EndpointSecurityExternalClient**: Bu, `com.apple.developer.endpoint-security.client` yetkisini gerektirir. Bu genellikle Uç Nokta Güvenlik çerçevesiyle etkileşimde bulunması gereken üçüncü taraf güvenlik yazılımı tarafından kullanılır.

Uç Nokta Güvenlik Uzantıları:**`libEndpointSecurity.dylib`**, sistem uzantılarının çekirdek ile iletişim kurmak için kullandığı C kütüphanesidir. Bu kütüphane, Endpoint Security KEXT ile iletişim kurmak için I/O Kit (`IOKit`) kullanır.

**`endpointsecurityd`**, özellikle erken başlatma sürecinde uç nokta güvenlik sistem uzantılarını yöneten ve başlatan önemli bir sistem hizmetidir. Yalnızca `Info.plist` dosyasındaki **`NSEndpointSecurityEarlyBoot`** ile işaretlenmiş **yalnızca sistem uzantıları**, bu erken başlatma işleminden faydalanır.

Başka bir sistem hizmeti olan **`sysextd`**, sistem uzantılarını doğrular ve bunları uygun sistem konumlarına taşır. Daha sonra ilgili hizmetten uzantının yüklenmesini ister. **`SystemExtensions.framework`**, sistem uzantılarını etkinleştirme ve devre dışı bırakma işlevinden sorumludur.

## ESF'nin Atlatılması

ESF, kırmızı takımı tespit etmeye çalışacak güvenlik araçları tarafından kullanılır, bu nedenle bunun nasıl atlatılabileceğine dair herhangi bir bilgi ilginç gelebilir.

### CVE-2021-30965

İşin aslı, güvenlik uygulamasının **Tam Disk Erişimi izinlerine** sahip olması gerekmektedir. Bu izni kaldırabilen bir saldırgan, yazılımın çalışmasını engelleyebilir:
```bash
tccutil reset All
```
**Daha fazla bilgi** için bu bypass ve ilgili olanlar hakkında [#OBTS v5.0: "EndpointSecurity'ın Achilles Topu" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI) konuşmasına bakabilirsiniz.

Sonunda, bu, **`tccd`** tarafından yönetilen güvenlik uygulamasına yeni izin **`kTCCServiceEndpointSecurityClient`** verilerek düzeltildi, böylece `tccutil` izinlerini temizlemez ve çalışmasını engellemez.

## Referanslar

* [**OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight**](https://www.youtube.com/watch?v=jaVkpM1UqOs)
* [**https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html**](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family'yi**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)'da **takip edin**.
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
