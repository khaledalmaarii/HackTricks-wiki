# macOS Sistem Uzantıları

{% hint style="success" %}
AWS Hacking'i öğrenin ve uygulayın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitimi AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitimi GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* Hacking püf noktalarını paylaşmak için PR'lar göndererek **HackTricks** ve **HackTricks Cloud** github depolarına katkıda bulunun.

</details>
{% endhint %}

## Sistem Uzantıları / Uç Nokta Güvenlik Çerçevesi

Kernel Uzantılarından farklı olarak, **Sistem Uzantıları kernel alanı yerine kullanıcı alanında çalışır**, bu da uzantı arızası nedeniyle sistem çökme riskini azaltır.

<figure><img src="../../../.gitbook/assets/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

Üç tür sistem uzantısı vardır: **DriverKit** Uzantıları, **Ağ** Uzantıları ve **Uç Nokta Güvenlik** Uzantıları.

### **DriverKit Uzantıları**

DriverKit, **donanım desteği sağlayan** kernel uzantılarının yerine geçen bir sistemdir. USB, Seri, NIC ve HID sürücüleri gibi cihaz sürücülerinin kernel alanı yerine kullanıcı alanında çalışmasına izin verir. DriverKit çerçevesi, belirli I/O Kit sınıflarının kullanıcı alanı sürümlerini içerir ve çekirdek, normal I/O Kit olaylarını kullanıcı alanına ileterek bu sürücülerin çalışması için daha güvenli bir ortam sunar.

### **Ağ Uzantıları**

Ağ Uzantıları, ağ davranışlarını özelleştirmeyi sağlar. Birkaç tür Ağ Uzantısı vardır:

* **Uygulama Proxy**: Bu, bağlantılar (veya akışlar) yerine bireysel paketlere dayalı olarak ağ trafiğini işleyen özel bir VPN istemcisi oluşturmak için kullanılır.
* **Paket Tüneli**: Bu, bireysel paketlere dayalı olarak ağ trafiğini işleyen özel bir VPN istemcisi oluşturmak için kullanılır.
* **Veri Filtresi**: Bu, ağ "akışlarını" filtrelemek için kullanılır. Ağ verilerini akış düzeyinde izleyebilir veya değiştirebilir.
* **Paket Filtresi**: Bu, bireysel ağ paketlerini filtrelemek için kullanılır. Ağ verilerini paket düzeyinde izleyebilir veya değiştirebilir.
* **DNS Proxy**: Bu, özel bir DNS sağlayıcısı oluşturmak için kullanılır. DNS isteklerini ve yanıtlarını izlemek veya değiştirmek için kullanılabilir.

## Uç Nokta Güvenlik Çerçevesi

Uç Nokta Güvenliği, Apple'ın macOS'ta sağladığı bir çerçevedir ve sistem güvenliği için bir dizi API sağlar. **Kötü amaçlı faaliyetleri tanımlamak ve korumak için sistem etkinliğini izlemek ve kontrol etmek üzere güvenlik satıcıları ve geliştiriciler tarafından kullanılması amaçlanmıştır**.

Bu çerçeve, işlem yürütmeleri, dosya sistemi olayları, ağ ve çekirdek olayları gibi **sistem etkinliklerini izlemek ve kontrol etmek için bir dizi API koleksiyonu sağlar**.

Bu çerçevenin çekirdeği, **`/System/Library/Extensions/EndpointSecurity.kext`** konumunda bulunan bir Kernel Uzantısı (KEXT) olarak uygulanmıştır. Bu KEXT, birkaç temel bileşenden oluşur:

* **EndpointSecurityDriver**: Bu, çekirdek uzantısının "giriş noktası" olarak hareket eder. OS ile Uç Nokta Güvenlik çerçevesi arasındaki ana etkileşim noktasıdır.
* **EndpointSecurityEventManager**: Bu bileşen, çekirdek kancalarını uygulamaktan sorumludur. Çekirdek kancaları, çerçevenin sistem çağrılarını engelleyerek sistem olaylarını izlemesine olanak tanır.
* **EndpointSecurityClientManager**: Bu, kullanıcı alanı istemcileriyle iletişimi yönetir, hangi istemcilerin bağlı olduğunu ve olay bildirimleri alması gerektiğini takip eder.
* **EndpointSecurityMessageManager**: Bu, mesajları ve olay bildirimlerini kullanıcı alanı istemcilerine gönderir.

Uç Nokta Güvenlik çerçevesinin izleyebileceği olaylar şunlara ayrılır:

* Dosya olayları
* İşlem olayları
* Soket olayları
* Çekirdek olayları (örneğin, bir çekirdek uzantısını yükleme/boşaltma veya bir I/O Kit cihazını açma)

### Uç Nokta Güvenlik Çerçevesi Mimarisi

<figure><img src="../../../.gitbook/assets/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

Uç Nokta Güvenlik çerçevesiyle **kullanıcı alanı iletişimi**, IOUserClient sınıfı aracılığıyla gerçekleşir. Çağrı türüne bağlı olarak iki farklı alt sınıf kullanılır:

* **EndpointSecurityDriverClient**: Bu, yalnızca sistem süreci `endpointsecurityd` tarafından tutulan `com.apple.private.endpoint-security.manager` yetkisini gerektirir.
* **EndpointSecurityExternalClient**: Bu, `com.apple.developer.endpoint-security.client` yetkisini gerektirir. Bu genellikle Uç Nokta Güvenlik çerçevesiyle etkileşimde bulunması gereken üçüncü taraf güvenlik yazılımı tarafından kullanılır.

Uç Nokta Güvenlik Uzantıları:**`libEndpointSecurity.dylib`**, sistem uzantılarının çekirdek ile iletişim kurmak için kullandığı C kütüphanesidir. Bu kütüphane, Endpoint Security KEXT ile iletişim kurmak için I/O Kit (`IOKit`) kullanır.

**`endpointsecurityd`**, özellikle erken başlatma sürecinde uç nokta güvenlik sistem uzantılarını yöneten ve başlatan önemli bir sistem daemonudur. **Yalnızca** `Info.plist` dosyasındaki **`NSEndpointSecurityEarlyBoot`** ile işaretlenen **sistem uzantıları**, bu erken başlatma işleminden faydalanır.

Başka bir sistem daemonu olan **`sysextd`**, sistem uzantılarını doğrular ve bunları uygun sistem konumlarına taşır. Daha sonra ilgili daemonun uzantıyı yüklemesini ister. **`SystemExtensions.framework`**, sistem uzantılarını etkinleştirme ve devre dışı bırakma işlevinden sorumludur.

## ESF'nin Atlatılması

ESF, kırmızı takımı tespit etmeye çalışacak güvenlik araçları tarafından kullanılır, bu yüzden bunun nasıl atlatılabileceği hakkında herhangi bir bilgi ilginç gelebilir.

### CVE-2021-30965

İşin aslı, güvenlik uygulamasının **Tam Disk Erişimi izinlerine** sahip olması gerekmektedir. Bu nedenle, bir saldırgan bunu kaldırabilirse, yazılımın çalışmasını engelleyebilir:
```bash
tccutil reset All
```
**Daha fazla bilgi** için bu bypass ve ilgili olanlar hakkında [#OBTS v5.0: "EndpointSecurity'ın Achilles Topuğu" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI) konuşmasına bakabilirsiniz.

Sonunda, **`tccd`** tarafından yönetilen güvenlik uygulamasına yeni izin **`kTCCServiceEndpointSecurityClient`** verilerek bu izinlerini temizlemesini önleyerek çalışmasını engellemesi engellendi.

## Referanslar

* [**OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight**](https://www.youtube.com/watch?v=jaVkpM1UqOs)
* [**https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html**](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)

{% hint style="success" %}
AWS Hacking'i öğrenin ve uygulayın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitimi AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitimi GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* Hacking püf noktalarını paylaşarak PR'ler göndererek **HackTricks** ve **HackTricks Cloud** github depolarına katkıda bulunun.

</details>
{% endhint %}
