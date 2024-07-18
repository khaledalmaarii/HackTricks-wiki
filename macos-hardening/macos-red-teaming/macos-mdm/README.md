# macOS MDM

{% hint style="success" %}
AWS Hacking'i öğrenin ve uygulayın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarını paylaşarak PR göndererek HackTricks ve HackTricks Cloud github depolarına katkıda bulunun.**

</details>
{% endhint %}

**macOS MDM'leri hakkında bilgi edinmek için:**

* [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
* [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## Temeller

### **MDM (Mobil Cihaz Yönetimi) Genel Bakışı**

[Mobil Cihaz Yönetimi](https://en.wikipedia.org/wiki/Mobile\_device\_management) (MDM), akıllı telefonlar, dizüstü bilgisayarlar ve tabletler gibi çeşitli son kullanıcı cihazlarının yönetimi için kullanılır. Özellikle Apple'ın platformları (iOS, macOS, tvOS) için, özel özellikler, API'lar ve uygulamaları içerir. MDM'nin işleyişi, MDM protokolünü destekleyen ticari olarak temin edilebilen veya açık kaynaklı bir MDM sunucusuna dayanır. Anahtar noktalar şunları içerir:

* Cihazlar üzerinde merkezi kontrol.
* MDM protokolüne uygun bir MDM sunucusuna bağımlılık.
* MDM sunucusunun cihazlara çeşitli komutlar gönderebilme yeteneği, örneğin uzaktan veri silme veya yapılandırma yükleme.

### **DEP (Cihaz Kayıt Programı) Temelleri**

Apple tarafından sunulan [Cihaz Kayıt Programı](https://www.apple.com/business/site/docs/DEP\_Guide.pdf) (DEP), iOS, macOS ve tvOS cihazları için sıfır dokunuşlu yapılandırmayı kolaylaştırarak Mobil Cihaz Yönetimi (MDM) entegrasyonunu basitleştirir. DEP, cihazların kutudan çıkar çıkmaz operasyonel hale gelmesini sağlayarak kayıt sürecini otomatikleştirir ve kullanıcı veya yönetici müdahalesini minimuma indirir. Temel noktalar şunları içerir:

* Cihazların ilk etkinleştirilmesinde önceden tanımlanmış bir MDM sunucusuna otomatik olarak kaydolmalarını sağlar.
* Öncelikle yeni cihazlar için faydalı olmakla birlikte, yeniden yapılandırılan cihazlar için de uygundur.
* Cihazların hızlı bir şekilde kurulmasını sağlayarak, cihazları organizasyonel kullanıma hızlı bir şekilde hazır hale getirir.

### **Güvenlik Düşünceleri**

DEP tarafından sağlanan kayıt kolaylığının faydalı olmasına rağmen, uygun koruma önlemlerinin MDM kaydı için yeterince uygulanmaması durumunda güvenlik riskleri oluşturabileceği önemlidir. Eğer MDM kaydı için koruyucu önlemler yeterince uygulanmazsa, saldırganlar bu basitleştirilmiş süreci kullanarak kurumsal cihazları taklit ederek kendi cihazlarını kuruluşun MDM sunucusuna kaydedebilirler.

{% hint style="danger" %}
**Güvenlik Uyarısı**: Basitleştirilmiş DEP kaydı, uygun koruma önlemleri olmadığında yetkisiz cihaz kaydına izin verebilir.
{% endhint %}

### SCEP (Basit Sertifika Kayıt Protokolü) Nedir?

* Göreceli olarak eski bir protokol, TLS ve HTTPS yaygınlaşmadan önce oluşturulmuştur.
* Müşterilere bir **Sertifika İmzalama İsteği** (CSR) gönderme standart bir yol sağlar. Müşteri, sunucudan kendisine imzalı bir sertifika vermesini ister.

### Yapılandırma Profilleri (aka mobileconfigs) Nedir?

* Apple'ın resmi **sistem yapılandırmasını belirleme/zorlama** yoludur.
* Birden fazla yük taşıyabilen dosya formatı.
* Özellik listelerine (XML türünden) dayanır.
* "kökenlerini doğrulamak, bütünlüklerini sağlamak ve içeriklerini korumak için imzalanabilir ve şifrelenebilir." Temeller — Sayfa 70, iOS Güvenlik Kılavuzu, Ocak 2018.

## Protokoller

### MDM

* APNs (**Apple sunucuları**) + RESTful API (**MDM satıcı** sunucuları) kombinasyonu
* **İletişim**, bir **cihaz** ve bir **cihaz yönetimi ürünü** ile ilişkili bir sunucu arasında gerçekleşir
* **Komutlar**, MDM'den cihaza **plist kodlu sözlükler** şeklinde iletilir
* Tümü **HTTPS** üzerinden. MDM sunucuları (genellikle) sabitlenebilir.
* Apple, MDM satıcısına kimlik doğrulaması için bir **APNs sertifikası** verir

### DEP

* **3 API**: 1 bayiler için, 1 MDM satıcıları için, 1 cihaz kimliği için (belgelenmemiş):
* Sözde [DEP "bulut hizmeti" API'si](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Bu, MDM sunucularının DEP profillerini belirli cihazlarla ilişkilendirmek için kullandığı API'dir.
* [Apple Yetkili Bayiler tarafından kullanılan DEP API'si](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html), cihazları kaydetmek, kayıt durumunu kontrol etmek ve işlem durumunu kontrol etmek için kullanılır.
* Belgelenmemiş özel DEP API. Bu, Apple Cihazlarının DEP profillerini istemek için kullanılır. macOS'ta, `cloudconfigurationd` ikili dosyası bu API üzerinden iletişim kurar.
* Daha modern ve **JSON** tabanlı (plist karşısında)
* Apple, MDM satıcısına bir **OAuth belirteci** verir

**DEP "bulut hizmeti" API'si**

* RESTful
* Apple'dan MDM sunucusuna cihaz kayıtlarını senkronize et
* MDM sunucusundan Apple'a "DEP profillerini" senkronize et (daha sonra cihaza Apple tarafından iletilir)
* Bir DEP "profil" şunları içerir:
* MDM satıcı sunucu URL'si
* Sunucu URL'si için ek güvenilir sertifikalar (isteğe bağlı sabitleme)
* Ek ayarlar (örneğin, Kurulum Yardımcısında hangi ekranların atlanacağı)

## Seri Numarası

2010'dan sonra üretilen Apple cihazlarının genellikle **12 karakterli alfasayısal** seri numaraları vardır, **ilk üç rakamın üretim yeri**, ardından **üretim yılını ve haftasını belirten iki rakam**, bir **benzersiz tanımlayıcı sağlayan üç rakam** ve **model numarasını temsil eden son dört rakam** bulunur.

{% content-ref url="macos-serial-number.md" %}
[macos-serial-number.md](macos-serial-number.md)
{% endcontent-ref %}

## Kayıt ve Yönetim Adımları

1. Cihaz kaydı oluşturma (Bayi, Apple): Yeni cihaz için kayıt oluşturulur
2. Cihaz kaydı atama (Müşteri): Cihaz bir MDM sunucusuna atanır
3. Cihaz kaydı senkronizasyonu (MDM satıcısı): MDM cihaz kayıtlarını senkronize eder ve DEP profillerini Apple'a gönderir
4. DEP kontrolü (Cihaz): Cihaz DEP profilini alır
5. Profil alımı (Cihaz)
6. Profil kurulumu (Cihaz) a. MDM, SCEP ve kök CA yükleri dahil
7. MDM komutu verme (Cihaz)

![](<../../../.gitbook/assets/image (694).png>)

`/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` dosyası, kayıt sürecinin **yüksek seviyeli "adımları"** olarak kabul edilebilecek işlevleri ihraç eder.
### Adım 4: DEP kontrolü - Aktivasyon Kaydının Alınması

Bu sürecin bir parçası, bir **kullanıcının bir Mac'i ilk kez başlattığında** (veya tam bir silme işleminden sonra)

![](<../../../.gitbook/assets/image (1044).png>)

veya `sudo profiles show -type enrollment` komutunu çalıştırdığında gerçekleşir

* **Cihazın DEP özellikli olup olmadığını belirle**
* Aktivasyon Kaydı, DEP "profil"i için iç isimdir
* Cihazın İnternete bağlandığı anda başlar
* **`CPFetchActivationRecord`** tarafından yönlendirilir
* **`cloudconfigurationd`** tarafından XPC aracılığıyla uygulanır. Cihaz ilk kez başlatıldığında **"Kurulum Yardımcısı**" veya **`profiles`** komutu bu hizmete başvurmak için bu daemon ile iletişim kurar.
* LaunchDaemon (her zaman root olarak çalışır)

Aktivasyon Kaydını almak için **`MCTeslaConfigurationFetcher`** tarafından gerçekleştirilen birkaç adımı takip eder. Bu süreç **Absinthe** adı verilen bir şifreleme kullanır

1. **Sertifika** al
1. [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer) adresinden GET isteği yap
2. Sertifikadan durumu başlat (**`NACInit`**)
1. Çeşitli cihaz özel verilerini kullanır (örneğin **`IOKit`** üzerinden Seri Numarası)
3. **Oturum anahtarını** al
1. [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session) adresine POST isteği yap
4. Oturumu oluştur (**`NACKeyEstablishment`**)
5. İsteği yap
1. `{ "action": "RequestProfileConfiguration", "sn": "" }` verilerini göndererek [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) adresine POST isteği yap
2. JSON yükü **Absinthe** kullanılarak şifrelenir (**`NACSign`**)
3. Tüm istekler HTTPS üzerinden yapılır, yerleşik kök sertifikalar kullanılır

![](<../../../.gitbook/assets/image (566) (1).png>)

Yanıt, aşağıdaki gibi bazı önemli veriler içeren bir JSON sözlüğüdür:

* **url**: Aktivasyon profili için MDM satıcısı ana bilgisayarının URL'si
* **anchor-certs**: Güvenilir kök sertifikalar olarak kullanılan DER sertifikalarının dizisi

### Adım 5: Profil Alımı

![](<../../../.gitbook/assets/image (444).png>)

* DEP profilde sağlanan **URL'ye** istek gönderilir.
* Eğer sağlanmışsa, **Güvenilir kök sertifikalar** güveni **değerlendirmek** için kullanılır.
* Hatırlatma: DEP profili **anchor\_certs** özelliği
* İstek, cihaz kimliği gibi **basit bir .plist** içerir
* Örnekler: **UDID, OS sürümü**.
* CMS imzalı, DER kodlanmış
* **APNS'den cihaz kimlik sertifikası kullanılarak imzalanmıştır**
* **Sertifika zinciri**, süresi dolmuş **Apple iPhone Device CA** içerir

![](<../../../.gitbook/assets/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Adım 6: Profil Kurulumu

* Alındıktan sonra, **profil sisteme kaydedilir**
* Bu adım otomatik olarak başlar (eğer **kurulum yardımcısında** ise)
* **`CPInstallActivationProfile`** tarafından yönlendirilir
* mdmclient üzerinden XPC ile uygulanır
* LaunchDaemon (root olarak) veya LaunchAgent (kullanıcı olarak), bağlama bağlı olarak
* Yapılandırma profilleri yüklemek için birden fazla yük içerir
* Framework, profilleri yüklemek için eklenti tabanlı bir mimariye sahiptir
* Her yük türü bir eklentiyle ilişkilendirilir
* XPC (çerçevede) veya klasik Cocoa (ManagedClient.app içinde) olabilir
* Örnek:
* Sertifika Yükleri SertifikaServisi.xpc kullanır

Genellikle bir MDM satıcısı tarafından sağlanan **aktivasyon profili**, aşağıdaki yükleri içerecektir:

* Cihazı MDM'ye **kaydetmek** için `com.apple.mdm`
* Cihaza güvenli bir şekilde bir **istemci sertifikası** sağlamak için `com.apple.security.scep`
* Cihazın Sistem Anahtar Zincirine **güvenilir CA sertifikaları yüklemek** için `com.apple.security.pem`
* MDM yükünü yüklemek, belgelerdeki **MDM kontrolüne** eşdeğerdir
* Yük, aşağıdaki ana özellikleri içerir:
*
* MDM Kontrolü URL'si (**`CheckInURL`**)
* MDM Komut Anketleme URL'si (**`ServerURL`**) + tetiklemek için APNs konusu
* MDM yükünü yüklemek için istek **`CheckInURL`** adresine gönderilir
* **`mdmclient`** tarafından uygulanır
* MDM yükü diğer yüklerden bağımlı olabilir
* **İsteklerin belirli sertifikalara sabitlenmesine izin verir**:
* Özellik: **`CheckInURLPinningCertificateUUIDs`**
* Özellik: **`ServerURLPinningCertificateUUIDs`**
* PEM yükü ile iletilir
* Cihazın bir kimlik sertifikası ile ilişkilendirilmesine izin verir:
* Özellik: KimlikSertifikasiUUID
* SCEP yükü ile iletilir

### Adım 7: MDM komutlarını dinleme

MDM kontrolü tamamlandıktan sonra, satıcı APNs'yi kullanarak **itme bildirimleri** gönderebilir
Alındığında, **`mdmclient`** tarafından işlenir
MDM komutları için anket yapmak için istek **ServerURL** adresine gönderilir
Daha önce yüklenen MDM yükü kullanılır:
İsteği sabitlemek için **`ServerURLPinningCertificateUUIDs`**
TLS istemci sertifikası için **`IdentityCertificateUUID`**
