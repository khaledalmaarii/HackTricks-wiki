# macOS MDM

<details>

<summary><strong>AWS hackleme hakkında sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family)
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek** paylaşın.

</details>

**macOS MDM hakkında bilgi edinmek için:**

* [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
* [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## Temel Bilgiler

### **MDM (Mobil Cihaz Yönetimi) Genel Bakışı**

[Mobil Cihaz Yönetimi](https://en.wikipedia.org/wiki/Mobile\_device\_management) (MDM), akıllı telefonlar, dizüstü bilgisayarlar ve tabletler gibi çeşitli son kullanıcı cihazlarının yönetimi için kullanılır. Özellikle Apple platformları (iOS, macOS, tvOS) için, özel özellikler, API'ler ve uygulamalar içerir. MDM'nin işleyişi, ticari olarak temin edilebilen veya açık kaynaklı olan uyumlu bir MDM sunucusuna dayanır ve [MDM Protokolü](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf)'nü desteklemelidir. Ana noktalar şunları içerir:

* Cihazlar üzerinde merkezi kontrol.
* MDM protokolüne uyumlu bir MDM sunucusuna bağımlılık.
* MDM sunucusunun, uzaktan veri silme veya yapılandırma yükleme gibi çeşitli komutları cihazlara iletebilme yeteneği.

### **DEP (Cihaz Kayıt Programı) Temelleri**

Apple tarafından sunulan [Cihaz Kayıt Programı](https://www.apple.com/business/site/docs/DEP\_Guide.pdf) (DEP), iOS, macOS ve tvOS cihazları için sıfır dokunuşlu yapılandırmayı kolaylaştırarak Mobil Cihaz Yönetimi (MDM) entegrasyonunu basitleştirir. DEP, cihazların kutudan çıkar çıkmaz, kullanıcı veya yönetici müdahalesiyle minimum düzeyde, operasyonel hale gelmesini otomatikleştirir. Temel noktalar şunları içerir:

* Cihazların ilk etkinleştirme sırasında önceden tanımlanmış bir MDM sunucusuna otomatik olarak kaydolmasını sağlar.
* Öncelikle yeni cihazlar için faydalıdır, ancak yeniden yapılandırma sürecinde olan cihazlar için de uygulanabilir.
* Cihazların hızlı bir şekilde kuruluma hazır hale gelmesini sağlayan basit bir kurulumu kolaylaştırır.

### **Güvenlik Düşünceleri**

DEP tarafından sağlanan kayıt kolaylığının, faydalı olmasının yanı sıra güvenlik riskleri de oluşturabileceği önemlidir. MDM kaydı için yeterli koruyucu önlemler uygulanmazsa, saldırganlar bu kolaylaştırılmış süreci kullanarak kuruluşun MDM sunucusuna kurumsal bir cihaz gibi kaydolabilirler.

{% hint style="danger" %}
**Güvenlik Uyarısı**: Basitleştirilmiş DEP kaydı, uygun koruma önlemleri alınmadığında yetkisiz cihaz kaydına izin verebilir.
{% endhint %}

### Temel Bilgiler SCEP (Basit Sertifika Kaydı Protokolü) Nedir?

* Nispeten eski bir protokol, TLS ve HTTPS yaygınlaşmadan önce oluşturulmuştur.
* İstemcilere bir **Sertifika İmzalama İsteği** (CSR) göndermek için standartlaştırılmış bir yol sağlar. İstemci, sunucudan kendisine imzalı bir sertifika vermesini ister.

### Yapılandırma Profilleri (aka mobileconfigs) Nedir?

* Apple'ın resmi **sistem yapılandırmasını belirleme/zorlama** yoludur.
* Birden çok yük taşıyabilen dosya formatı.
* Özellik listelerine (XML türündeki) dayanır.
* "kökenlerini doğrulamak, bütünlüklerini sağlamak ve içeriklerini korumak için imzalanabilir ve şifrelenebilir." Temel — Sayfa 70, iOS Güvenlik Kılavuzu, Ocak 2018.

## Protokoller

### MDM

* APNs (**Apple sunucuları**) + RESTful API (**MDM** **satıcı** sunucuları) kombinasyonu
* İletişim, bir **cihaz** ve bir **cihaz yönetimi** **ürününe** bağlı bir sunucu arasında gerçekleşir
* **Komutlar**, MDM'den cihaza **plist kodlu sözlükler** şeklinde iletilir
* Tümüyle **HTTPS** üzerinden. MDM sunucuları genellikle sabitlenir.
* Apple, MDM satıcısına kimlik doğrulaması için bir **APNs sertifikası** verir

### DEP

* **3 API**: bayiler için 1, MDM satıcıları için 1, cihaz kimliği için 1 (belgelenmemiş):
* Sözde [DEP "bulut hizmeti" API'si](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Bu, MDM sunucularının DEP profillerini belirli cihazlarla ilişkilendirmek için kullandığı API'dir.
* [Apple Yetkili Bayileri tarafından kullanılan DEP API'si](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html), cihazları kaydetmek, kayıt durumunu kontrol etmek ve işlem durumunu kontrol etmek için kullanılır.
* Belgelenmemiş özel DEP API'si. Bu, Apple Cihazlarının DEP profillerini istemek için kullanılır. macOS'ta, `cloudconfigurationd` ikili dosyası bu API üzerinden iletişim kurar.
* Daha modern ve **JSON** tabanlı (plist'e karşı)
* Apple, MDM satıcısına bir **OAuth belirteci** verir

**DEP "bulut hizmeti" API'si**

* RESTful
* Apple'dan MDM sunucusuna cihaz kayıtlarını senkronize eder
* Apple'dan daha sonra cihaza teslim edilen DEP profillerini senkronize eder
* Bir DEP "profil"i şunları içerir:
* MDM satıcı sunucusu URL'si
* Sunucu URL'si için ek güvenilir sertifikalar (isteğe bağlı sabitleme)
* Ek ayarlar (örneğin, Kurulum Yardımcısı'nda hangi ekranların atlanacağı)

## Seri Numarası

2010'dan sonra üretilen Apple cihazlarının genellikle **12 karakterli alfasayısal** seri numaraları vardır. İlk üç rakam üretim yeri, takip eden iki rakam üretim yılı ve haftasını, bir sonraki üç rakam benzersiz bir tanımlayıcıyı ve son dört rakam model numarasını temsil eder.

\{% content-ref url

### Adım 4: DEP kontrolü - Etkinleştirme Kaydını Alma

Bu sürecin bir parçası, bir kullanıcının bir Mac'i ilk kez başlattığında (veya tam bir silme işleminden sonra) gerçekleşir.

![](<../../../.gitbook/assets/image (568).png>)

veya `sudo profiles show -type enrollment` komutunu çalıştırdığında

* Cihazın DEP özellikli olup olmadığını belirleme
* Etkinleştirme Kaydı, DEP "profilinin" iç ismidir
* Cihazın İnternet'e bağlandığı anda başlar
* **`CPFetchActivationRecord`** tarafından yönlendirilir
* **`cloudconfigurationd`** tarafından XPC aracılığıyla uygulanır. Cihaz ilk kez başlatıldığında "Kurulum Yardımcısı" veya `profiles` komutu, etkinleştirme kaydını almak için bu hizmete başvurur.
* LaunchDaemon (her zaman root olarak çalışır)

**`MCTeslaConfigurationFetcher`** tarafından gerçekleştirilen Etkinleştirme Kaydını almak için birkaç adım izlenir. Bu işlem **Absinthe** adı verilen bir şifreleme kullanır.

1. **Sertifika** alınır
2. [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer) adresine GET isteği gönderilir
3. Sertifikadan durum başlatılır (**`NACInit`**)
4. Çeşitli cihaz özel verileri kullanılır (örneğin **`IOKit`** üzerinden Seri Numarası)
5. **Oturum anahtarı** alınır
6. [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session) adresine POST isteği gönderilir
7. Oturum kurulur (**`NACKeyEstablishment`**)
8. İstek yapılır
9. Veri `{ "action": "RequestProfileConfiguration", "sn": "" }` şeklinde [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) adresine POST isteği gönderilir
10. JSON verisi Absinthe kullanılarak şifrelenir (**`NACSign`**)
11. Tüm istekler HTTPS üzerinden yapılır ve yerleşik kök sertifikalar kullanılır

![](<../../../.gitbook/assets/image (566).png>)

Yanıt, aşağıdaki gibi bazı önemli veriler içeren bir JSON sözlüğüdür:

* **url**: Etkinleştirme profili için MDM satıcısı ana bilgisayarının URL'si
* **anchor-certs**: Güvenilir kök sertifikalarının DER biçimindeki dizisi

### **Adım 5: Profil Alma**

![](<../../../.gitbook/assets/image (567).png>)

* DEP profili tarafından sağlanan **url'ye istek gönderilir**.
* Eğer sağlanmışsa, **anchor sertifikaları** güveni değerlendirmek için kullanılır.
* Hatırlatma: DEP profili'nin **anchor\_certs** özelliği
* İstek, cihaz kimlik bilgileriyle birlikte basit bir .plist dosyasıdır
* Örnekler: **UDID, işletim sistemi sürümü**.
* CMS ile imzalanmış, DER kodlanmış
* Cihaz kimlik sertifikası (APNS'den) kullanılarak imzalanmıştır
* **Sertifika zinciri**, süresi dolmuş **Apple iPhone Device CA** içerir

![](https://github.com/carlospolop/hacktricks/blob/tr/.gitbook/assets/image%20\(567\)%20\(1\)%20\(2\)%20\(2\)%20\(2\)%20\(2\)%20\(2\)%20\(2\)%20\(2\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(7\).png)

### Adım 6: Profil Kurulumu

* Alındıktan sonra, **profil sistemde depolanır**
* Bu adım otomatik olarak başlar (eğer **kurulum yardımcısı** içindeyse)
* **`CPInstallActivationProfile`** tarafından yönlendirilir
* mdmclient tarafından XPC üzerinden uygulanır
* LaunchDaemon (root olarak) veya LaunchAgent (kullanıcı olarak), bağlama bağlı olarak
* Yapılandırma profillerinin kurulumu için birden fazla yük vardır
* Profil kurulumu için eklenti tabanlı bir mimariye sahiptir
* Her yük türü bir eklentiyle ilişkilendirilir
* XPC (çerçevede) veya klasik Cocoa (ManagedClient.app içinde) olabilir
* Örnek:
* Sertifika Yükleri, CertificateService.xpc kullanır

Genellikle, bir MDM satıcısı tarafından sağlanan **etkinleştirme profili** aşağıdaki yükleri içerir:

* `com.apple.mdm`: Cihazı MDM'e **kaydetmek** için
* `com.apple.security.scep`: Cihaza güvenli bir **istemci sertifikası** sağlamak için
* `com.apple.security.pem`: Cihazın Sistem Anahtar Zincirine **güvenilir CA sertifikaları kurmak** için
* MDM yükünün belgelerdeki MDM check-in'e **eşdeğer olduğu** şeklinde kurulumu
* Yük, aşağıdaki ana özellikleri içerir:
*
* MDM Check-In URL'si (**`CheckInURL`**)
* MDM Komut Anketleme URL'si (**`ServerURL`**) + tetiklemek için APNs konusu
* MDM yükünü kurmak için istek **`CheckInURL`** adresine gönderilir
* **`mdmclient`** tarafından uygulanır
* MDM yükü diğer yüklerden bağımlı olabilir
* İsteklerin belirli sertifikalara **sabitlenmesine izin verir**:
* Özellik: **`CheckInURLPinningCertificateUUIDs`**
* Özellik: **`ServerURLPinningCertificateUUIDs`**
* PEM yükü ile teslim edilir
* Cihazın bir kimlik sertifikasıyla ilişkilendirilmesine izin verir:
* Özellik: IdentityCertificateUUID
* SCEP yükü ile teslim edilir

### **Adım 7: MDM komutlarını dinleme**

MDM check-in tamamlandıktan sonra, satıcı APNs kullanarak **bildirimler gönderebilir** Alındığında, **`mdmclient`** tarafından işlenir MDM komutlarını sorgulamak için istek **ServerURL** adresine gönderilir Daha önceden kurulan MDM yükü kullanılır: İstek için **`ServerURLPinningCertificateUUIDs`** sabitleme için TLS istemci sertifikası için **`IdentityCertificateUUID`** kullanılır

## Saldırılar

### Başka Kuruluşlara Cihaz Kaydetme

Daha önce belirtildiği gibi, bir cihazı bir kuruluşa kaydetmek için **yalnızca o Kuruluşa ait bir Seri Numarası gereklidir**. Cihaz kaydedildikten sonra, birçok kuruluş yeni cihaza hassas veriler yükleyecektir: sertifikalar, uygulamalar, WiFi şifreleri, VPN yapılandırmaları [ve benzeri](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Bu nedenle, kayıt süreci doğru şekilde korunmazsa, bu saldırganlar için tehlikeli bir giriş noktası olabilir:

{% content-ref url="enrolling-devices-in-other-organisations.md" %}
[enrolling-devices-in-other-organisations.md](enrolling-devices-in-other-organisations.md)
{% endcontent-ref %}

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a> <strong>ile öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks't

</details>
