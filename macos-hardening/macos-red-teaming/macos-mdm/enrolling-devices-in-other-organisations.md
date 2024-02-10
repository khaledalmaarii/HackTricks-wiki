# Diğer Organizasyonlara Cihaz Kaydetme

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

## Giriş

[**Daha önce belirtildiği gibi**](./#what-is-mdm-mobile-device-management)**,** bir cihazı bir organizasyona kaydetmek için **yalnızca o Organizasyona ait bir Seri Numarası gereklidir**. Cihaz kaydedildikten sonra, birçok organizasyon yeni cihaza hassas veriler yükleyecektir: sertifikalar, uygulamalar, WiFi şifreleri, VPN yapılandırmaları [ve benzeri](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Bu nedenle, kayıt süreci doğru şekilde korunmadığında saldırganlar için tehlikeli bir giriş noktası olabilir.

**Aşağıdaki, araştırmanın özeti [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Teknik ayrıntılar için kontrol edin!**

## DEP ve MDM İkili Analizine Genel Bakış

Bu araştırma, macOS'ta Cihaz Kayıt Programı (DEP) ve Mobil Cihaz Yönetimi (MDM) ile ilişkili ikili dosyalara derinlemesine iner. Ana bileşenler şunları içerir:

- **`mdmclient`**: macOS 10.13.4 öncesi sürümlerde MDM sunucularıyla iletişim kurar ve DEP kontrol noktalarını tetikler.
- **`profiles`**: Yapılandırma Profillerini yönetir ve macOS 10.13.4 ve sonraki sürümlerde DEP kontrol noktalarını tetikler.
- **`cloudconfigurationd`**: DEP API iletişimlerini yönetir ve Cihaz Kayıt profillerini alır.

DEP kontrol noktaları, Aktivasyon Kaydını almak için özel Yapılandırma Profilleri çerçevesinden `CPFetchActivationRecord` ve `CPGetActivationRecord` işlevlerini kullanır ve `CPFetchActivationRecord`, XPC aracılığıyla `cloudconfigurationd` ile koordine olur.

## Tesla Protokolü ve Absinthe Şemasının Tersine Mühendisliği

DEP kontrol noktası, `cloudconfigurationd`nin şifrelenmiş, imzalı bir JSON yükünü _iprofiles.apple.com/macProfile_ adresine göndermesini içerir. Yük, cihazın seri numarasını ve "RequestProfileConfiguration" eylemini içerir. Kullanılan şifreleme şeması, içeriden "Absinthe" olarak adlandırılır. Bu şemanın çözülmesi karmaşıktır ve birçok adım içerir, bu da Aktivasyon Kaydı isteğinde keyfi seri numaraları eklemek için alternatif yöntemleri keşfetmeye yol açmıştır.

## DEP İsteklerinin Proxy Edilmesi

Charles Proxy gibi araçlar kullanılarak _iprofiles.apple.com_ adresine yönelik DEP isteklerinin yakalanması ve değiştirilmesi girişimleri, yük şifrelemesi ve SSL/TLS güvenlik önlemleri nedeniyle engellenmiştir. Bununla birlikte, `MCCloudConfigAcceptAnyHTTPSCertificate` yapılandırmasının etkinleştirilmesi, sunucu sertifikası doğrulamasını atlamayı sağlar, ancak yükün şifreli olması seri numarasının şifre çözme anahtarı olmadan değiştirilmesini engeller.

## DEP ile Etkileşim Halindeki Sistem İkili Dosyalarının Enstrümantasyonu

`cloudconfigurationd` gibi sistem ikili dosyalarının enstrümantasyonu, macOS'ta Sistem Bütünlük Koruması'nın (SIP) devre dışı bırakılmasını gerektirir. SIP devre dışı bırakıldığında, LLDB gibi araçlar sistem süreçlerine bağlanmak ve DEP API etkileşimlerinde kullanılan seri numarasını potansiyel olarak değiştirmek için kullanılabilir. Bu yöntem, yetkilendirmelerin ve kod imzalamanın karmaşıklıklarını önlediği için tercih edilir.

**İkili Enstrümantasyonun Sömürülmesi:**
`cloudconfigurationd`de JSON serileştirmeden önce DEP isteği yükünün değiştirilmesi etkili oldu. Süreç şunları içeriyordu:

1. LLDB'yi `cloudconfigurationd`ye bağlamak.
2. Sistem seri numarasının alındığı noktayı bulmak.
3. Yük şifrelenip gönderilmeden önce belleğe keyfi bir seri numarası enjekte etmek.

Bu yöntem, keyfi seri numaraları için tam DEP profillerinin alınmasına olanak sağladı ve potansiyel bir güvenlik açığı gösterdi.

### Python ile Enstrümantasyonun Otomatikleştirilmesi

Sömürü süreci, LLDB API'si kullanılarak Python ile otomatikleştirildi, bu da keyfi seri numaraları programatik olarak enjekte etmeyi ve ilgili DEP profillerini almayı mümkün kıldı.

### DEP ve MDM Güvenlik Açıklarının Potansiyel Etkileri

Araştırma, önemli güvenlik endişelerini vurguladı:

1. **Bilgi Sızdırma**: DEP kayıtlı bir seri numarası sağlayarak, DEP profili içinde bulunan hassas kurumsal bilgiler alınabilir.
2. **Sahte DEP Kaydı**: Doğru kimlik doğrulama olmadan, DEP kayıtlı bir seri numarasına sahip bir saldırgan, kuruluşun MDM sunucusuna sahte bir cihaz kaydedebilir ve hassas verilere ve ağ kaynaklarına erişim elde edebilir.

Sonuç olarak, DEP ve MDM, kurumsal ortamlarda Apple cihazlarını yönetmek için güçlü araçlar sağlasa da, güvenli ve izlenmesi gereken potansiyel saldırı vektörleri de sunar.
