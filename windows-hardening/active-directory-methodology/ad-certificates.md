# AD Sertifikaları

<details>

<summary><strong>AWS hackleme becerilerinizi sıfırdan ileri seviyeye taşıyın</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile</strong>!</summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı yapmak** veya HackTricks'i **PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi paylaşarak** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **katkıda bulunun**.

</details>

## Giriş

### Bir Sertifikanın Bileşenleri

- Sertifikanın **Konusu**, sahibini belirtir.
- Bir sertifikayı sahibiyle ilişkilendirmek için bir **Genel Anahtar**, özel olarak tutulan bir anahtarla eşleştirilir.
- **Geçerlilik Süresi**, **NotBefore** ve **NotAfter** tarihleriyle belirlenir ve sertifikanın etkin süresini işaretler.
- Sertifika Otoritesi (CA) tarafından sağlanan benzersiz bir **Seri Numarası**, her sertifikayı tanımlar.
- **Düzenleyen**, sertifikayı veren CA'ya atıfta bulunur.
- **SubjectAlternativeName**, kimlik esnekliğini artıran konu için ek isimlere izin verir.
- **Temel Kısıtlamalar**, sertifikanın bir CA veya son kullanıcı için olup olmadığını belirler ve kullanım kısıtlamalarını tanımlar.
- **Genişletilmiş Anahtar Kullanımları (EKU'lar)**, Nesne Tanımlayıcıları (OID'ler) aracılığıyla sertifikanın belirli amaçlarını, kod imzalama veya e-posta şifreleme gibi, belirtir.
- **İmza Algoritması**, sertifikayı imzalamak için kullanılan yöntemi belirtir.
- İmza, düzenleyenin özel anahtarıyla oluşturulur ve sertifikanın otantikliğini garanti eder.

### Özel Düşünceler

- **Subject Alternative Names (SAN'lar)**, bir sertifikayı birden fazla kimliğe uygulanabilir hale getirir ve birden çok alan adına sahip sunucular için önemlidir. SAN belirtisini manipüle ederek saldırganların taklit risklerini önlemek için güvenli verme süreçleri önemlidir.

### Active Directory (AD) içindeki Sertifika Otoriteleri (CA'lar)

AD CS, AD ormanında CA sertifikalarını belirli konteynerler aracılığıyla tanır ve her biri benzersiz rolleri olan:

- **Sertifikasyon Otoriteleri** konteyneri, güvenilen kök CA sertifikalarını içerir.
- **Kayıt Hizmetleri** konteyneri, Kurumsal CA'ları ve sertifika şablonlarını ayrıntılı olarak belirtir.
- **NTAuthCertificates** nesnesi, AD kimlik doğrulaması için yetkilendirilmiş CA sertifikalarını içerir.
- **AIA (Yetkilendirme Bilgi Erişimi)** konteyneri, ara ve çapraz CA sertifikalarıyla sertifika zinciri doğrulamasını kolaylaştırır.

### Sertifika Edinme: İstemci Sertifikası İstek Akışı

1. İstek süreci, istemcilerin bir Kurumsal CA bulmasiyla başlar.
2. Bir CSR oluşturulur, bir genel anahtar ve diğer ayrıntıları içerir, genel-özel anahtar çifti oluşturulduktan sonra.
3. CA, CSR'yi mevcut sertifika şablonlarına karşı değerlendirir ve şablonun izinlerine dayanarak sertifikayı verir.
4. Onaylandıktan sonra, CA sertifikayı özel anahtarıyla imzalar ve istemciye geri gönderir.

### Sertifika Şablonları

AD içinde tanımlanan bu şablonlar, sertifikaların verilmesi için ayarları ve izinleri belirtir. Bu, sertifika hizmetlerine erişimi yönetmek için kritik olan izinli EKU'ları ve kayıt veya değiştirme haklarını içerir.

## Sertifika Kaydı

Sertifikalar için kayıt süreci, bir yönetici tarafından **bir sertifika şablonu oluşturularak başlatılır** ve ardından Kurumsal Sertifika Otoritesi (CA) tarafından **yayınlanır**. Bu, şablonun adını bir Active Directory nesnesinin `certificatetemplates` alanına ekleyerek istemci kaydını mümkün kılar.

Bir istemcinin bir sertifika talep etmesi için **kayıt hakları** verilmelidir. Bu haklar, sertifika şablonunun ve Kurumsal CA'nın güvenlik tanımlayıcıları tarafından belirlenir. İstek başarılı olması için her iki konumda da izinlerin verilmesi gerekir.

### Şablon Kayıt Hakları

Bu haklar, Erişim Kontrol Girişleri (ACE'ler) aracılığıyla belirtilir ve şunları içerir:
- **Certificate-Enrollment** ve **Certificate-AutoEnrollment** hakları, her biri belirli GUID'lerle ilişkilidir.
- **ExtendedRights**, tüm genişletilmiş izinlere izin verir.
- **FullControl/GenericAll**, şablona tam kontrol sağlar.

### Kurumsal CA Kayıt Hakları

CA'nın hakları, Sertifika Otoritesi yönetim konsolu üzerinden erişilebilen güvenlik tanımlayıcısıyla belirtilir. Bazı ayarlar, düşük ayrıcalıklı kullanıcılara uzaktan erişim izni verir, bu da bir güvenlik endişesi olabilir.

### Ek Verme Kontrolleri

Belirli kontroller uygulanabilir, örneğin:
- **Yönetici Onayı**: İstekleri onaylanana kadar beklemeye alır.
- **Kayıt Ajanları ve Yetkili İmzalar**: CSR üzerinde gereken imzaların sayısını ve gerekli Uygulama Politikası OID'lerini belirtir.

### Sertifikaları Talep Etme Yöntemleri

Sertifikalar aşağıdaki yöntemlerle talep edilebilir:
1. **Windows İstemci Sertifika Kayıt Protokolü** (MS-WCCE), DCOM arabirimlerini kullanarak.
2. **ICertPassage Uzak Protokolü** (MS-ICPR), adlandırılmış borular veya TCP/IP aracılığıyla.
3. **Sertifika kayıt web arayüzü**, Sertifika Otoritesi Web Kaydı rolü yüklü olduğunda.
4. **Sertifika Kayıt Hizmeti** (CES), Sertifika Kayıt Politikası (CEP) hizmetiyle birlikte kullanılır.
5. Ağ cihazları için **Ağ Cihazı Kayıt Hizmeti** (NDES), Basit Sertifika Kayıt Protokolü (SCEP) kullanılarak.

Windows kullanıcıları, GUI (`certmgr.msc` veya `certlm.msc`) veya komut satırı araçları (`certreq.exe` veya PowerShell'ın `Get-Certificate` komutu) aracılığıyla da sertifikalar talep edebilir.
```powershell
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Sertifika Kimlik Doğrulama

Active Directory (AD), öncelikle **Kerberos** ve **Secure Channel (Schannel)** protokollerini kullanarak sertifika kimlik doğrulamayı destekler.

### Kerberos Kimlik Doğrulama Süreci

Kerberos kimlik doğrulama sürecinde, bir kullanıcının Bilet Verme Biletine (TGT) yönelik isteği, kullanıcının sertifikasının **özel anahtarı** kullanılarak imzalanır. Bu istek, sertifikanın **geçerlilik**, **yol** ve **iptal durumu** gibi bir dizi doğrulama işleminden geçer. Doğrulamalar arasında sertifikayı güvenilir bir kaynaktan aldığı ve yayıncının **NTAUTH sertifika deposu**'nda bulunduğu doğrulanır. Başarılı doğrulamalar sonucunda bir TGT verilir. AD'deki **`NTAuthCertificates`** nesnesi, aşağıdaki konumda bulunur:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
# AD Sertifikaları

Sertifika kimlik doğrulaması için güveni sağlamak için merkezi bir rol oynar.

### Güvenli Kanal (Schannel) Kimlik Doğrulaması

Schannel, el sıkışma sırasında başarılı bir şekilde doğrulanan bir sertifika sunan istemci tarafından erişimi yetkilendiren güvenli TLS/SSL bağlantılarını kolaylaştırır. Bir sertifikanın bir AD hesabına eşlenmesi, diğer yöntemler arasında Kerberos'un **S4U2Self** işlevi veya sertifikanın **Alternatif Konu Adı (SAN)** kullanılarak gerçekleştirilebilir.

### AD Sertifika Hizmetleri Sorgulama

AD'nin sertifika hizmetleri, LDAP sorguları aracılığıyla sorgulanabilir ve **Kurumsal Sertifika Yetkilileri (CA'lar)** ve yapılandırmaları hakkında bilgi ortaya çıkarabilir. Bu, özel ayrıcalıklara sahip olmadan herhangi bir etki alanı doğrulama yetkisine sahip kullanıcı tarafından erişilebilir. AD CS ortamlarında sorgulama ve zafiyet değerlendirmesi için **[Certify](https://github.com/GhostPack/Certify)** ve **[Certipy](https://github.com/ly4k/Certipy)** gibi araçlar kullanılır.

Bu araçları kullanmak için kullanılan komutlar:
```bash
# Enumerate trusted root CA certificates and Enterprise CAs with Certify
Certify.exe cas
# Identify vulnerable certificate templates with Certify
Certify.exe find /vulnerable

# Use Certipy for enumeration and identifying vulnerable templates
certipy find -vulnerable -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
## Referanslar

* [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)
* [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana dönüşmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'da takip edin.**
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>
