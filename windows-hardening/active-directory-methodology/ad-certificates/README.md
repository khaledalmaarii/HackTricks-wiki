# AD Sertifikaları

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na(https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünleri**](https://peass.creator-spring.com)'ni edinin
* [**PEASS Ailesi**]'ni(https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**]'i(https://opensea.io/collection/the-peass-family) içeren koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'da **takip edin**.
* **Hacking püf noktalarınızı göndererek HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR'lar göndererek paylaşın.

</details>

## Giriş

### Bir Sertifikanın Bileşenleri

- Sertifikanın **Konusu**, sahibini belirtir.
- Bir **Genel Anahtar**, sertifikayı sahibine bağlamak için özel olarak tutulan bir anahtarla eşleştirilir.
- **Geçerlilik Süresi**, **NotBefore** ve **NotAfter** tarihleri tarafından tanımlanır ve sertifikanın etkin süresini belirler.
- Sertifika için her birini tanımlayan benzersiz bir **Seri Numarası**, Sertifika Yetkilisi (CA) tarafından sağlanır.
- **Veren**, sertifikayı veren CA'yı ifade eder.
- **SubjectAlternativeName**, konu için ek isimlere izin verir, tanımlama esnekliğini artırır.
- **Temel Kısıtlamalar**, sertifikanın bir CA için mi yoksa bir son varlık için mi olduğunu belirler ve kullanım kısıtlamalarını tanımlar.
- **Genişletilmiş Anahtar Kullanımları (EKU'lar)**, sertifikanın belirli amaçlarını, kod imzalama veya e-posta şifreleme gibi, Nesne Tanımlayıcılar (OID'ler) aracılığıyla belirler.
- **İmza Algoritması**, sertifikayı imzalamak için kullanılan yöntemi belirtir.
- **İmza**, sertifikanın otantikliğini garanti etmek için verenin özel anahtarıyla oluşturulur.

### Özel Düşünceler

- **Konu Alternatif İsimler (SAN'lar)**, bir sertifikanın birden fazla kimliğe uygulanabilirliğini genişletir, birden fazla alanı olan sunucular için kritiktir. Saldırganların SAN belirtimini manipüle ederek taklit risklerini önlemek için güvenli verme süreçleri hayati önem taşır.

### Active Directory (AD) içinde Sertifika Yetkilileri (CA'lar)

AD CS, AD ormanında CA sertifikalarını belirli konteynerler aracılığıyla tanır, her biri benzersiz rolleri yerine getirir:

- **Sertifika Yetkilileri** konteyneri güvenilir kök CA sertifikalarını içerir.
- **Kayıt Hizmetleri** konteyneri Kurumsal CA'ları ve sertifika şablonlarını detaylandırır.
- **NTAuthCertificates** nesnesi, AD kimlik doğrulaması için yetkilendirilmiş CA sertifikalarını içerir.
- **AIA (Yetki Bilgi Erişimi)** konteyneri, ara ve çapraz CA sertifikaları ile sertifika zinciri doğrulamasını kolaylaştırır.

### Sertifika Edinme: İstemci Sertifikası İsteme Akışı

1. İstek süreci, istemcilerin bir Kurumsal CA bulmasına başlar.
2. Bir genel-özel anahtar çifti oluşturulduktan sonra bir CSR oluşturulur, sertifika şablonunun izinlerine dayanarak sertifikayı veren CA, CSR'yi değerlendirir.
3. Onaylandıktan sonra, CA sertifikayı özel anahtarıyla imzalar ve istemciye geri gönderir.

### Sertifika Şablonları

AD içinde tanımlanan bu şablonlar, sertifikaların verilmesi için ayarları ve izinleri belirler, sertifika hizmetlerine erişimi yönetmek için kritiktir.

## Sertifika Kaydı

Sertifikalar için kayıt süreci, bir yönetici tarafından **bir sertifika şablonu oluşturularak başlatılır**, ardından bir Kurumsal Sertifika Yetkilisi (CA) tarafından **yayınlanır**. Bu, şablonun adını bir Active Directory nesnesinin `certificatetemplates` alanına ekleyerek istemci kaydını mümkün kılar.

Bir istemcinin sertifika isteğinde bulunabilmesi için **kayıt hakları** verilmelidir. Bu haklar, sertifika şablonundaki güvenlik tanımlayıcıları ve Kurumsal CA'nın kendisi üzerinde tanımlanır. İstek başarılı olabilmesi için her iki konumda da izinlerin verilmesi gerekir.

### Şablon Kayıt Hakları

Bu haklar, Erişim Kontrol Girişleri (ACE'ler) aracılığıyla belirtilir ve **Sertifika-Kaydı** ve **Sertifika-OtomatikKaydı** hakları gibi izinleri detaylandırır.
- **Genişletilmiş Haklar**, tüm genişletilmiş izinleri sağlar.
- **Tam Kontrol/Genel Tümü**, şablona tam kontrol sağlar.

### Kurumsal CA Kayıt Hakları

CA'nın hakları, Sertifika Yetkilisi yönetim konsolu aracılığıyla erişilebilen güvenlik tanımlayıcılarında belirtilir. Bazı ayarlar, düşük ayrıcalıklı kullanıcılara uzaktan erişim izni verebilir, bu da bir güvenlik endişesi olabilir.

### Ek İşlem Kontrolleri

Belirli kontroller uygulanabilir, örneğin:
- **Yönetici Onayı**: Sertifika yöneticisi tarafından onaylanana kadar istekleri bekleme durumuna alır.
- **Kayıt Ajanları ve Yetkili İmzalar**: CSR üzerinde gereken imza sayısını ve gerekli Uygulama Politikası OID'lerini belirtir.

### Sertifikaları İsteğe Bağlı Yöntemler

Sertifikalar, şu yollarla istenebilir:
1. **Windows İstemci Sertifika Kayıt Protokolü** (MS-WCCE), DCOM arayüzlerini kullanarak.
2. **ICertPassage Uzak Protokolü** (MS-ICPR), adlandırılmış borular veya TCP/IP aracılığıyla.
3. **Sertifika kayıt web arayüzü**, Sertifika Yetkilisi Web Kaydı rolü yüklüyse.
4. **Sertifika Kayıt Hizmeti** (CES), Sertifika Kayıt Politikası (CEP) hizmeti ile birlikte.
5. **Ağ Cihazı Kayıt Hizmeti** (NDES), Basit Sertifika Kayıt Protokolü (SCEP) kullanarak ağ cihazları için.

Windows kullanıcıları ayrıca sertifikaları GUI (`certmgr.msc` veya `certlm.msc`) veya komut satırı araçları (`certreq.exe` veya PowerShell'ın `Get-Certificate` komutu) aracılığıyla da isteyebilir.
```powershell
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Sertifika Doğrulaması

Active Directory (AD), genellikle **Kerberos** ve **Güvenli Kanal (Schannel)** protokollerini kullanarak sertifika doğrulamasını destekler.

### Kerberos Doğrulama Süreci

Kerberos doğrulama sürecinde, bir kullanıcının Bir Bilet Verme Bileti (TGT) talebi, kullanıcının sertifikasının **özel anahtarı** kullanılarak imzalanır. Bu talep, sertifikanın **geçerliliği**, **yolu** ve **iptal durumu** dahil olmak üzere alan denetimlerinden geçer. Doğrulamalar arasında sertifikanın güvenilir bir kaynaktan geldiğinin doğrulanması ve yayıncının **NTAUTH sertifika deposu**'ndaki varlığının onaylanması da bulunmaktadır. Başarılı doğrulamalar, bir TGT'nin verilmesiyle sonuçlanır. AD'deki **`NTAuthCertificates`** nesnesi şurada bulunabilir:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
### Güvenilirlik sertifika kimlik doğrulaması için temel oluşturur.

### Güvenli Kanal (Schannel) Kimlik Doğrulaması

Schannel, güvenli TLS/SSL bağlantılarını kolaylaştırır, el sıkışma sırasında istemci başarılı bir şekilde doğrulanan bir sertifika sunar ve erişimi yetkilendirir. Bir sertifikanın bir AD hesabına eşlenmesi, Kerberos'un **S4U2Self** işlevini veya sertifikanın **Konu Alternatif Adı (SAN)** gibi diğer yöntemleri içerebilir.

### AD Sertifika Hizmetleri Numaralandırma

AD'nin sertifika hizmetleri, LDAP sorguları aracılığıyla numaralandırılabilir, **Kurumsal Sertifika Yetkilileri (CAs)** ve yapılandırmaları hakkında bilgi ortaya çıkarabilir. Bu, özel ayrıcalıklara sahip olmayan herhangi bir etki alanı doğrulama yapılmış kullanıcı tarafından erişilebilir. **[Certify](https://github.com/GhostPack/Certify)** ve **[Certipy](https://github.com/ly4k/Certipy)** gibi araçlar, AD CS ortamlarında numaralandırma ve zayıflık değerlendirmesi için kullanılır.

Bu araçları kullanmak için komutlar:
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

<summary><strong>Sıfırdan kahraman olana kadar AWS hacklemeyi öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'da **takip edin**.**
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
