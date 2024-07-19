# AD Certificates

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Introduction

### Components of a Certificate

- Sertifikanın **Sahibi**, sertifikanın sahibini belirtir.
- **Açık Anahtar**, sertifikayı gerçek sahibine bağlamak için özel bir anahtarla eşleştirilir.
- **Geçerlilik Süresi**, **NotBefore** ve **NotAfter** tarihleri ile tanımlanır ve sertifikanın etkin süresini işaret eder.
- Sertifika Otoritesi (CA) tarafından sağlanan benzersiz bir **Seri Numarası**, her sertifikayı tanımlar.
- **Verici**, sertifikayı veren CA'yı ifade eder.
- **SubjectAlternativeName**, kimlik tanımlama esnekliğini artırarak konu için ek adlar sağlar.
- **Temel Kısıtlamalar**, sertifikanın bir CA veya son varlık için olup olmadığını tanımlar ve kullanım kısıtlamalarını belirler.
- **Genişletilmiş Anahtar Kullanımları (EKU'lar)**, sertifikanın belirli amaçlarını, örneğin kod imzalama veya e-posta şifreleme, Nesne Tanımlayıcıları (OID'ler) aracılığıyla belirler.
- **İmza Algoritması**, sertifikayı imzalamak için kullanılan yöntemi belirtir.
- **İmza**, vericinin özel anahtarı ile oluşturulur ve sertifikanın doğruluğunu garanti eder.

### Special Considerations

- **Subject Alternative Names (SAN'lar)**, bir sertifikanın birden fazla kimliğe uygulanabilirliğini genişletir, bu da birden fazla alan adı olan sunucular için kritik öneme sahiptir. Güvenli verilme süreçleri, saldırganların SAN spesifikasyonunu manipüle ederek kimlik taklit etme risklerini önlemek için hayati öneme sahiptir.

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS, AD ormanında CA sertifikalarını belirlenmiş konteynerler aracılığıyla tanır; her biri benzersiz roller üstlenir:

- **Sertifika Otoriteleri** konteyneri, güvenilir kök CA sertifikalarını tutar.
- **Kayıt Hizmetleri** konteyneri, Kurumsal CA'ları ve sertifika şablonlarını detaylandırır.
- **NTAuthCertificates** nesnesi, AD kimlik doğrulaması için yetkilendirilmiş CA sertifikalarını içerir.
- **AIA (Otorite Bilgi Erişimi)** konteyneri, ara ve çapraz CA sertifikaları ile sertifika zinciri doğrulamasını kolaylaştırır.

### Certificate Acquisition: Client Certificate Request Flow

1. İstek süreci, istemcilerin bir Kurumsal CA bulmasıyla başlar.
2. Bir açık anahtar ve diğer detayları içeren bir CSR oluşturulur, ardından bir açık-özel anahtar çifti oluşturulur.
3. CA, mevcut sertifika şablonlarına karşı CSR'yi değerlendirir ve şablonun izinlerine dayanarak sertifikayı verir.
4. Onaylandığında, CA sertifikayı özel anahtarı ile imzalar ve istemciye geri gönderir.

### Certificate Templates

AD içinde tanımlanan bu şablonlar, sertifika vermek için ayarları ve izinleri belirler; izin verilen EKU'lar ve kayıt veya değişiklik hakları dahil, sertifika hizmetlerine erişimi yönetmek için kritik öneme sahiptir.

## Certificate Enrollment

Sertifikalar için kayıt süreci, bir yöneticinin **bir sertifika şablonu oluşturması** ile başlar; bu şablon daha sonra bir Kurumsal Sertifika Otoritesi (CA) tarafından **yayınlanır**. Bu, şablonu istemci kaydı için kullanılabilir hale getirir; bu adım, şablonun adını bir Active Directory nesnesinin `certificatetemplates` alanına ekleyerek gerçekleştirilir.

Bir istemcinin sertifika talep edebilmesi için, **kayıt hakları** verilmelidir. Bu haklar, sertifika şablonundaki güvenlik tanımlayıcıları ve Kurumsal CA'nın kendisi tarafından tanımlanır. Bir talebin başarılı olması için her iki konumda da izinler verilmelidir.

### Template Enrollment Rights

Bu haklar, belirli izinleri detaylandıran Erişim Kontrol Girişleri (ACE'ler) aracılığıyla belirtilir:
- **Sertifika-Kayıt** ve **Sertifika-OtomatikKayıt** hakları, her biri belirli GUID'lerle ilişkilidir.
- **GenişletilmişHaklar**, tüm genişletilmiş izinlere izin verir.
- **TamKontrol/GenişTüm**, şablon üzerinde tam kontrol sağlar.

### Enterprise CA Enrollment Rights

CA'nın hakları, Sertifika Otoritesi yönetim konsolu aracılığıyla erişilebilen güvenlik tanımlayıcısında belirtilmiştir. Bazı ayarlar, düşük ayrıcalıklı kullanıcıların uzaktan erişim sağlamasına bile izin verebilir, bu da bir güvenlik endişesi olabilir.

### Additional Issuance Controls

Bazı kontroller uygulanabilir, örneğin:
- **Yönetici Onayı**: Talepleri, bir sertifika yöneticisi tarafından onaylanana kadar beklemede tutar.
- **Kayıt Ajanları ve Yetkili İmzalar**: Bir CSR üzerindeki gerekli imza sayısını ve gerekli Uygulama Politika OID'lerini belirtir.

### Methods to Request Certificates

Sertifikalar şu yöntemlerle talep edilebilir:
1. **Windows İstemci Sertifika Kayıt Protokolü** (MS-WCCE), DCOM arayüzlerini kullanarak.
2. **ICertPassage Uzak Protokolü** (MS-ICPR), adlandırılmış borular veya TCP/IP aracılığıyla.
3. **Sertifika kayıt web arayüzü**, Sertifika Otoritesi Web Kayıt rolü yüklü olduğunda.
4. **Sertifika Kayıt Hizmeti** (CES), Sertifika Kayıt Politikası (CEP) hizmeti ile birlikte.
5. **Ağ Cihazı Kayıt Hizmeti** (NDES) için ağ cihazları, Basit Sertifika Kayıt Protokolü (SCEP) kullanarak.

Windows kullanıcıları ayrıca GUI (`certmgr.msc` veya `certlm.msc`) veya komut satırı araçları (`certreq.exe` veya PowerShell'in `Get-Certificate` komutu) aracılığıyla sertifika talep edebilir.
```powershell
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Sertifika Kimlik Doğrulaması

Active Directory (AD), esasen **Kerberos** ve **Secure Channel (Schannel)** protokollerini kullanarak sertifika kimlik doğrulamasını destekler.

### Kerberos Kimlik Doğrulama Süreci

Kerberos kimlik doğrulama sürecinde, bir kullanıcının Ticket Granting Ticket (TGT) talebi, kullanıcının sertifikasının **özel anahtarı** ile imzalanır. Bu talep, alan denetleyicisi tarafından sertifikanın **geçerliliği**, **yolu** ve **iptal durumu** dahil olmak üzere birkaç doğrulamadan geçer. Doğrulamalar ayrıca sertifikanın güvenilir bir kaynaktan geldiğini doğrulamayı ve vericinin **NTAUTH sertifika deposunda** varlığını onaylamayı içerir. Başarılı doğrulamalar, bir TGT'nin verilmesiyle sonuçlanır. AD'deki **`NTAuthCertificates`** nesnesi, şu konumda bulunur:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
is central to establishing trust for certificate authentication.

### Secure Channel (Schannel) Authentication

Schannel, güvenli TLS/SSL bağlantılarını kolaylaştırır; burada bir el sıkışma sırasında, istemci, başarılı bir şekilde doğrulanırsa erişimi yetkilendiren bir sertifika sunar. Bir sertifikanın bir AD hesabına eşlenmesi, Kerberos'un **S4U2Self** fonksiyonu veya sertifikanın **Subject Alternative Name (SAN)** gibi diğer yöntemleri içerebilir.

### AD Certificate Services Enumeration

AD'nin sertifika hizmetleri, LDAP sorguları aracılığıyla sıralanabilir ve **Enterprise Certificate Authorities (CAs)** ve bunların yapılandırmaları hakkında bilgi açığa çıkarır. Bu, özel ayrıcalıklara sahip olmadan herhangi bir alan kimlik doğrulamalı kullanıcı tarafından erişilebilir. **[Certify](https://github.com/GhostPack/Certify)** ve **[Certipy](https://github.com/ly4k/Certipy)** gibi araçlar, AD CS ortamlarında sıralama ve zafiyet değerlendirmesi için kullanılır.

Bu araçları kullanmak için komutlar şunlardır:
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

{% hint style="success" %}
AWS Hacking öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
