# Sertifikalar

<details>

<summary><strong>Sıfırdan kahramana kadar AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)'da **takip edin**.
* **Hacking püf noktalarınızı paylaşarak PR göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

<figure><img src="../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kullanarak dünyanın **en gelişmiş topluluk araçları** tarafından desteklenen **iş akışlarını kolayca oluşturun ve otomatikleştirin**.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Sertifika Nedir

Bir **genel anahtar sertifikası**, birinin genel anahtarı sahibi olduğunu kanıtlamak için kriptografi alanında kullanılan dijital bir kimliktir. Anahtarın ayrıntılarını, sahibin kimliğini (konuyu) ve güvenilir bir otoriteden (veren) dijital imzayı içerir. Yazılım, vereni güvenirse ve imza geçerliyse, anahtar sahibiyle güvenli iletişim mümkündür.

Sertifikalar genellikle [sertifika otoriteleri](https://en.wikipedia.org/wiki/Certificate\_authority) (CA'lar) tarafından [genel anahtar altyapısı](https://en.wikipedia.org/wiki/Public-key\_infrastructure) (PKI) kurulumunda verilir. Başka bir yöntem ise [güven ağı](https://en.wikipedia.org/wiki/Web\_of\_trust) yöntemidir, burada kullanıcılar doğrudan birbirlerinin anahtarlarını doğrular. Sertifikalar için yaygın format [X.509](https://en.wikipedia.org/wiki/X.509)'dur ve RFC 5280'de belirtildiği gibi belirli ihtiyaçlara uygun olarak uyarlanabilir.

## x509 Ortak Alanlar

### **x509 Sertifikalarındaki Ortak Alanlar**

x509 sertifikalarında, sertifikanın geçerliliğini ve güvenliğini sağlamak için birkaç **alan** kritik roller oynar. İşte bu alanların ayrıntıları:

* **Sürüm Numarası**, x509 formatının sürümünü belirtir.
* **Seri Numarası**, sertifikayı benzersiz bir şekilde tanımlar, genellikle iptal takibi için bir Sertifika Otoritesi'nin (CA) sistemi içinde.
* **Konu** alanı sertifikanın sahibini temsil eder, bu bir makine, bir birey veya bir kuruluş olabilir. Detaylı kimlik bilgilerini içerir:
* **Ortak Ad (CN)**: Sertifika tarafından kapsanan alanlar.
* **Ülke (C)**, **Yer (L)**, **Eyalet veya İl (ST, S veya P)**, **Organizasyon (O)** ve **Organizasyon Birimi (OU)** coğrafi ve organizasyonel detaylar sağlar.
* **Belirgin Ad (DN)** tam konu kimliğini kapsar.
* **Veren**, sertifikayı doğrulayan ve imzalayan kişiyi detaylandırır, CA için Konu ile benzer alt alanları içerir.
* **Geçerlilik Süresi**, **Önce Değil** ve **Sonra Değil** zaman damgaları ile işaretlenir, sertifikanın belirli bir tarihten önce veya sonra kullanılmadığından emin olunur.
* Sertifikanın güvenliği için kritik olan **Genel Anahtar** bölümü, genel anahtarın algoritmasını, boyutunu ve diğer teknik detaylarını belirtir.
* **x509v3 uzantıları**, sertifikanın işlevselliğini artırır, **Anahtar Kullanımı**, **Genişletilmiş Anahtar Kullanımı**, **Konu Alternatif Adı** ve sertifikanın uygulamasını ayarlamak için diğer özellikleri belirtir.

#### **Anahtar Kullanımı ve Uzantılar**

* **Anahtar Kullanımı**, genel anahtarın kriptografik uygulamalarını tanımlar, örneğin dijital imza veya anahtar şifreleme.
* **Genişletilmiş Anahtar Kullanımı**, sertifikanın kullanım alanlarını daha da daraltır, örneğin TLS sunucu kimlik doğrulaması için.
* **Konu Alternatif Adı** ve **Temel Kısıtlama**, sertifika tarafından kapsanan ek ana bilgisayar adlarını ve sertifikanın bir CA mı yoksa son varlık sertifikası mı olduğunu belirtir.
* **Konu Anahtar Kimliği** ve **Yetki Anahtar Kimliği**, anahtarların benzersizliğini ve izlenebilirliğini sağlar.
* **Yetki Bilgi Erişimi** ve **CRL Dağıtım Noktaları**, sertifikayı veren CA'yı doğrulamak için yollar sağlar ve sertifika iptal durumunu kontrol etmek için yollar sağlar.
* **CT Ön Sertifika SCT'leri**, sertifikaya olan kamu güveni için önemli olan şeffaflık günlüklerini sunar.
```python
# Example of accessing and using x509 certificate fields programmatically:
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Load an x509 certificate (assuming cert.pem is a certificate file)
with open("cert.pem", "rb") as file:
cert_data = file.read()
certificate = x509.load_pem_x509_certificate(cert_data, default_backend())

# Accessing fields
serial_number = certificate.serial_number
issuer = certificate.issuer
subject = certificate.subject
public_key = certificate.public_key()

print(f"Serial Number: {serial_number}")
print(f"Issuer: {issuer}")
print(f"Subject: {subject}")
print(f"Public Key: {public_key}")
```
### **OCSP ve CRL Dağıtım Noktaları Arasındaki Fark**

**OCSP** (**RFC 2560**), bir istemci ve yanıtlayıcının birlikte çalışarak dijital genel anahtar sertifikasının iptal edilip edilmediğini kontrol etmesini sağlar ve tam **CRL**'yi indirmeye gerek kalmadan yapar. Bu yöntem, potansiyel olarak büyük bir dosya indirmeyi gerektiren geleneksel **CRL**'den daha verimlidir. CRL'ler en fazla 512 giriş içerebilir. Daha fazla detay [burada](https://www.arubanetworks.com/techdocs/ArubaOS%206\_3\_1\_Web\_Help/Content/ArubaFrameStyles/CertRevocation/About\_OCSP\_and\_CRL.htm) bulunabilir.

### **Sertifika Şeffaflığı Nedir**

Sertifika Şeffaflığı, SSL sertifikalarının verilmesi ve varlığının alan sahipleri, CA'lar ve kullanıcılar tarafından görülebilir olduğunu sağlayarak sertifika ile ilgili tehditlerle mücadeleye yardımcı olur. Amaçları şunlardır:

* CA'ların alan sahibinin bilgisi olmadan bir alan için SSL sertifikaları vermesini engellemek.
* Yanlışlıkla veya kötü niyetle verilen sertifikaları izlemek için açık bir denetim sistemi oluşturmak.
* Kullanıcıları sahte sertifikalara karşı korumak.

#### **Sertifika Günlükleri**

Sertifika günlükleri, ağ hizmetleri tarafından tutulan, herkese açık olarak denetlenebilir, yalnızca eklemeye izin veren sertifikaların kayıtlarıdır. Bu günlükler, denetim amaçları için kriptografik kanıtlar sağlar. Hem verme yetkilileri hem de halk, bu günlüklere sertifikaları gönderebilir veya doğrulama için sorgulayabilir. Günlük sunucularının kesin sayısı sabit değildir, küresel olarak binin altında olması beklenir. Bu sunucular, CA'lar, İSP'ler veya ilgili herhangi bir varlık tarafından bağımsız olarak yönetilebilir.

#### **Sorgu**

Herhangi bir alan için Sertifika Şeffaflığı günlüklerini keşfetmek için [https://crt.sh/](https://crt.sh) adresini ziyaret edin.

## **Formatlar**

### **PEM Formatı**

* Sertifikalar için en yaygın kullanılan formattır.
* Sertifikalar ve özel anahtarlar için ayrı dosyalar gerektirir, Base64 ASCII ile kodlanmıştır.
* Yaygın uzantılar: .cer, .crt, .pem, .key.
* Başlıca olarak Apache ve benzeri sunucular tarafından kullanılır.

### **DER Formatı**

* Sertifikaların ikili bir formatıdır.
* PEM dosyalarında bulunan "BEGIN/END CERTIFICATE" ifadelerini içermez.
* Yaygın uzantılar: .cer, .der.
* Genellikle Java platformları ile kullanılır.

### **P7B/PKCS#7 Formatı**

* Base64 ASCII'de depolanır, .p7b veya .p7c uzantılarına sahiptir.
* Yalnızca sertifikaları ve zincir sertifikalarını içerir, özel anahtarı hariç tutar.
* Microsoft Windows ve Java Tomcat tarafından desteklenir.

### **PFX/P12/PKCS#12 Formatı**

* Sunucu sertifikalarını, ara sertifikaları ve özel anahtarları tek bir dosyada kapsayan ikili bir formattır.
* Uzantılar: .pfx, .p12.
* Genellikle Windows'ta sertifika içe ve dışa aktarma işlemleri için kullanılır.

### **Format Dönüştürme**

**PEM dönüşümleri**, uyumluluk için önemlidir:

* **x509'tan PEM'e**
```bash
openssl x509 -in certificatename.cer -outform PEM -out certificatename.pem
```
* **PEM'den DER'a**
```bash
openssl x509 -outform der -in certificatename.pem -out certificatename.der
```
* **DER'den PEM'e**
```bash
openssl x509 -inform der -in certificatename.der -out certificatename.pem
```
* **PEM'den P7B'ye**
```bash
openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
```
* **PKCS7'i PEM'e dönüştürme**
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
```
**PFX dönüşümleri**, Windows üzerinde sertifikaları yönetmek için hayati öneme sahiptir:

* **PFX'ten PEM'e**
```bash
openssl pkcs12 -in certificatename.pfx -out certificatename.pem
```
* **PFX to PKCS#8** iki adımdan oluşur:
1. PFX'i PEM'e dönüştürün
```bash
openssl pkcs12 -in certificatename.pfx -nocerts -nodes -out certificatename.pem
```
2. PEM'i PKCS8'e dönüştürün
```bash
openSSL pkcs8 -in certificatename.pem -topk8 -nocrypt -out certificatename.pk8
```
* **P7B'den PFX'e** dönüştürmek için de iki komut gereklidir:
1. P7B'yi CER'e dönüştürün
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.cer
```
2. CER ve Özel Anahtarı PFX'e Dönüştürün
```bash
openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile cacert.cer
```
***

<figure><img src="../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) kullanarak dünyanın en gelişmiş topluluk araçlarıyla desteklenen **otomatik iş akışları** oluşturun ve kolayca yönetin.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Sıfırdan kahraman olmaya kadar AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin, özel [**NFT'lerimizi**](https://opensea.io/collection/the-peass-family) görün
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
