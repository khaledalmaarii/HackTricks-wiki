# Sertifikalar

<details>

<summary><strong>AWS hackleme becerilerinizi sıfırdan kahraman seviyesine yükseltin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile</strong>!</summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Dünyanın en gelişmiş topluluk araçları tarafından desteklenen **iş akışlarını kolayca oluşturun ve otomatikleştirin** için [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)'i kullanın.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Sertifika Nedir

Bir **genel anahtar sertifikası**, bir kişinin bir genel anahtara sahip olduğunu kanıtlamak için kriptografi alanında kullanılan bir dijital kimliktir. Sertifika, anahtarın ayrıntılarını, sahibin kimliğini (konu) ve güvenilir bir otoriteden (veren) dijital bir imzayı içerir. Yazılım, vereni güveniyor ve imza geçerliyse, anahtar sahibiyle güvenli iletişim mümkündür.

Sertifikalar genellikle bir [sertifika otoritesi](https://en.wikipedia.org/wiki/Certificate_authority) (CA) tarafından bir [genel anahtar altyapısı](https://en.wikipedia.org/wiki/Public-key_infrastructure) (PKI) kurulumunda verilir. Başka bir yöntem, kullanıcıların doğrudan birbirlerinin anahtarlarını doğruladığı [güven ağı](https://en.wikipedia.org/wiki/Web_of_trust)dir. Sertifikalar için yaygın format [X.509](https://en.wikipedia.org/wiki/X.509)'dur ve RFC 5280'de belirtildiği gibi belirli ihtiyaçlara uyarlanabilir.

## x509 Ortak Alanlar

### **x509 Sertifikalarında Ortak Alanlar**

x509 sertifikalarında, sertifikanın geçerliliği ve güvenliği için birkaç **alan** önemli roller oynar. İşte bu alanların ayrıntıları:

- **Sürüm Numarası**, x509 formatının sürümünü belirtir.
- **Seri Numarası**, sertifikayı bir Sertifika Otoritesi'nin (CA) sistemi içinde benzersiz bir şekilde tanımlar ve genellikle iptal takibinde kullanılır.
- **Konu** alanı, sertifikanın sahibini temsil eder ve bir makine, bir birey veya bir kuruluş olabilir. Ayrıntılı kimlik bilgilerini içerir:
- **Ortak Ad (CN)**: Sertifika tarafından kapsanan alanlar.
- **Ülke (C)**, **Yer (L)**, **Eyalet veya İl (ST, S veya P)**, **Organizasyon (O)** ve **Organizasyon Birimi (OU)** coğrafi ve organizasyonel ayrıntıları sağlar.
- **Distinguished Name (DN)**, tam konu tanımlamasını kapsar.
- **Veren**, sertifikayı doğrulayan ve imzalayan kişiyi ayrıntılarıyla belirtir ve CA için Konu ile benzer alt alanları içerir.
- **Geçerlilik Süresi**, **Not Before** ve **Not After** zaman damgalarıyla belirtilir ve sertifikanın belirli bir tarihten önce veya sonra kullanılmamasını sağlar.
- Sertifikanın güvenliği için önemli olan **Genel Anahtar** bölümü, genel anahtarın algoritmasını, boyutunu ve diğer teknik ayrıntıları belirtir.
- **x509v3 uzantıları**, sertifikanın işlevselliğini artırır ve sertifikanın uygulamasını ince ayarlamak için **Anahtar Kullanımı**, **Genişletilmiş Anahtar Kullanımı**, **Alternatif Konu Adı** ve diğer özellikleri belirtir.

#### **Anahtar Kullanımı ve Uzantılar**

- **Anahtar Kullanımı**, genel anahtarın kriptografik uygulamalarını, dijital imza veya anahtar şifreleme gibi, tanımlar.
- **Genişletilmiş Anahtar Kullanımı**, sertifikanın kullanım durumlarını daha da daraltır, örneğin TLS sunucusu kimlik doğrulaması için.
- **Alternatif Konu Adı** ve **Temel Kısıtlama**, sertifika tarafından kapsanan ek ana bilgisayar adlarını ve sertifikanın bir CA veya son varlık sertifikası olup olmadığını tanımlar.
- **Konu Anahtar Tanımlayıcısı** ve **Yetkilendirme Anahtar Tanımlayıcısı**, anahtarların benzersizliğini ve izlenebilirliğini sağlar.
- **Yetkilendirme Bilgi Erişimi** ve **CRL Dağıtım Noktaları**, sertifikayı veren CA'yı doğrulamak ve sertifika iptal durumunu kontrol etmek için yol sağlar.
- **CT Ön Sertifika SCT'leri**, sertifikaya olan kamu güveni için önemli olan şeffaflık günlüklerini sunar.
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

**OCSP** (**RFC 2560**), bir dijital genel anahtar sertifikasının iptal edilip edilmediğini kontrol etmek için bir istemci ve bir yanıtlayıcının birlikte çalıştığı bir yöntemdir ve tam **CRL**'yi indirmeye gerek duymaz. Bu yöntem, potansiyel olarak büyük bir dosya indirmeyi gerektiren, iptal edilen sertifika seri numaralarının bir listesini sağlayan geleneksel **CRL**'den daha verimlidir. CRL'ler 512 girişe kadar içerebilir. Daha fazla ayrıntı [burada](https://www.arubanetworks.com/techdocs/ArubaOS%206_3_1_Web_Help/Content/ArubaFrameStyles/CertRevocation/About_OCSP_and_CRL.htm) bulunabilir.

### **Sertifika Şeffaflığı Nedir**

Sertifika Şeffaflığı, SSL sertifikalarının verilmesi ve varlığının alan sahipleri, CA'lar ve kullanıcılar tarafından görülebilir olmasını sağlayarak sertifika ile ilgili tehditlerle mücadele etmeye yardımcı olur. Aşağıdaki hedeflere sahiptir:

* CA'ların alan sahibinin bilgisi olmadan bir alan için SSL sertifikaları vermesini engellemek.
* Yanlışlıkla veya kötü niyetle verilen sertifikaları izlemek için açık bir denetim sistemi oluşturmak.
* Kullanıcıları sahte sertifikalara karşı korumak.

#### **Sertifika Kayıtları**

Sertifika kayıtları, ağ hizmetleri tarafından tutulan, herkes tarafından denetlenebilir, sadece ekleme yapılan sertifikaların kayıtlarıdır. Bu kayıtlar, denetim amaçları için kriptografik kanıtlar sağlar. Hem verme yetkilileri hem de kamu, bu kayıtlara sertifikaları sunabilir veya sorgulayabilir. Kayıt sunucularının tam sayısı sabit değildir, küresel olarak binin altında olması beklenir. Bu sunucular, CA'lar, ISS'ler veya ilgilenen herhangi bir kuruluş tarafından bağımsız olarak yönetilebilir.

#### **Sorgu**

Herhangi bir alan için Sertifika Şeffaflığı kayıtlarını keşfetmek için [https://crt.sh/](https://crt.sh) adresini ziyaret edin.

Sertifikaları depolamak için farklı formatlar mevcuttur, her birinin kendi kullanım durumları ve uyumlulukları vardır. Bu özet, ana formatları kapsar ve bunlar arasında dönüştürme konusunda rehberlik sağlar.

## **Formatlar**

### **PEM Formatı**
- Sertifikalar için en yaygın kullanılan formattır.
- Sertifikaları ve özel anahtarları ayrı dosyalarda gerektirir, Base64 ASCII ile kodlanmıştır.
- Yaygın uzantılar: .cer, .crt, .pem, .key.
- Apache ve benzeri sunucular tarafından başlıca kullanılır.

### **DER Formatı**
- Sertifikaların ikili bir formattır.
- PEM dosyalarında bulunan "BEGIN/END CERTIFICATE" ifadelerini içermez.
- Yaygın uzantılar: .cer, .der.
- Genellikle Java platformlarıyla kullanılır.

### **P7B/PKCS#7 Formatı**
- Base64 ASCII ile depolanır, .p7b veya .p7c uzantılarına sahiptir.
- Sadece sertifikaları ve zincir sertifikalarını, özel anahtarı hariç tutar.
- Microsoft Windows ve Java Tomcat tarafından desteklenir.

### **PFX/P12/PKCS#12 Formatı**
- Sunucu sertifikalarını, ara sertifikalarını ve özel anahtarları tek bir dosyada kapsayan ikili bir formattır.
- Uzantılar: .pfx, .p12.
- Genellikle sertifika alma ve alma işlemleri için Windows'ta kullanılır.

### **Formatları Dönüştürme**

Uyumluluk için **PEM dönüşümleri** önemlidir:

- **x509'tan PEM'e**
```bash
openssl x509 -in certificatename.cer -outform PEM -out certificatename.pem
```
- **PEM'den DER'e**

PEM formatındaki bir sertifikayı DER formatına dönüştürmek için aşağıdaki adımları izleyebilirsiniz:

1. İlk olarak, PEM formatındaki sertifikayı bir metin düzenleyiciyle açın.
2. Sertifikanın başında "-----BEGIN CERTIFICATE-----" ve sonunda "-----END CERTIFICATE-----" ifadelerini bulun.
3. Bu ifadeler arasındaki tüm metni kopyalayın ve yeni bir metin dosyasına yapıştırın.
4. Dosyayı ".pem" uzantısıyla kaydedin.
5. Ardından, OpenSSL aracını kullanarak PEM dosyasını DER formatına dönüştürebilirsiniz. Aşağıdaki komutu kullanarak dönüşümü gerçekleştirebilirsiniz:

   ```bash
   openssl x509 -in example.pem -out example.der -outform DER
   ```

   Burada "example.pem" dönüştürmek istediğiniz PEM dosyasının adıdır ve "example.der" ise çıktı olarak almak istediğiniz DER dosyasının adıdır.

6. Dönüştürme işlemi tamamlandıktan sonra, DER formatındaki sertifikayı kullanabilirsiniz.
```bash
openssl x509 -outform der -in certificatename.pem -out certificatename.der
```
- **DER'den PEM'e**

DER formatındaki bir sertifikayı PEM formatına dönüştürmek için aşağıdaki adımları izleyebilirsiniz:

1. DER formatındaki sertifikayı bir metin düzenleyiciyle açın.
2. Sertifika içeriğini kopyalayın ve yeni bir metin dosyasına yapıştırın.
3. Dosyayı `.cer` veya `.der` uzantısıyla kaydedin.
4. OpenSSL aracını kullanarak DER formatındaki sertifikayı PEM formatına dönüştürün. Aşağıdaki komutu kullanabilirsiniz:

   ```plaintext
   openssl x509 -inform der -in certificate.cer -out certificate.pem
   ```

   Burada `certificate.cer`, kaydettiğiniz DER formatındaki sertifika dosyasının adıdır.
5. Dönüştürülen PEM formatındaki sertifikayı kullanabilirsiniz.
```bash
openssl x509 -inform der -in certificatename.der -out certificatename.pem
```
- **PEM'dan P7B'ye**

PEM formatındaki bir sertifikayı P7B formatına dönüştürmek için aşağıdaki adımları izleyebilirsiniz:

1. OpenSSL aracını kullanarak PEM dosyasını P7B formatına dönüştürmek için aşağıdaki komutu çalıştırın:

   ```plaintext
   openssl crl2pkcs7 -nocrl -certfile certificate.pem -out certificate.p7b -certfile ca.pem
   ```

   - `certificate.pem`: Dönüştürmek istediğiniz PEM dosyasının adı.
   - `certificate.p7b`: Dönüştürülen P7B dosyasının adı.
   - `ca.pem`: Kök sertifikaların bulunduğu PEM dosyasının adı (isteğe bağlı).

2. Komutu çalıştırdıktan sonra, PEM dosyası P7B formatına dönüştürülecektir. Dönüştürülen P7B dosyasını kullanabilirsiniz.

Bu adımları takip ederek, PEM formatındaki bir sertifikayı P7B formatına dönüştürebilirsiniz.
```bash
openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
```
- **PKCS7'yi PEM'e dönüştürme**
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
```
**PFX dönüşümleri**, Windows üzerinde sertifikaları yönetmek için önemlidir:

- **PFX'ten PEM'e**
```bash
openssl pkcs12 -in certificatename.pfx -out certificatename.pem
```
- **PFX'i PKCS#8'e dönüştürme** iki adımdan oluşur:
1. PFX'i PEM'e dönüştürün.
```bash
openssl pkcs12 -in certificatename.pfx -nocerts -nodes -out certificatename.pem
```
2. PEM'i PKCS8'e dönüştürmek

PEM formatındaki bir sertifikayı PKCS8 formatına dönüştürmek için aşağıdaki adımları izleyebilirsiniz:

1. OpenSSL aracını kullanarak PEM dosyasını açın:
   ```plaintext
   openssl rsa -in key.pem -outform PEM -out key.pem
   ```

2. PEM dosyasını PKCS8 formatına dönüştürün:
   ```plaintext
   openssl pkcs8 -topk8 -inform PEM -outform DER -in key.pem -out key.pk8 -nocrypt
   ```

Bu adımları takip ederek PEM formatındaki bir sertifikayı PKCS8 formatına dönüştürebilirsiniz.
```bash
openSSL pkcs8 -in certificatename.pem -topk8 -nocrypt -out certificatename.pk8
```
- **P7B'yi PFX'e** dönüştürmek için iki komut gereklidir:
1. P7B'yi CER'ye dönüştürün.
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.cer
```
2. CER ve Özel Anahtarı PFX'e Dönüştürme

Bir sertifika (.cer) ve özel anahtarını (.key) PFX formatına dönüştürmek için aşağıdaki adımları izleyebilirsiniz:

1. OpenSSL'i kullanarak bir PFX dosyası oluşturmak için aşağıdaki komutu çalıştırın:

   ```plaintext
   openssl pkcs12 -export -in certificate.cer -inkey privatekey.key -out certificate.pfx
   ```

   - `certificate.cer`: Dönüştürmek istediğiniz sertifika dosyasının adını ve yolunu belirtin.
   - `privatekey.key`: Dönüştürmek istediğiniz özel anahtar dosyasının adını ve yolunu belirtin.
   - `certificate.pfx`: Oluşturulacak PFX dosyasının adını ve yolunu belirtin.

2. Komutu çalıştırdıktan sonra, OpenSSL sizden bir PFX parolası girmenizi isteyecektir. Bu parolayı hatırlayın, çünkü PFX dosyasını kullanırken gerekecektir.

3. Parolayı girdikten sonra, OpenSSL PFX dosyasını oluşturacak ve belirttiğiniz ad ve yol ile kaydedecektir.

Artık CER ve özel anahtarınızı PFX formatında kullanabilirsiniz.
```bash
openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile cacert.cer
```
***

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kullanarak dünyanın en gelişmiş topluluk araçları tarafından desteklenen iş akışlarını kolayca oluşturun ve otomatikleştirin.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek veya HackTricks'i PDF olarak indirmek isterseniz** [**ABONELİK PLANLARINA**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin, özel [**NFT'ler**](https://opensea.io/collection/the-peass-family)
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* Hacking hilelerinizi [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR göndererek paylaşın.

</details>
