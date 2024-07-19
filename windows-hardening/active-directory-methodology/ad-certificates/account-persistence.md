# AD CS Hesap Sürekliliği

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

**Bu, [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf) adresindeki harika araştırmanın makine sürekliliği bölümlerinin küçük bir özetidir.**

## **Sertifikalar ile Aktif Kullanıcı Kimlik Bilgisi Hırsızlığını Anlamak – PERSIST1**

Bir kullanıcının alan kimlik doğrulamasına izin veren bir sertifika talep edebileceği bir senaryoda, bir saldırganın bu sertifikayı **talep etme** ve **çalma** fırsatı vardır; bu da bir ağda **sürekliliği sağlamak** için kullanılır. Varsayılan olarak, Active Directory'deki `User` şablonu bu tür taleplere izin verir, ancak bazen devre dışı bırakılabilir.

[**Certify**](https://github.com/GhostPack/Certify) adlı bir araç kullanarak, sürekli erişimi sağlayan geçerli sertifikaları aramak mümkündür:
```bash
Certify.exe find /clientauth
```
Bir sertifikanın gücünün, sertifikanın ait olduğu **kullanıcı olarak kimlik doğrulama** yeteneğinde yattığı vurgulanmaktadır; bu, sertifika **geçerli** kaldığı sürece, herhangi bir şifre değişikliğinden bağımsızdır.

Sertifikalar, `certmgr.msc` kullanarak grafik arayüz üzerinden veya `certreq.exe` ile komut satırından talep edilebilir. **Certify** ile, bir sertifika talep etme süreci aşağıdaki gibi basitleştirilmiştir:
```bash
Certify.exe request /ca:CA-SERVER\CA-NAME /template:TEMPLATE-NAME
```
Başarılı bir istek üzerine, `.pem` formatında bir sertifika ve ona ait özel anahtar oluşturulur. Bunu Windows sistemlerinde kullanılabilir bir `.pfx` dosyasına dönüştürmek için aşağıdaki komut kullanılır:
```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
`.pfx` dosyası daha sonra bir hedef sisteme yüklenebilir ve kullanıcının Ticket Granting Ticket (TGT) talep etmesi için [**Rubeus**](https://github.com/GhostPack/Rubeus) adlı bir araçla kullanılabilir, saldırganın erişimini sertifika **geçerli** olduğu sürece (genellikle bir yıl) uzatır:
```bash
Rubeus.exe asktgt /user:harmj0y /certificate:C:\Temp\cert.pfx /password:CertPass!
```
Önemli bir uyarı, bu tekniğin, **THEFT5** bölümünde belirtilen başka bir yöntemle birleştirildiğinde, bir saldırganın **NTLM hash**'ini sürekli olarak elde etmesine olanak tanıdığı ve Yerel Güvenlik Otoritesi Alt Sistemi Hizmeti (LSASS) ile etkileşime girmeden, yükseltilmemiş bir bağlamdan sağladığı, uzun vadeli kimlik bilgisi hırsızlığı için daha gizli bir yöntem sunduğunu paylaşmaktadır.

## **Sertifikalar ile Makine Sürekliliği Elde Etme - PERSIST2**

Başka bir yöntem, bir tehlikeye atılmış sistemin makine hesabını bir sertifika için kaydettirmeyi içerir; bu, böyle eylemlere izin veren varsayılan `Machine` şablonunu kullanır. Bir saldırgan bir sistemde yükseltilmiş ayrıcalıklar elde ederse, **SYSTEM** hesabını kullanarak sertifika talep edebilir ve bu da bir tür **süreklilik** sağlar:
```bash
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine
```
Bu erişim, saldırgana makine hesabı olarak **Kerberos**'a kimlik doğrulama yapma ve **S4U2Self** kullanarak host üzerindeki herhangi bir hizmet için Kerberos hizmet biletleri alma yetkisi verir, bu da saldırgana makineye kalıcı erişim sağlar.

## **Sertifika Yenileme ile Kalıcılığı Uzatma - PERSIST3**

Son yöntem, sertifika şablonlarının **geçerlilik** ve **yenileme sürelerini** kullanmayı içerir. Bir sertifikayı süresi dolmadan önce **yenileyerek**, bir saldırgan, Sertifika Otoritesi (CA) sunucusunda iz bırakabilecek ek bilet kaydı gereksinimi olmadan Active Directory'ye kimlik doğrulamasını sürdürebilir.

Bu yaklaşım, CA sunucusuyla daha az etkileşimle tespit edilme riskini en aza indirerek ve yöneticileri saldırıya karşı uyaran artefaktların üretilmesini önleyerek **uzatılmış kalıcılık** yöntemi sağlar.
