# AD CS Alan Kalıcılığı

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahramanla öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek isterseniz** veya **HackTricks'i PDF olarak indirmek isterseniz** [**ABONELİK PLANLARINA**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek paylaşın**.

</details>

**Bu, [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf) adresinde paylaşılan alan kalıcılığı tekniklerinin özeti**. Daha fazla ayrıntı için kontrol edin.

## Çalıntı CA Sertifikaları ile Sertifikaları Sahteleme - DPERSIST1

Bir sertifikanın bir CA sertifikası olduğunu nasıl anlarsınız?

Bir sertifikanın bir CA sertifikası olduğu belirlenebilir, eğer şu koşullar sağlanıyorsa:

- Sertifika, özel anahtarının makinenin DPAPI'si veya işletim sistemi bunu destekliyorsa TPM/HSM gibi donanım tarafından güvence altına alınmış şekilde CA sunucusunda depolanır.
- Sertifikanın İhraç Eden ve Konu alanları, CA'nın ayırt edici adıyla eşleşir.
- "CA Sürümü" uzantısı yalnızca CA sertifikalarında bulunur.
- Sertifikada Genişletilmiş Anahtar Kullanımı (EKU) alanları bulunmaz.

Bu sertifikanın özel anahtarını çıkarmak için, CA sunucusundaki `certsrv.msc` aracı, yerleşik GUI üzerinden desteklenen yöntemdir. Bununla birlikte, bu sertifika sistemde depolanan diğer sertifikalardan farklı değildir; bu nedenle, çıkarma için [THEFT2 tekniği](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) gibi yöntemler uygulanabilir.

Sertifika ve özel anahtar ayrıca aşağıdaki komutla Certipy kullanılarak elde edilebilir:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
`.pfx` formatında CA sertifikası ve özel anahtar elde edildikten sonra, [ForgeCert](https://github.com/GhostPack/ForgeCert) gibi araçlar kullanılarak geçerli sertifikalar oluşturulabilir:
```bash
# Generating a new certificate with ForgeCert
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword Password123! --Subject "CN=User" --SubjectAltName localadmin@theshire.local --NewCertPath localadmin.pfx --NewCertPassword Password123!

# Generating a new certificate with certipy
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local -subject 'CN=Administrator,CN=Users,DC=CORP,DC=LOCAL'

# Authenticating using the new certificate with Rubeus
Rubeus.exe asktgt /user:localdomain /certificate:C:\ForgeCert\localadmin.pfx /password:Password123!

# Authenticating using the new certificate with certipy
certipy auth -pfx administrator_forged.pfx -dc-ip 172.16.126.128
```
{% hint style="warning" %}
Sertifika sahteciliği için hedeflenen kullanıcının etkin ve Active Directory'de kimlik doğrulama yapabilme yeteneğine sahip olması gerekmektedir. krbtgt gibi özel hesaplar için sertifika sahteciliği etkisizdir.
{% endhint %}

Bu sahte sertifika, belirtilen bitiş tarihine kadar **geçerli** olacak ve **kök CA sertifikası geçerli olduğu sürece** (genellikle 5 ila **10+ yıl**) geçerli olacaktır. Ayrıca, **makinelere** yönelik olarak da geçerlidir, bu nedenle **S4U2Self** ile birleştirildiğinde, saldırgan CA sertifikası geçerli olduğu sürece herhangi bir etki alanı makinesinde **kalıcılık sağlayabilir**.\
Ayrıca, bu yöntemle **üretilen sertifikaların iptal edilemeyeceği** unutulmamalıdır çünkü CA bunlardan haberdar değildir.

## Güvenilmez CA Sertifikalarına Güvenme - DPERSIST2

`NTAuthCertificates` nesnesi, içinde bir veya daha fazla **CA sertifikası** içeren `cacertificate` özelliğine sahiptir ve Active Directory (AD) bunu kullanır. **Erişim denetleyicisi**, kimlik doğrulayan **sertifikadaki İhraç Eden** alanında belirtilen CA ile eşleşen bir girişin `NTAuthCertificates` nesnesini kontrol eder. Eşleşme bulunursa kimlik doğrulama devam eder.

Bir saldırgan, bu AD nesnesi üzerinde kontrol sahibi olduktan sonra, `NTAuthCertificates` nesnesine bir öz imzalı CA sertifikası ekleyebilir. Normalde, yalnızca **Enterprise Admin** grubunun üyeleri, **Domain Admins** veya **Administrators** ile **forest root’unun etki alanındaki** bu nesneyi değiştirme izni verilir. `certutil.exe` kullanarak `NTAuthCertificates` nesnesini düzenleyebilirler. Komutu `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA126` veya [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool) kullanarak düzenleyebilirler.

Bu yetenek, ForgeCert ile dinamik olarak sertifikalar oluşturmak için kullanılan bir yöntemle birlikte kullanıldığında özellikle önemlidir.

## Kötü Amaçlı Yapılandırma - DPERSIST3

AD CS bileşenlerinin **güvenlik tanımlayıcılarının değiştirilmesi** yoluyla **kalıcılık** için fırsatlar bolca bulunmaktadır. "[Etki Alanı Yükseltme](domain-escalation.md)" bölümünde açıklanan değişiklikler, yükseltilmiş erişime sahip bir saldırgan tarafından kötü amaçlı olarak uygulanabilir. Bu, şunlar gibi hassas bileşenlere "kontrol hakları" (örneğin, WriteOwner/WriteDACL vb.) eklemeyi içerir:

- **CA sunucusunun AD bilgisayar** nesnesi
- **CA sunucusunun RPC/DCOM sunucusu**
- **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** içindeki herhangi bir **alt nesne veya konteyner** (örneğin, Sertifika Şablonları konteyneri, Sertifika Yetkilileri konteyneri, NTAuthCertificates nesnesi vb.)
- Varsayılan olarak veya kuruluş tarafından **AD CS'yi kontrol etme yetkisi verilen AD grupları** (örneğin, yerleşik Cert Publishers grubu ve üyelerinden herhangi biri)

Kötü amaçlı uygulamanın bir örneği, etki alanında **yükseltilmiş izinlere** sahip olan bir saldırganın, varsayılan **`User`** sertifika şablonuna **`WriteOwner`** iznini, saldırganın kendisini hak sahibi olarak eklemesiyle eklemesini içerebilir. Bunun için saldırgan önce **`User`** şablonunun sahipliğini kendisine değiştirir. Bundan sonra, şablonda **`ENROLLEE_SUPPLIES_SUBJECT`**'i etkinleştirmek için **`mspki-certificate-name-flag`** 1 olarak ayarlanır ve bir kullanıcının talepte Alternatif Bir İsim sağlamasına izin verilir. Ardından, saldırgan **şablonda** kullanarak, bir **etki alanı yöneticisi** adını alternatif bir isim olarak seçebilir ve elde edilen sertifikayı DA olarak kimlik doğrulama için kullanabilir.


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin!</summary>

HackTricks'yi desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı yapmak veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u takip edin.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR göndererek paylaşın.

</details>
