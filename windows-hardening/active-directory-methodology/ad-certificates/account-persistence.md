# AD CS Hesap Sürekliliği

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahramanla öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

**Bu, [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)** adresindeki harika araştırmanın makine sürekliliği bölümlerinin küçük bir özetidir.


## **Sertifikalarla Aktif Kullanıcı Kimlik Bilgisi Çalma - PERSIST1**

Bir kullanıcının etki alanı kimlik doğrulamasına izin veren bir sertifika talep edebildiği bir senaryoda, bir saldırgan ağda **süreklilik sağlamak** için bu sertifikayı **talep edebilir** ve **çalabilir**. Active Directory'deki `User` şablonu varsayılan olarak böyle talepleri kabul eder, ancak bazen devre dışı bırakılabilir.

[**Certify**](https://github.com/GhostPack/Certify) adlı bir araç kullanarak, kalıcı erişimi etkinleştiren geçerli sertifikaları arayabilirsiniz:
```bash
Certify.exe find /clientauth
```
Sertifikanın gücü, sertifikaya ait kullanıcı olarak **kimlik doğrulama** yapabilme yeteneğinde yatmaktadır. Sertifika **geçerli** olduğu sürece, herhangi bir şifre değişikliğine bakılmaksızın bu yetenek devam eder.

Sertifikalar, `certmgr.msc` kullanarak grafik arayüzü veya `certreq.exe` ile komut satırı üzerinden istenebilir. **Certify** ile sertifika talep etme süreci aşağıdaki gibi basitleştirilir:
```bash
Certify.exe request /ca:CA-SERVER\CA-NAME /template:TEMPLATE-NAME
```
Başarılı bir istek sonrasında, bir sertifika ve onun özel anahtarı `.pem` formatında oluşturulur. Bu `.pem` dosyasını Windows sistemlerinde kullanılabilir hale getirmek için aşağıdaki komut kullanılır:
```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
`.pfx` dosyası daha sonra bir hedef sistemde yüklenip, [**Rubeus**](https://github.com/GhostPack/Rubeus) adlı bir araçla kullanılabilir. Bu araç, kullanıcı için bir Bilet Verme Bileti (TGT) talep etmek için kullanılır ve saldırganın erişimini sertifika **geçerli** olduğu sürece (genellikle bir yıl) uzatır:
```bash
Rubeus.exe asktgt /user:harmj0y /certificate:C:\Temp\cert.pfx /password:CertPass!
```
## **Sertifikalarla Makine Sürekliliği Kazanma - PERSIST2**

Başka bir yöntem, bir kompromize edilmiş sistemin makine hesabını bir sertifika için kaydetmeyi içerir ve bu işlemlere izin veren varsayılan `Machine` şablonunu kullanır. Bir saldırgan bir sisteme yükseltilmiş ayrıcalıklarla erişim sağlarsa, **SYSTEM** hesabını kullanarak sertifika talep edebilir ve bu da bir tür **süreklilik** sağlar:
```bash
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine
```
Bu erişim saldırganın makine hesabı olarak **Kerberos** üzerinde kimlik doğrulamasını yapmasına ve **S4U2Self** kullanarak ana bilgisayarda herhangi bir hizmet için Kerberos hizmet bileti almasına olanak tanır, bu da saldırgana makineye sürekli erişim sağlar.

## **Sertifika Yenileme Yoluyla Kalıcılığı Genişletme - PERSIST3**

Tartışılan son yöntem, sertifika şablonlarının **geçerlilik** ve **yenileme süreleri**nden yararlanmaktır. Bir sertifikayı süresi dolmadan yenileyerek, saldırgan ek bilet kayıtlarına ihtiyaç duymadan Active Directory'ye kimlik doğrulamasını sürdürebilir ve bu da Sertifika Yetkilisi (CA) sunucusunda iz bırakabilecek ek artefaktlardan kaçınır.

Bu yaklaşım, daha az CA sunucusu etkileşimiyle ve yöneticileri saldırıya uyarabilecek artefaktların oluşturulmasından kaçınarak **genişletilmiş bir kalıcılık** yöntemi sağlar.

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya HackTricks'i **PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'i keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek** paylaşın.

</details>
