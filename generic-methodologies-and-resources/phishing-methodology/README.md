# Phishing Metodolojisi

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olacak şekilde öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)'ı **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

## Metodoloji

1. Kurbanı keşfet
1. **Kurban alanını** seçin.
2. Kurban tarafından kullanılan **giriş portalı** aramak için bazı temel web numaralandırma işlemleri yapın ve **taklit edeceğiniz** portalı **belirleyin**.
3. Bazı **OSINT** kullanarak **e-postaları bulun**.
2. Ortamı hazırla
1. Saldırı değerlendirmesi için kullanacağınız alanı **satın alın**
2. E-posta hizmetiyle ilgili kayıtları (SPF, DMARC, DKIM, rDNS) **yapılandırın**
3. **gophish** ile VPS'yi yapılandırın
3. Kampanyayı hazırla
1. **E-posta şablonunu** hazırlayın
2. Kimlik bilgilerini çalmak için **web sayfasını** hazırlayın
4. Kampanyayı başlat!

## Benzer alan adları oluşturma veya güvenilir bir alan adı satın alma

### Alan Adı Varyasyon Teknikleri

* **Anahtar kelime**: Alan adı, orijinal alan adının önemli bir **anahtar kelimesini içerir** (örneğin, zelster.com-management.com).
* **Alt alan tireli**: Alt alan adının **noktasını çizgi ile değiştirin** (örneğin, www-zelster.com).
* **Yeni TLD**: Aynı alan adını **yeni bir TLD** kullanarak kullanın (örneğin, zelster.org)
* **Homoglyph**: Alan adındaki bir harfi, benzer görünen harflerle **değiştirir** (örneğin, zelfser.com).
* **Transposition:** Alan adı içindeki iki harfi **yer değiştirir** (örneğin, zelster.com).
* **Tekil/çoğul**: Alan adının sonuna "s" ekler veya "s"yi kaldırır (örneğin, zeltsers.com).
* **Atlamak**: Alan adından bir harfi **kaldırır** (örneğin, zelser.com).
* **Tekrarlama**: Alan adındaki bir harfi **tekrarlar** (örneğin, zeltsser.com).
* **Değiştirme**: Homoglyph gibi, ancak daha az gizli. Alan adındaki bir harfi, belki de klavyedeki orijinal harfe yakın bir harfle **değiştirir** (örneğin, zektser.com).
* **Alt alan**: Alan adının içine bir **nokta** ekleyin (örneğin, ze.lster.com).
* **Ekleme**: Alan adına bir harf **ekler** (örneğin, zerltser.com).
* **Nokta eksikliği**: Alan adına TLD'yi ekleyin. (örneğin, zelstercom.com)

**Otomatik Araçlar**

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Web Siteleri**

* [https://dnstwist.it/](https://dnstwist.it)
* [https://dnstwister.report/](https://dnstwister.report)
* [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Güneş patlamaları, kozmik ışınlar veya donanım hataları gibi çeşitli faktörlerden dolayı, **depolanan veya iletişimdeki bazı bitlerin otomatik olarak tersine dönme olasılığı** vardır.

Bu kavram **DNS isteklerine uygulandığında**, DNS sunucusu tarafından alınan **alan adı**, başlangıçta istenen alan adıyla aynı olmayabilir.

Örneğin, "windows.com" alanında tek bir bit değişikliği, onu "windnws.com" olarak değiştirebilir.

Saldırganlar, kurbanın alan adına benzer **çoklu bit-flipping alan adlarını** kaydederek bundan faydalanabilirler. Amaçları, meşru kullanıcıları kendi altyapılarına yönlendirmektir.

Daha fazla bilgi için [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/) adresini okuyun.

### Güvenilir bir alan adı satın alma

Kullanabileceğiniz bir süresi dolmuş alan adı için [https://www.expireddomains.net/](https://www.expireddomains.net) adresinde arama yapabilirsiniz.\
Satın alacağınız süresi dolmuş alan adının **zaten iyi bir SEO'ya sahip olduğundan emin olmak** için aşağıdaki kategorilere nasıl sınıflandırıldığını araştırabilirsiniz:

* [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
* [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## E-postaları Keşfetme

* [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% ücretsiz)
* [https://phonebook.cz/](https://phonebook.cz) (100% ücretsiz)
* [https://maildb.io/](https://maildb.io)
* [https://hunter.io/](https://hunter.io)
* [https://anymailfinder.com/](https://anymailfinder.com)

Daha fazla geçerli e-posta adresi keşfetmek veya zaten keşfettiğiniz adresleri **doğrulamak** için kurbanın smtp sunucularını brute-force yöntemiyle kontrol edebilirsiniz. [E-posta adreslerini doğrulama/keşfetme yöntemini buradan öğrenin](../../network-services-pentesting/pentesting-smtp/#username-bruteforce-enumeration).\
Ayrıca, kullanıcılar e-postalarına erişmek için **herhangi bir web portalı** kullanıyorsa, kullanıcı adı brute force saldırısına karşı savunmasız olup olmadığını kontrol edebilir ve mümkünse bu zafiyeti sömürebilirsiniz.

## GoPhish'i Yapılandırma

### Kurulum

[https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0) adresinden indirebilirsiniz.

İndirin ve `/opt/gophish` dizinine çıkarın ve `/opt/gophish/gophish` komutunu çalıştırın.\
Çıktıda, yönetici kullanıcısı için bir şifre verilecektir. Bu nedenle, bu portu erişmek için o portu yerel olarak yönlendirmeniz ve bu kimlik bilgilerini kullanarak yönetici şifresini değiştirmeniz gerekebilir.
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Yapılandırma

**TLS sertifikası yapılandırması**

Bu adımdan önce kullanacağınız alan adını **zaten satın almış** olmanız gerekmektedir ve bu alan adının **gophish**'i yapılandırdığınız **VPS'nin IP'sine yönlendirilmiş** olması gerekmektedir.
```bash
DOMAIN="<domain>"
wget https://dl.eff.org/certbot-auto
chmod +x certbot-auto
sudo apt install snapd
sudo snap install core
sudo snap refresh core
sudo apt-get remove certbot
sudo snap install --classic certbot
sudo ln -s /snap/bin/certbot /usr/bin/certbot
certbot certonly --standalone -d "$DOMAIN"
mkdir /opt/gophish/ssl_keys
cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem" /opt/gophish/ssl_keys/key.pem
cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" /opt/gophish/ssl_keys/key.crt​
```
**E-posta yapılandırması**

Başlamak için şunu yükleyin: `apt-get install postfix`

Ardından, aşağıdaki dosyalara alan adını ekleyin:

* **/etc/postfix/virtual\_domains**
* **/etc/postfix/transport**
* **/etc/postfix/virtual\_regexp**

**Ayrıca /etc/postfix/main.cf içindeki aşağıdaki değişkenlerin değerlerini değiştirin**

`myhostname = <alanadı>`\
`mydestination = $myhostname, <alanadı>, localhost.com, localhost`

Son olarak, **/etc/hostname** ve **/etc/mailname** dosyalarını alan adınıza göre değiştirin ve **VPS'nizi yeniden başlatın.**

Şimdi, `mail.<alanadı>`'nın VPS'nin **ip adresine** işaret eden bir **DNS A kaydı** ve `mail.<alanadı>`'na işaret eden bir **DNS MX kaydı** oluşturun.

Şimdi bir e-posta göndermeyi test edelim:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish yapılandırması**

Gophish'in çalışmasını durdurun ve yapılandırmasını yapalım.\
`/opt/gophish/config.json` dosyasını aşağıdaki gibi düzenleyin (https kullanımına dikkat edin):
```bash
{
"admin_server": {
"listen_url": "127.0.0.1:3333",
"use_tls": true,
"cert_path": "gophish_admin.crt",
"key_path": "gophish_admin.key"
},
"phish_server": {
"listen_url": "0.0.0.0:443",
"use_tls": true,
"cert_path": "/opt/gophish/ssl_keys/key.crt",
"key_path": "/opt/gophish/ssl_keys/key.pem"
},
"db_name": "sqlite3",
"db_path": "gophish.db",
"migrations_prefix": "db/db_",
"contact_address": "",
"logging": {
"filename": "",
"level": ""
}
}
```
**Gophish servisini yapılandırma**

Gophish servisini otomatik olarak başlatmak ve yönetmek için bir servis oluşturmak için aşağıdaki içeriğe sahip `/etc/init.d/gophish` dosyasını oluşturabilirsiniz:
```bash
#!/bin/bash
# /etc/init.d/gophish
# initialization file for stop/start of gophish application server
#
# chkconfig: - 64 36
# description: stops/starts gophish application server
# processname:gophish
# config:/opt/gophish/config.json
# From https://github.com/gophish/gophish/issues/586

# define script variables

processName=Gophish
process=gophish
appDirectory=/opt/gophish
logfile=/var/log/gophish/gophish.log
errfile=/var/log/gophish/gophish.error

start() {
echo 'Starting '${processName}'...'
cd ${appDirectory}
nohup ./$process >>$logfile 2>>$errfile &
sleep 1
}

stop() {
echo 'Stopping '${processName}'...'
pid=$(/bin/pidof ${process})
kill ${pid}
sleep 1
}

status() {
pid=$(/bin/pidof ${process})
if [["$pid" != ""| "$pid" != "" ]]; then
echo ${processName}' is running...'
else
echo ${processName}' is not running...'
fi
}

case $1 in
start|stop|status) "$1" ;;
esac
```
Servisi yapılandırmayı tamamlayın ve aşağıdaki adımları takip ederek kontrol edin:
```bash
mkdir /var/log/gophish
chmod +x /etc/init.d/gophish
update-rc.d gophish defaults
#Check the service
service gophish start
service gophish status
ss -l | grep "3333\|443"
service gophish stop
```
## Posta sunucusu ve alan adı yapılandırması

### Bekle ve meşru ol

Bir alan adı ne kadar eskiyse, spam olarak yakalanma olasılığı o kadar az olur. Bu nedenle, phishing değerlendirmesinden önce mümkün olduğunca uzun süre beklemelisiniz (en az 1 hafta). Ayrıca, itibarlı bir sektör hakkında bir sayfa yayınlarsanız, elde edilen itibar daha iyi olacaktır.

Unutmayın, bir hafta beklemeniz gerekebilir, ancak şu anda her şeyi yapılandırabilirsiniz.

### Ters DNS (rDNS) kaydı yapılandırma

VPS'nin IP adresini alan adına çözen bir rDNS (PTR) kaydı ayarlayın.

### Gönderen Politika Çerçevesi (SPF) Kaydı

Yeni alan adı için bir SPF kaydı **yapılandırmalısınız**. SPF kaydının ne olduğunu bilmiyorsanız, [**bu sayfayı okuyun**](../../network-services-pentesting/pentesting-smtp/#spf).

SPF politikanızı oluşturmak için [https://www.spfwizard.net/](https://www.spfwizard.net) adresini kullanabilirsiniz (VPS makinesinin IP'sini kullanın).

![](<../../.gitbook/assets/image (388).png>)

Bu, alan içinde bir TXT kaydı içine yerleştirilmesi gereken içeriktir:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain Tabanlı Mesaj Kimlik Doğrulama, Raporlama ve Uyum (DMARC) Kaydı

Yeni alan adı için bir DMARC kaydı **yapılandırmalısınız**. DMARC kaydının ne olduğunu bilmiyorsanız, [**bu sayfayı okuyun**](../../network-services-pentesting/pentesting-smtp/#dmarc).

Aşağıdaki içeriğe sahip yeni bir DNS TXT kaydı oluşturmanız gerekmektedir:

```plaintext
_dmarc.<alanadı>  TXT  "v=DMARC1; p=none; rua=mailto:admin@<alanadı>; ruf=mailto:admin@<alanadı>; fo=1"
```
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Yeni alan adı için bir DKIM yapılandırması yapmanız gerekmektedir. Eğer DMARC kaydı nedir bilmiyorsanız [bu sayfayı okuyun](../../network-services-pentesting/pentesting-smtp/#dkim).

Bu rehber, şu adrese dayanmaktadır: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

{% hint style="info" %}
DKIM anahtarının oluşturduğu her iki B64 değerini birleştirmeniz gerekmektedir:
```
v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
```
{% endhint %}

### E-posta yapılandırma puanınızı test edin

Bunu [https://www.mail-tester.com/](https://www.mail-tester.com) adresini kullanarak yapabilirsiniz.\
Sadece sayfaya erişin ve size verdikleri adrese bir e-posta gönderin:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Ayrıca, e-posta yapılandırmanızı kontrol edebilirsiniz, bunun için `check-auth@verifier.port25.com` adresine bir e-posta gönderin ve yanıtı okuyun (bunun için port 25'i açmanız ve e-postayı root olarak gönderirseniz yanıtı _/var/mail/root_ dosyasında görebilirsiniz).\
Tüm testleri geçtiğinizden emin olun:
```bash
==========================================================
Summary of Results
==========================================================
SPF check:          pass
DomainKeys check:   neutral
DKIM check:         pass
Sender-ID check:    pass
SpamAssassin check: ham
```
Ayrıca, kontrolünüz altındaki bir Gmail'e **mesaj gönderebilir** ve Gmail gelen kutunuzda **e-posta başlıklarını** kontrol edebilirsiniz, `dkim=pass` ifadesi `Authentication-Results` başlık alanında bulunmalıdır.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Spamhouse Kara Listesinden Kaldırma

[www.mail-tester.com](www.mail-tester.com) adresindeki sayfa, alan adınızın spamhouse tarafından engellenip engellenmediğini size gösterebilir. Alan adınızı/IP'nizi kaldırmak için şu adrese başvurabilirsiniz: [https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Microsoft Kara Listesinden Kaldırma

Alan adınızı/IP'nizi kaldırmak için [https://sender.office.com/](https://sender.office.com) adresine başvurabilirsiniz.

## GoPhish Kampanyası Oluşturma ve Başlatma

### Gönderici Profili

* Gönderici profiliyi tanımlamak için bir **isim belirleyin**
* Hangi hesaptan phishing e-postalarını göndereceğinize karar verin. Öneriler: _noreply, support, servicedesk, salesforce..._
* Kullanıcı adını ve şifreyi boş bırakabilirsiniz, ancak Sertifika Hatalarını Yoksay'ı kontrol ettiğinizden emin olun

![](<../../.gitbook/assets/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (17).png>)

{% hint style="info" %}
Her şeyin düzgün çalıştığını test etmek için "**Test E-postası Gönder**" işlevini kullanmanız önerilir.\
Testleri yaparken kara listeye alınmamak için **test e-postalarını 10 dakikalık e-posta adreslerine göndermenizi öneririm**.
{% endhint %}

### E-posta Şablonu

* Şablonu tanımlamak için bir **isim belirleyin**
* Ardından bir **konu** yazın (normal bir e-postada okumayı bekleyebileceğiniz bir şey, garip bir şey olmasın)
* "**Takip İmajı Ekle**" seçeneğini işaretlediğinizden emin olun
* **E-posta şablonunu** yazın (aşağıdaki örnekte olduğu gibi değişkenler kullanabilirsiniz):
```markup
<html>
<head>
<title></title>
</head>
<body>
<p class="MsoNormal"><span style="font-size:10.0pt;font-family:&quot;Verdana&quot;,sans-serif;color:black">Dear {{.FirstName}} {{.LastName}},</span></p>
<br />
Note: We require all user to login an a very suspicios page before the end of the week, thanks!<br />
<br />
Regards,</span></p>

WRITE HERE SOME SIGNATURE OF SOMEONE FROM THE COMPANY

<p>{{.Tracker}}</p>
</body>
</html>
```
**E-postanın güvenilirliğini artırmak için**, müşteriden bir e-postadan bazı imzalar kullanmanız önerilir. Öneriler:

* **Var olmayan bir adrese** bir e-posta gönderin ve yanıtta herhangi bir imza olup olmadığını kontrol edin.
* info@ex.com veya press@ex.com veya public@ex.com gibi **genel e-postaları** arayın ve onlara bir e-posta gönderin ve yanıtı bekleyin.
* **Bazı geçerli keşfedilen** e-postalarla iletişim kurmaya çalışın ve yanıtı bekleyin.

![](<../../.gitbook/assets/image (393).png>)

{% hint style="info" %}
E-posta Şablonu ayrıca **göndermek için dosya eklemeye** izin verir. Özel olarak oluşturulmuş dosyalar/dokümanlar kullanarak NTLM meydan okumalarını çalmak isterseniz [bu sayfayı](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md) okuyun.
{% endhint %}

### İniş Sayfası

* Bir **ad yazın**
* Web sayfasının **HTML kodunu yazın**. Web sayfalarını **ithal edebilirsiniz**.
* **Gönderilen Veriyi Yakala** ve **Parolaları Yakala** işaretleyin
* Bir **yönlendirme** ayarlayın

![](<../../.gitbook/assets/image (394).png>)

{% hint style="info" %}
Genellikle sayfanın HTML kodunu değiştirmeniz ve sonuçları beğenene kadar yerelde bazı testler yapmanız gerekecektir (belki bir Apache sunucusu kullanarak). Ardından, o HTML kodunu kutuya yazın.\
HTML için **bazı statik kaynaklar** kullanmanız gerekiyorsa (belki bazı CSS ve JS sayfaları), onları _**/opt/gophish/static/endpoint**_ dizinine kaydedebilir ve ardından _**/static/\<dosyaadı>**_ üzerinden erişebilirsiniz.
{% endhint %}

{% hint style="info" %}
Yönlendirme için, kullanıcıları kurbanın gerçek ana web sayfasına **yönlendirebilirsiniz**, veya örneğin _/static/migration.html_ sayfasına yönlendirebilir, 5 saniye boyunca **dönen çark** ([**https://loading.io/**](https://loading.io)) ekleyebilir ve ardından işlemin başarılı olduğunu belirtebilirsiniz.
{% endhint %}

### Kullanıcılar ve Gruplar

* Bir ad belirleyin
* Verileri **ithal edin** (örnekteki şablonu kullanmak için her kullanıcının adı, soyadı ve e-posta adresine ihtiyacınız vardır)

![](<../../.gitbook/assets/image (395).png>)

### Kampanya

Son olarak, bir kampanya oluşturun ve bir ad, e-posta şablonu, iniş sayfası, URL, gönderme profili ve grup seçin. URL, kurbanlara gönderilen bağlantı olacaktır.

**Gönderme Profili**, son phishing e-postasının nasıl görüneceğini görmek için bir test e-postası göndermenize olanak sağlar:

![](<../../.gitbook/assets/image (396).png>)

{% hint style="info" %}
Test e-postalarını 10 dakikalık e-posta adreslerine göndermenizi öneririm, böylece testler yaparken kara listeye alınmaktan kaçınırsınız.
{% endhint %}

Her şey hazır olduğunda, kampanyayı başlatın!

## Web Sitesi Klonlama

Herhangi bir nedenle web sitesini klonlamak isterseniz, aşağıdaki sayfaya bakın:

{% content-ref url="clone-a-website.md" %}
[clone-a-website.md](clone-a-website.md)
{% endcontent-ref %}

## Arka Kapılı Belgeler ve Dosyalar

Bazı phishing değerlendirmelerinde (özellikle Kırmızı Takımlar için), **bir tür arka kapı içeren dosyaları da göndermek isteyebilirsiniz** (belki bir C2 veya belki sadece kimlik doğrulama tetikleyecek bir şey).\
Örnekler için aşağıdaki sayfaya bakın:

{% content-ref url="phishing-documents.md" %}
[phishing-documents.md](phishing-documents.md)
{% endcontent-ref %}

## Phishing MFA

### Proxy MitM Aracılığıyla

Önceki saldırı oldukça zekidir çünkü gerçek bir web sitesini taklit ediyor ve kullanıcı tarafından ayarlanan bilgileri topluyorsunuz. Ne yazık ki, kullanıcı doğru parolayı girmediyse veya taklit ettiğiniz uygulama 2FA ile yapılandırılmışsa, **bu bilgiler sizi aldatılan kullanıcı olarak taklit etmenize izin vermeyecektir**.

Bu noktada [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) ve [**muraena**](https://github.com/muraenateam/muraena) gibi araçlar kullanışlı olacaktır. Bu araç, MitM benzeri bir saldırı oluşturmanıza izin verir. Temel olarak, saldırı aşağıdaki şekilde çalışır:

1. Gerçek web sayfasının **giriş** formunu **taklit edersiniz**.
2. Kullanıcı, sahte sayfanıza **kimlik bilgilerini** gönderir ve araç bunları gerçek web sayfasına göndererek **kimlik bilgilerinin çalışıp çalışmadığını kontrol eder**.
3. Hesap **2FA ile yapılandırılmışsa**, MitM sayfası bunu isteyecek ve **kullanıcı girdiğinde** araç bunu gerçek web sayfasına gönderecektir.
4. Kullanıcı kimlik doğrulandığında (saldırgan olarak) araç, MitM yaparken her etkileşimdeki **kimlik bilgilerini, 2FA'yı, çerezleri ve herhangi bir bilgiyi yakalamış olacaktır**.

### VNC Aracılığıyla

Eğer kurbanı, orijinaline benzer görünüme sahip **bir kötü niyetli sayfaya yönlendirmek** yerine, onu gerçek web sayfasına bağlı bir tarayıcıya sahip **bir VNC oturumuna yönlendirirseniz** ne olur? Ne yaptığını görebilir, şifreyi, kullanılan MFA'yı, çerezleri çalabilirsiniz...\
Bunu [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) ile yapabilirsiniz.

## Algılamanın Algılanması

Elbette, yakalanıp yakalanmadığınızı bilmek için **alan adınızı kara listelerde aramanız gerekmektedir**. Listelenmişse, alan adınızın bir şekilde şüpheli olarak algılandığı anlamına gelir.\
Alan adınızın herhangi bir kara listede olup olmadığını kontrol etmek için kolay bir yol, [https://malwareworld.com/](https://malwareworld.com) adresini kullanmaktır.

Ancak, kurbanın **vahşi doğada şüpheli phishing etkinliği arayıp aramadığını** bilmek için başka yollar da vardır, aşağıda açıklandığı gibi:

{% content-ref url="detecting-phising.md" %}
[detecting-phising.md](detecting-phising.md)
{% endcontent-ref %}

Kurbanın alan adına çok benzeyen bir alan adı **satın al
