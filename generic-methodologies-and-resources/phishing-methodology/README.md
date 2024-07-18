# Phishing Methodology

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

## Methodology

1. Kurbanı araştırın
1. **Kurban alan adını** seçin.
2. Kurban tarafından kullanılan **giriş portallarını** bulmak için bazı temel web sayımı yapın ve hangi birini **taklit edeceğinize** **karar verin**.
3. **E-posta bulmak için bazı OSINT** kullanın.
2. Ortamı hazırlayın
1. Phishing değerlendirmesi için kullanacağınız **alan adını satın alın**.
2. İlgili kayıtları (SPF, DMARC, DKIM, rDNS) **e-posta hizmetini yapılandırın**.
3. **gophish** ile VPS'yi yapılandırın.
3. Kampanyayı hazırlayın
1. **E-posta şablonunu** hazırlayın.
2. Kimlik bilgilerini çalmak için **web sayfasını** hazırlayın.
4. Kampanyayı başlatın!

## Benzer alan adları oluşturun veya güvenilir bir alan adı satın alın

### Alan Adı Varyasyon Teknikleri

* **Anahtar Kelime**: Alan adı, orijinal alan adının önemli bir **anahtar kelimesini** **içerir** (örneğin, zelster.com-management.com).
* **tireli alt alan**: Bir alt alanın **noktasını tire ile değiştirin** (örneğin, www-zelster.com).
* **Yeni TLD**: Aynı alan adı, **yeni bir TLD** kullanarak (örneğin, zelster.org).
* **Homoglif**: Alan adındaki bir harfi, **benzer görünen harflerle** **değiştirir** (örneğin, zelfser.com).
* **Transpozisyon:** Alan adı içinde **iki harfi değiştirir** (örneğin, zelsetr.com).
* **Tekil/Çoğul**: Alan adının sonuna “s” ekler veya çıkarır (örneğin, zeltsers.com).
* **Atlama**: Alan adından **bir harfi çıkarır** (örneğin, zelser.com).
* **Tekrar:** Alan adındaki **bir harfi tekrarlar** (örneğin, zeltsser.com).
* **Değiştirme**: Homoglif gibi ama daha az gizli. Alan adındaki bir harfi, belki de orijinal harfin klavye üzerindeki yakınındaki bir harfle değiştirir (örneğin, zektser.com).
* **Alt alan**: Alan adı içinde bir **nokta** ekleyin (örneğin, ze.lster.com).
* **Ekleme**: Alan adına **bir harf ekler** (örneğin, zerltser.com).
* **Eksik nokta**: Alan adına TLD'yi ekleyin. (örneğin, zelstercom.com)

**Otomatik Araçlar**

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Web Siteleri**

* [https://dnstwist.it/](https://dnstwist.it)
* [https://dnstwister.report/](https://dnstwister.report)
* [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

**Depolanan veya iletişimdeki bazı bitlerin otomatik olarak değişme olasılığı** vardır; bu, güneş patlamaları, kozmik ışınlar veya donanım hataları gibi çeşitli faktörlerden kaynaklanabilir.

Bu kavram **DNS isteklerine uygulandığında**, **DNS sunucusu tarafından alınan alan adının**, başlangıçta istenen alan adıyla aynı olmaması mümkündür.

Örneğin, "windows.com" alan adındaki tek bir bit değişikliği, onu "windnws.com" haline getirebilir.

Saldırganlar, **kurbanın alan adına benzer birden fazla bit-flipping alan adı kaydederek** bundan **yararlanabilirler**. Amaçları, meşru kullanıcıları kendi altyapılarına yönlendirmektir.

Daha fazla bilgi için [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/) adresini okuyun.

### Güvenilir bir alan adı satın alın

Kullanabileceğiniz bir süresi dolmuş alan adı aramak için [https://www.expireddomains.net/](https://www.expireddomains.net) adresini ziyaret edebilirsiniz.\
Satın alacağınız süresi dolmuş alan adının **zaten iyi bir SEO'ya sahip olduğundan emin olmak için** şu kategorilere bakabilirsiniz:

* [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
* [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## E-posta Bulma

* [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (%100 ücretsiz)
* [https://phonebook.cz/](https://phonebook.cz) (%100 ücretsiz)
* [https://maildb.io/](https://maildb.io)
* [https://hunter.io/](https://hunter.io)
* [https://anymailfinder.com/](https://anymailfinder.com)

Daha fazla geçerli e-posta adresi **bulmak veya** zaten bulduğunuz adresleri **doğrulamak için**, kurbanın smtp sunucularını brute-force ile kontrol edebilirsiniz. [E-posta adresini doğrulama/bulma hakkında buradan öğrenin](../../network-services-pentesting/pentesting-smtp/#username-bruteforce-enumeration).\
Ayrıca, kullanıcıların **e-postalarına erişmek için herhangi bir web portalı kullanıp kullanmadıklarını** unutmayın; eğer kullanıyorsanız, **kullanıcı adı brute force** için savunmasız olup olmadığını kontrol edebilir ve mümkünse bu açığı istismar edebilirsiniz.

## GoPhish'i Yapılandırma

### Kurulum

Bunu [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0) adresinden indirebilirsiniz.

İndirin ve `/opt/gophish` dizinine çıkarın ve `/opt/gophish/gophish` komutunu çalıştırın.\
Çıktıda, 3333 portundaki admin kullanıcı için bir şifre verilecektir. Bu nedenle, o porta erişin ve bu kimlik bilgilerini kullanarak admin şifresini değiştirin. O portu yerel olarak tünellemeniz gerekebilir.
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Configuration

**TLS sertifika yapılandırması**

Bu adımdan önce, kullanacağınız **alan adını zaten satın almış olmalısınız** ve bu alan adı, **gophish** yapılandırdığınız **VPS'nin IP'sine** **yönlendirilmiş olmalıdır**.
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
**Mail yapılandırması**

Başlamak için: `apt-get install postfix`

Sonra alan adını aşağıdaki dosyalara ekleyin:

* **/etc/postfix/virtual\_domains**
* **/etc/postfix/transport**
* **/etc/postfix/virtual\_regexp**

**Ayrıca /etc/postfix/main.cf içindeki aşağıdaki değişkenlerin değerlerini değiştirin**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Son olarak **`/etc/hostname`** ve **`/etc/mailname`** dosyalarını alan adınıza göre değiştirin ve **VPS'nizi yeniden başlatın.**

Şimdi, `mail.<domain>` için bir **DNS A kaydı** oluşturun ve VPS'nin **ip adresine** işaret eden bir **DNS MX** kaydı oluşturun.

Şimdi bir e-posta göndermeyi test edelim:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish yapılandırması**

Gophish'in çalışmasını durdurun ve yapılandıralım.\
`/opt/gophish/config.json` dosyasını aşağıdaki gibi değiştirin (https kullanımına dikkat edin):
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
**Gophish hizmetini yapılandırın**

Gophish hizmetini otomatik olarak başlatılabilir ve bir hizmet olarak yönetilebilir hale getirmek için `/etc/init.d/gophish` dosyasını aşağıdaki içerikle oluşturabilirsiniz:
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
Hizmeti yapılandırmayı tamamlayın ve kontrol edin:
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
## Mail sunucusu ve alan adı yapılandırması

### Bekleyin ve meşru olun

Bir alan adı ne kadar eskiyse, spam olarak yakalanma olasılığı o kadar düşüktür. Bu nedenle, phishing değerlendirmesinden önce mümkün olduğunca uzun süre (en az 1 hafta) beklemelisiniz. Ayrıca, itibarlı bir sektörde bir sayfa oluşturursanız, elde edilen itibar daha iyi olacaktır.

Bir hafta beklemeniz gerekse bile, her şeyi şimdi yapılandırmayı tamamlayabileceğinizi unutmayın.

### Ters DNS (rDNS) kaydını yapılandırın

VPS'nin IP adresini alan adıyla çözen bir rDNS (PTR) kaydı ayarlayın.

### Gönderen Politika Çerçevesi (SPF) Kaydı

**Yeni alan adı için bir SPF kaydı yapılandırmalısınız**. SPF kaydının ne olduğunu bilmiyorsanız [**bu sayfayı okuyun**](../../network-services-pentesting/pentesting-smtp/#spf).

SPF politikanızı oluşturmak için [https://www.spfwizard.net/](https://www.spfwizard.net) adresini kullanabilirsiniz (VPS makinesinin IP'sini kullanın).

![](<../../.gitbook/assets/image (1037).png>)

Bu, alan adı içindeki bir TXT kaydına yerleştirilmesi gereken içeriktir:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) Kaydı

Yeni alan için **bir DMARC kaydı yapılandırmalısınız**. DMARC kaydının ne olduğunu bilmiyorsanız [**bu sayfayı okuyun**](../../network-services-pentesting/pentesting-smtp/#dmarc).

Aşağıdaki içeriğe sahip `_dmarc.<domain>` ana bilgisayarına işaret eden yeni bir DNS TXT kaydı oluşturmalısınız:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Yeni alan için **bir DKIM yapılandırmalısınız**. DMARC kaydının ne olduğunu bilmiyorsanız [**bu sayfayı okuyun**](../../network-services-pentesting/pentesting-smtp/#dkim).

Bu eğitim, şuraya dayanmaktadır: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

{% hint style="info" %}
DKIM anahtarının ürettiği her iki B64 değerini birleştirmeniz gerekiyor:
```
v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
```
{% endhint %}

### E-posta yapılandırma puanınızı test edin

Bunu [https://www.mail-tester.com/](https://www.mail-tester.com) kullanarak yapabilirsiniz.\
Sadece sayfaya erişin ve size verdikleri adrese bir e-posta gönderin:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
E-posta yapılandırmanızı **kontrol edebilirsiniz** `check-auth@verifier.port25.com` adresine bir e-posta göndererek ve **yanıtı okuyarak** (bunun için **25** numaralı portu **açmanız** ve e-postayı root olarak gönderirseniz _/var/mail/root_ dosyasında yanıtı görmeniz gerekecek).\
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
**Kontrolünüz altındaki bir Gmail'e mesaj gönderebilir** ve Gmail gelen kutunuzda **e-postanın başlıklarını** kontrol edebilirsiniz, `dkim=pass` `Authentication-Results` başlık alanında bulunmalıdır.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Spamhouse Kara Listesinden Çıkarma

Sayfa [www.mail-tester.com](https://www.mail-tester.com) alan adınızın spamhouse tarafından engellenip engellenmediğini gösterebilir. Alan adınızın/IP'nizin kaldırılmasını talep edebilirsiniz: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Microsoft Kara Listesinden Çıkarma

Alan adınızın/IP'nizin kaldırılmasını talep edebilirsiniz [https://sender.office.com/](https://sender.office.com).

## GoPhish Kampanyası Oluşturma ve Başlatma

### Gönderici Profili

* Gönderici profilini tanımlamak için bir **isim belirleyin**
* Phishing e-postalarını hangi hesaptan göndereceğinize karar verin. Öneriler: _noreply, support, servicedesk, salesforce..._
* Kullanıcı adı ve şifreyi boş bırakabilirsiniz, ancak Sertifika Hatalarını Yoksay'ı kontrol ettiğinizden emin olun.

![](<../../.gitbook/assets/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

{% hint style="info" %}
Her şeyin çalıştığını test etmek için "**Test E-postası Gönder**" işlevini kullanmanız önerilir.\
Testlerin kara listeye alınmaktan kaçınmak için **test e-postalarını 10 dakikalık e-posta adreslerine göndermenizi** öneririm.
{% endhint %}

### E-posta Şablonu

* Şablonu tanımlamak için bir **isim belirleyin**
* Ardından bir **konu** yazın (olağan bir e-postada okuyabileceğiniz bir şey, garip bir şey değil)
* "**İzleme Resmi Ekle**" seçeneğini kontrol ettiğinizden emin olun
* **e-posta şablonunu** yazın (aşağıdaki örnekte olduğu gibi değişkenler kullanabilirsiniz):
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
Not edin ki **e-postanın güvenilirliğini artırmak için**, müşteriden gelen bir e-posta imzası kullanılması önerilir. Öneriler:

* **Mevcut olmayan bir adrese** e-posta gönderin ve yanıtın herhangi bir imza içerip içermediğini kontrol edin.
* **Açık e-postalar** arayın, örneğin info@ex.com veya press@ex.com veya public@ex.com ve onlara bir e-posta gönderin ve yanıtı bekleyin.
* **Bazı geçerli bulunan** e-postalarla iletişim kurmayı deneyin ve yanıtı bekleyin.

![](<../../.gitbook/assets/image (80).png>)

{% hint style="info" %}
E-posta Şablonu ayrıca **göndermek için dosyalar eklemeye** de olanak tanır. Eğer bazı özel hazırlanmış dosyalar/belgeler kullanarak NTLM zorluklarını çalmak isterseniz [bu sayfayı okuyun](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).
{% endhint %}

### Açılış Sayfası

* Bir **isim** yazın.
* Web sayfasının **HTML kodunu yazın**. Web sayfalarını **içe aktarabileceğinizi** unutmayın.
* **Gönderilen Verileri Yakala** ve **Şifreleri Yakala** işaretleyin.
* Bir **yönlendirme** ayarlayın.

![](<../../.gitbook/assets/image (826).png>)

{% hint style="info" %}
Genellikle sayfanın HTML kodunu değiştirmeniz ve yerel olarak bazı testler yapmanız gerekecek (belki bazı Apache sunucusu kullanarak) **sonuçlardan memnun kalana kadar.** Sonra, o HTML kodunu kutuya yazın.\
HTML için **bazı statik kaynaklar** kullanmanız gerekiyorsa (belki bazı CSS ve JS sayfaları) bunları _**/opt/gophish/static/endpoint**_ dizinine kaydedebilir ve ardından _**/static/\<filename>**_ üzerinden erişebilirsiniz.
{% endhint %}

{% hint style="info" %}
Yönlendirme için kullanıcıları **kurbanın meşru ana web sayfasına yönlendirebilir** veya örneğin _/static/migration.html_ sayfasına yönlendirebilir, 5 saniye boyunca bir **dönme tekerleği** ([**https://loading.io/**](https://loading.io)**) koyabilir ve ardından işlemin başarılı olduğunu belirtebilirsiniz. 
{% endhint %}

### Kullanıcılar & Gruplar

* Bir isim ayarlayın.
* **Verileri içe aktarın** (örneğin, şablonu kullanmak için her kullanıcının adı, soyadı ve e-posta adresine ihtiyacınız olduğunu unutmayın).

![](<../../.gitbook/assets/image (163).png>)

### Kampanya

Son olarak, bir isim, e-posta şablonu, açılış sayfası, URL, gönderim profili ve grup seçerek bir kampanya oluşturun. URL'nin kurbanlara gönderilecek bağlantı olacağını unutmayın.

**Gönderim Profili, test e-postası göndererek son phishing e-postasının nasıl görüneceğini görmenizi sağlar**:

![](<../../.gitbook/assets/image (192).png>)

{% hint style="info" %}
Test e-postalarını **10 dakikalık e-posta adreslerine** göndermeyi öneririm, böylece test yaparken kara listeye alınmaktan kaçınabilirsiniz.
{% endhint %}

Her şey hazır olduğunda, kampanyayı başlatın!

## Web Sitesi Klonlama

Herhangi bir nedenle web sitesini klonlamak isterseniz, aşağıdaki sayfayı kontrol edin:

{% content-ref url="clone-a-website.md" %}
[clone-a-website.md](clone-a-website.md)
{% endcontent-ref %}

## Arka Kapılı Belgeler & Dosyalar

Bazı phishing değerlendirmelerinde (özellikle Kırmızı Takımlar için) **bir tür arka kapı içeren dosyalar göndermek** isteyebilirsiniz (belki bir C2 veya belki sadece bir kimlik doğrulama tetikleyici).\
Bazı örnekler için aşağıdaki sayfayı kontrol edin:

{% content-ref url="phishing-documents.md" %}
[phishing-documents.md](phishing-documents.md)
{% endcontent-ref %}

## Phishing MFA

### Proxy MitM Üzerinden

Önceki saldırı oldukça zekice, çünkü gerçek bir web sitesini taklit ediyor ve kullanıcının belirlediği bilgileri topluyorsunuz. Ne yazık ki, kullanıcı doğru şifreyi girmediyse veya taklit ettiğiniz uygulama 2FA ile yapılandırılmışsa, **bu bilgi sizi kandırılan kullanıcı gibi göstermez**.

Bu noktada [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) ve [**muraena**](https://github.com/muraenateam/muraena) gibi araçlar faydalıdır. Bu araç, MitM benzeri bir saldırı oluşturmanıza olanak tanır. Temelde, saldırılar şu şekilde çalışır:

1. Gerçek web sayfasının **giriş** formunu taklit edersiniz.
2. Kullanıcı **kimlik bilgilerini** sahte sayfanıza gönderir ve araç bunları gerçek web sayfasına gönderir, **kimlik bilgilerin çalışıp çalışmadığını kontrol eder**.
3. Hesap **2FA** ile yapılandırılmışsa, MitM sayfası bunu isteyecek ve kullanıcı **girdiğinde** aracı gerçek web sayfasına gönderecektir.
4. Kullanıcı kimlik doğrulandıktan sonra (saldırgan olarak) **kimlik bilgilerini, 2FA'yı, çerezi ve aracın MitM gerçekleştirdiği her etkileşimden herhangi bir bilgiyi** yakalamış olacaksınız.

### VNC Üzerinden

Kurbanı **orijinaline benzer bir kötü amaçlı sayfaya göndermek** yerine, onu **gerçek web sayfasına bağlı bir tarayıcı ile bir VNC oturumuna** göndermeyi düşünsenize? Ne yaptığını görebilir, şifreyi, kullanılan MFA'yı, çerezleri çalabilirsiniz...\
Bunu [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) ile yapabilirsiniz.

## Tespiti Tespit Etme

Elbette, yakalandığınızı anlamanın en iyi yollarından biri, **alan adınızı kara listelerde aramaktır**. Eğer listelenmişse, bir şekilde alan adınız şüpheli olarak tespit edilmiştir.\
Alan adınızın herhangi bir kara listede görünüp görünmediğini kontrol etmenin kolay bir yolu [https://malwareworld.com/](https://malwareworld.com) kullanmaktır.

Ancak, kurbanın **şüpheli phishing faaliyetlerini aktif olarak arayıp aramadığını** anlamanın başka yolları da vardır, bunlar aşağıda açıklanmıştır:

{% content-ref url="detecting-phising.md" %}
[detecting-phising.md](detecting-phising.md)
{% endcontent-ref %}

**Kurbanın alan adına çok benzer bir isimle bir alan adı satın alabilir** ve/veya **sizin kontrolünüzdeki bir alanın** **alt alanı için bir sertifika oluşturabilirsiniz** **ve kurbanın alan adının** **anahtar kelimesini** içerebilirsiniz. Eğer **kurban** onlarla herhangi bir **DNS veya HTTP etkileşimi** gerçekleştirirse, **şüpheli alan adlarını aktif olarak aradığını** bileceksiniz ve çok dikkatli olmanız gerekecek.

### Phishing'i Değerlendirme

E-postanızın spam klasörüne düşüp düşmeyeceğini veya engellenip engellenmeyeceğini veya başarılı olup olmayacağını değerlendirmek için [**Phishious**](https://github.com/Rices/Phishious) kullanın.

## Referanslar

* [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
* [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
* [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
* [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
