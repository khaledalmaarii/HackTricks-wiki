# Phishing Metodolojisi

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünleri**](https://peass.creator-spring.com)'ni edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)'da **takip edin**.
* **Hacking püf noktalarınızı paylaşarak** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR göndererek.

</details>

## Metodoloji

1. Kurbanı keşfet
1. **Kurban alanını** seçin.
2. Kurban tarafından kullanılan **giriş portallarını araştırarak** bazı temel web numaralandırma işlemleri gerçekleştirin ve **taklit edeceğiniz** portali **belirleyin**.
3. Bazı **OSINT** kullanarak **e-postaları bulun**.
2. Ortamı hazırlayın
1. Saldırı değerlendirmesi için kullanacağınız alan adını **satın alın**
2. İlgili kayıtlarla (SPF, DMARC, DKIM, rDNS) ilişkili e-posta hizmetini **yapılandırın**
3. VPS'yi **gophish** ile yapılandırın
3. Kampanyayı hazırlayın
1. **E-posta şablonunu** hazırlayın
2. Kimlik bilgilerini çalmak için **web sayfasını** hazırlayın
4. Kampanyayı başlatın!

## Benzer alan adı oluşturma veya güvenilir bir alan adı satın alma

### Alan Adı Varyasyon Teknikleri

* **Anahtar kelime**: Alan adı, orijinal alan adının önemli bir **anahtar kelimesini içerir** (örneğin, zelster.com-yönetim.com).
* **Alt alan tireli**: Alt alan adı için **noktayı kısa çizgiyle değiştirin** (örneğin, www-zelster.com).
* **Yeni TLD**: Aynı alan adını yeni bir **TLD kullanarak** (örneğin, zelster.org)
* **Homoglyph**: Alan adındaki bir harfi, benzer görünümlü harflerle **değiştirir** (örneğin, zelfser.com).
* **Transpozisyon:** Alan adı içindeki iki harfi **yer değiştirir** (örneğin, zelsetr.com).
* **Tekil/çoğul**: Alan adının sonuna “s” ekler veya çıkarır (örneğin, zeltsers.com).
* **Çıkarma**: Alan adından bir harfi **çıkarır** (örneğin, zelser.com).
* **Tekrarlama**: Alan adındaki bir harfi **tekrarlar** (örneğin, zeltsser.com).
* **Değiştirme**: Homoglyph gibi ancak daha az gizli. Alan adındaki bir harfi, belki de klavyedeki orijinal harfe yakın bir harfle **değiştirir** (örneğin, zektser.com).
* **Alt alanlı**: Alan adının içine bir **nokta** ekler (örneğin, ze.lster.com).
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

**Güneş lekeleri, kozmik ışınlar veya donanım hataları gibi çeşitli faktörlerden dolayı depolanan veya iletişimde olan bazı bitlerin otomatik olarak tersine dönme olasılığı vardır.**

Bu kavram **DNS isteklerine uygulandığında**, DNS sunucusu tarafından alınan **alan adının** başlangıçta istenen alan adıyla aynı olmadığı mümkündür.

Örneğin, "windows.com" alanındaki tek bir bit değişikliği, onu "windnws.com" olarak değiştirebilir.

Saldırganlar, meşru kullanıcıları kendi altyapılarına yönlendirmeyi amaçlayan kurbanın alan adına benzer **çoklu bit-flipping alan adlarını** kaydederek bundan faydalanabilirler.

Daha fazla bilgi için [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/) adresini ziyaret edin.

### Güvenilir bir alan adı satın alma

[https://www.expireddomains.net/](https://www.expireddomains.net) adresinde kullanılmayan bir alan adını arayabilirsiniz.\
Satın almayı düşündüğünüz kullanılmayan alan adının **zaten iyi bir SEO'ya sahip olup olmadığını** kontrol etmek için şu kategorilere nasıl sınıflandırıldığını araştırabilirsiniz:

* [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
* [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## E-postaları Keşfetme

* [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% ücretsiz)
* [https://phonebook.cz/](https://phonebook.cz) (100% ücretsiz)
* [https://maildb.io/](https://maildb.io)
* [https://hunter.io/](https://hunter.io)
* [https://anymailfinder.com/](https://anymailfinder.com)

Daha fazla geçerli e-posta adresi keşfetmek veya zaten keşfettiğiniz e-postaları **doğrulamak için** kurbanın smtp sunucularını brute-force yöntemiyle kontrol edebilirsiniz. [E-posta adresini doğrulama/keşfetme hakkında bilgi edinin buradan](../../network-services-pentesting/pentesting-smtp/#username-bruteforce-enumeration).\
Ayrıca, kullanıcılar **e-postalarına erişmek için herhangi bir web portalı kullanıyorsa**, bu portalın **kullanıcı adı brute force** saldırısına karşı savunmasız olup olmadığını kontrol edebilir ve mümkünse bu zafiyeti sömürebilirsiniz.

## GoPhish'i Yapılandırma

### Kurulum

[https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0) adresinden indirebilirsiniz

İndirin ve `/opt/gophish` dizinine açın ve `/opt/gophish/gophish`'i çalıştırın\
Yönetici kullanıcısı için bir şifre verilecektir, bu nedenle bu portu ziyaret edin ve bu kimlik bilgilerini kullanarak yönetici şifresini değiştirin. Bu portu yerel olarak yönlendirmeniz gerekebilir.
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Yapılandırma

**TLS sertifikası yapılandırması**

Bu adımdan önce kullanacağınız alan adını **zaten satın almış olmalısınız** ve alan adının **gophish**'i yapılandırdığınız **VPS'in IP'sine işaret etmesi gerekmektedir**.
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

Ardından alan adını aşağıdaki dosyalara ekleyin:

* **/etc/postfix/virtual\_domains**
* **/etc/postfix/transport**
* **/etc/postfix/virtual\_regexp**

**Ayrıca /etc/postfix/main.cf içindeki aşağıdaki değişkenlerin değerlerini değiştirin**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Son olarak, **`/etc/hostname`** ve **`/etc/mailname`** dosyalarını alan adınıza göre değiştirin ve **VPS'nizi yeniden başlatın.**

Şimdi, `mail.<domain>`'in **VPS'nin ip adresine** işaret eden bir **DNS A kaydı** ve `mail.<domain>`'e işaret eden bir **DNS MX** kaydı oluşturun.

Şimdi bir e-posta göndermeyi test edelim:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish yapılandırması**

Gophish'in çalışmasını durdurun ve yapılandırın.\
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
**Gophish servisini yapılandırın**

Gophish servisini otomatik olarak başlatılabilir ve yönetilebilir hale getirmek için aşağıdaki içeriğe sahip `/etc/init.d/gophish` dosyasını oluşturabilirsiniz:
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
Servisi yapılandırmayı tamamlayın ve kontrol etmek için aşağıdakileri yapın:
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
## Posta sunucusu ve alan adını yapılandırma

### Bekle ve meşru ol

Bir alan adı ne kadar eskiyse, spam olarak yakalanma olasılığı o kadar az olur. Bu nedenle, siber güvenlik değerlendirmesinden önce mümkün olduğunca uzun süre beklemelisiniz (en az 1 hafta). Ayrıca, itibarlı bir sektör hakkında bir sayfa yayınlarsanız, elde edilen itibar daha iyi olacaktır.

Unutmayın ki bir hafta beklemek zorunda olsanız da şimdi her şeyi yapılandırmayı bitirebilirsiniz.

### Ters DNS (rDNS) kaydını yapılandırma

VPS'nin IP adresini alan adına çözen bir rDNS (PTR) kaydı ayarlayın.

### Gönderen Politika Çerçevesi (SPF) Kaydı

Yeni alan adı için bir SPF kaydı yapılandırmalısınız. Eğer SPF kaydı nedir bilmiyorsanız [bu sayfayı okuyun](../../network-services-pentesting/pentesting-smtp/#spf).

SPF politikanızı oluşturmak için [https://www.spfwizard.net/](https://www.spfwizard.net) adresini kullanabilirsiniz (VPS makinesinin IP'sini kullanın)

![](<../../.gitbook/assets/image (1037).png>)

Bu, alan içinde bir TXT kaydı içinde ayarlanması gereken içeriktir:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Alan Tabanlı Mesaj Kimliği Doğrulama, Raporlama ve Uyum (DMARC) Kaydı

Yeni alan adı için bir DMARC kaydı **yapılandırmalısınız**. Bir DMARC kaydının ne olduğunu bilmiyorsanız [**bu sayfayı okuyun**](../../network-services-pentesting/pentesting-smtp/#dmarc).

Aşağıdaki içeriğe sahip yeni bir DNS TXT kaydı oluşturmanız gerekmektedir ve bu kayıt, `_dmarc.<alanadı>` isimli ana bilgisayar adını işaret etmelidir:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Yeni alan adı için bir DKIM **yapılandırmalısınız**. Bir DMARC kaydının ne olduğunu bilmiyorsanız [**bu sayfayı okuyun**](../../network-services-pentesting/pentesting-smtp/#dkim).

Bu kılavuz şuraya dayanmaktadır: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

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
Ayrıca, e-posta yapılandırmanızı kontrol edebilirsiniz, bunun için bir e-posta göndererek `check-auth@verifier.port25.com` adresine ve yanıtı okuyarak (bunun için port 25'i açmanız ve e-postayı root olarak gönderirseniz yanıtı _/var/mail/root_ dosyasında görebilirsiniz).\
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
Ayrıca **kontrolünüz altındaki bir Gmail'e mesaj gönderebilir** ve Gmail gelen kutunuzda **e-posta başlıklarını** kontrol edebilirsiniz, `dkim=pass` ifadesinin `Authentication-Results` başlık alanında bulunması gerekmektedir.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Spamhouse Kara Listeden Kaldırma

[www.mail-tester.com](https://www.mail-tester.com) sayfası, alan adınızın spamhouse tarafından engellenip engellenmediğini size gösterebilir. Alan adınızı/IP'nizi kaldırmak için şuraya başvurabilirsiniz: [https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Microsoft Kara Listeden Kaldırma

Alan adınızı/IP'nizi kaldırmak için [https://sender.office.com/](https://sender.office.com) adresinden başvuruda bulunabilirsiniz.

## GoPhish Kampanyası Oluşturma ve Başlatma

### Gönderim Profili

* Gönderen profiliyi tanımlamak için **bir isim belirleyin**
* Balık avı e-postalarını hangi hesaptan göndereceğinize karar verin. Öneriler: _noreply, support, servicedesk, salesforce..._
* Kullanıcı adını ve şifreyi boş bırakabilirsiniz, ancak Sertifika Hatalarını Yoksay'ı kontrol ettiğinizden emin olun

![](<../../.gitbook/assets/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

{% hint style="info" %}
Her şeyin çalıştığını test etmek için "**Test E-postası Gönder**" işlevini kullanmanız önerilir.\
Testler yaparken kara listeye alınmamak için **test e-postalarını 10 dakikalık e-posta adreslerine göndermenizi öneririm**.
{% endhint %}

### E-posta Şablonu

* Şablonu tanımlamak için **bir isim belirleyin**
* Daha sonra bir **konu** yazın (garip bir şey olmasın, sıradan bir e-postada okumayı bekleyebileceğiniz bir şey)
* "**İzleme Resmi Ekle**" seçeneğini işaretlediğinizden emin olun
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

* **Var olmayan bir adrese** e-posta gönderin ve yanıtta herhangi bir imza olup olmadığını kontrol edin.
* info@ex.com veya press@ex.com veya public@ex.com gibi **genel e-postaları** arayın ve onlara bir e-posta gönderin ve yanıtı bekleyin.
* **Bazı geçerli keşfedilmiş** e-postalarla iletişime geçmeye çalışın ve yanıtı bekleyin.

![](<../../.gitbook/assets/image (80).png>)

{% hint style="info" %}
E-posta Şablonu ayrıca **göndermek için dosya eklemenize** olanak tanır. Özel olarak hazırlanmış dosyalar/dokümanlar kullanarak NTLM zorluklarını çalmak istiyorsanız [bu sayfayı okuyun](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).
{% endhint %}

### İniş Sayfası

* Bir **ad** yazın
* Web sayfasının HTML kodunu yazın. Web sayfalarını **ithal edebileceğinizi** unutmayın.
* **Gönderilen Verileri Yakala** ve **Şifreleri Yakala** işaretleyin
* Bir **yönlendirme** ayarlayın

![](<../../.gitbook/assets/image (826).png>)

{% hint style="info" %}
Genellikle sayfanın HTML kodunu değiştirmeniz ve bazı testler yapmanız gerekecektir (belki bazı Apache sunucusu kullanarak yerelde) **sonuçları beğenene kadar**. Sonra, o HTML kodunu kutuya yazın.\
HTML için **bazı statik kaynakları kullanmanız gerekiyorsa** (belki bazı CSS ve JS sayfaları) onları _**/opt/gophish/static/endpoint**_ içine kaydedebilir ve ardından _**/static/\<dosyaadı>**_ adresinden erişebilirsiniz.
{% endhint %}

{% hint style="info" %}
Yönlendirme için kullanıcıları **kurbanın meşru ana web sayfasına yönlendirebilirsiniz**, veya örneğin _/static/migration.html_ sayfasına yönlendirebilir, 5 saniye boyunca **dönen çark** ([**https://loading.io/**](https://loading.io)) ekleyebilir ve ardından işlemin başarılı olduğunu belirtebilirsiniz.
{% endhint %}

### Kullanıcılar & Gruplar

* Bir ad belirleyin
* Verileri **ithal edin** (örneğin, örneğin şablonu kullanmak için her kullanıcının adı, soyadı ve e-posta adresine ihtiyacınız olacak)

![](<../../.gitbook/assets/image (163).png>)

### Kampanya

Son olarak, bir kampanya oluşturun, bir ad, e-posta şablonu, iniş sayfası, URL, gönderme profili ve grup seçerek. URL'nin, kurbanlara gönderilen bağlantı olacağını unutmayın

**Gönderme Profili, son phishing e-postasının nasıl görüneceğini görmek için bir test e-postası göndermenize olanak tanır**:

![](<../../.gitbook/assets/image (192).png>)

{% hint style="info" %}
Test e-postalarını **siyah listeye alınmamak için 10 dakikalık e-posta adreslerine göndermenizi öneririm**.
{% endhint %}

Her şey hazır olduğunda, kampanyayı başlatın!

## Website Klonlama

Herhangi bir nedenden dolayı web sitesini klonlamak isterseniz aşağıdaki sayfaya bakın:

{% content-ref url="clone-a-website.md" %}
[clone-a-website.md](clone-a-website.md)
{% endcontent-ref %}

## Arka Kapılı Belgeler & Dosyalar

Bazı phishing değerlendirmelerinde (genellikle Kırmızı Takımlar için) ayrıca **arka kapı içeren dosyalar göndermek isteyeceksiniz** (belki bir C2 veya belki sadece kimlik doğrulamasını tetikleyecek bir şey).\
Örnekler için aşağıdaki sayfaya bakın:

{% content-ref url="phishing-documents.md" %}
[phishing-documents.md](phishing-documents.md)
{% endcontent-ref %}

## Phishing MFA

### Proxy MitM Aracılığıyla

Önceki saldırı oldukça zekice çünkü gerçek bir web sitesini taklit ediyorsunuz ve kullanıcı tarafından belirlenen bilgileri topluyorsunuz. Ne yazık ki, kullanıcı doğru şifreyi girmediyse veya taklit ettiğiniz uygulama 2FA ile yapılandırılmışsa, **bu bilgiler sizi aldatılan kullanıcıyı taklit etmeye yetmeyecek**.

Bu tür durumlarda [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) ve [**muraena**](https://github.com/muraenateam/muraena) gibi araçlar işe yarar. Bu araçlar size MitM benzeri bir saldırı oluşturmanıza olanak tanır. Temelde, saldırılar aşağıdaki şekilde çalışır:

1. Gerçek web sayfasının **girişini taklit edersiniz**.
2. Kullanıcı **kimlik bilgilerini** sahte sayfanıza gönderir ve araç bunları gerçek web sayfasına gönderir, **kimlik bilgilerinin çalışıp çalışmadığını kontrol eder**.
3. Hesap **2FA ile yapılandırılmışsa**, MitM sayfası bunu isteyecek ve **kullanıcı girdiğinde** araç bunu gerçek web sayfasına gönderecektir.
4. Kullanıcı kimlik doğrulandığında siz (saldırgan olarak) **kimlik bilgilerini, 2FA'yı, çerezi ve araç MitM işlemi sırasında her etkileşimin herhangi bir bilgisini yakalamış olacaksınız**.

### VNC Aracılığıyla

Kurbanı orijinaline benzer görünüme sahip **kötü niyetli bir sayfaya yönlendirmek** yerine, onu **gerçek web sayfasına bağlı bir tarayıcı olan bir VNC oturumuna yönlendirirseniz** ne olurdu? Ne yaptığını görebilecek, şifreyi çalabilecek, kullanılan MFA'yı, çerezleri çalabileceksiniz...\
Bunu [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) ile yapabilirsiniz

## Tespitin Tespiti

Tabii ki, yakalandığınızı bilmek için en iyi yollardan biri **alanınızı siyah listelerde aramaktır**. Eğer listede görünüyorsa, alanınızın şüpheli olarak algılandığı bir şekilde algılanmıştır.\
Alanınızın herhangi bir siyah listede olup olmadığını kontrol etmenin kolay bir yolu [https://malwareworld.com/](https://malwareworld.com) kullanmaktır

Ancak, kurbanın **vahşi doğada şüpheli phishing etkinliği aradığını aktif olarak bilmek** için başka yollar da vardır, aşağıdaki sayfada açıklandığı gibi:

{% content-ref url="detecting-phising.md" %}
[detecting-phising.md](detecting-phising.md)
{% endcontent-ref %}

Kurbanın alan adına çok benzer bir alan adı **satın alabilir** ve/veya sizin kontrolünüzdeki bir alan adının alt alan adı için bir **sertifika oluşturabilirsiniz** ve kurbanın alan adının anahtar kelimesini içeren bir alt alan adı. Eğer **kurban** bunlarla herhangi bir **DNS veya HTTP etkileşimi** yaparsa, **şüpheli alanları aradığını** bileceksiniz ve çok gizli olmanız gerekecektir.

### Phishing'i Değerlendirme

E-postanızın spam klasöründe mi yoksa engellenmiş mi yoksa başarılı mı olacağını değerlendirmek için [**Phishious** ](https://github.com/Rices/Phishious)'u kullanın.

## Referanslar

* [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
* [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
* [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
* [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
