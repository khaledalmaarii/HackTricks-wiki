# Harici Keşif Metodolojisi

<details>

<summary><strong>Sıfırdan kahraman olmaya kadar AWS hacklemeyi öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na göz atın (https://github.com/sponsors/carlospolop)!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı göndererek HackTricks ve HackTricks Cloud** github depolarına PR göndererek paylaşın.

</details>

<figure><img src="../../.gitbook/assets/image (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Eğer **hacking kariyeri**ne ilgi duyuyorsanız ve hacklenemez olanı hacklemek istiyorsanız - **işe alıyoruz!** (_akıcı Lehçe yazılı ve konuşma gereklidir_).

{% embed url="https://www.stmcyber.com/careers" %}

## Varlıkların Keşfi

> Dolayısıyla, bir şirkete ait her şeyin kapsamda olduğu söylendi ve bu şirketin aslında neye sahip olduğunu anlamak istiyorsunuz.

Bu aşamanın amacı, öncelikle **ana şirkete ait olan şirketleri** elde etmek ve ardından bu şirketlerin **varlıklarını** elde etmektir. Bunun için şunları yapacağız:

1. Ana şirketin satın almalarını bulmak, bu bize kapsamda olan şirketleri verecektir.
2. Her şirketin ASN'sini (varsa) bulmak, bu bize her şirketin sahip olduğu IP aralıklarını verecektir.
3. İlkini aramak için ters whois aramalarını kullanarak diğer girişleri (kuruluş adları, alan adları...) aramak (bu rekürsif olarak yapılabilir)
4. Shodan `org` ve `ssl` filtreleri gibi diğer teknikleri kullanarak diğer varlıkları aramak (`ssl` hilesi rekürsif olarak yapılabilir).

### **Satın Almalar**

Öncelikle, **ana şirkete ait olan diğer şirketleri** bilmemiz gerekiyor.\
Bir seçenek, [https://www.crunchbase.com/](https://www.crunchbase.com) adresini ziyaret etmek, **ana şirketi aramak** ve "**satın almalar**"ı **tıklamak**. Orada ana şirket tarafından satın alınan diğer şirketleri göreceksiniz.\
Diğer bir seçenek, ana şirketin **Wikipedia** sayfasını ziyaret etmek ve **satın almaları** aramaktır.

> Tamam, bu noktada kapsamda olan tüm şirketleri bilmelisiniz. Şimdi varlıklarını nasıl bulacağımızı anlayalım.

### **ASN'ler**

Bir otomatik sistem numarası (**ASN**), bir **otonom sistem** (AS) tarafından **Internet Assigned Numbers Authority (IANA)** tarafından bir **benzersiz numara** olarak atanmıştır.\
Bir **AS**, dış ağlara erişim için belirgin bir politikaya sahip **IP adresi bloklarından** oluşur ve tek bir kuruluş tarafından yönetilir ancak birkaç operatörden oluşabilir.

Şirketin **herhangi bir ASN atayıp atamadığını** bulmak, **IP aralıklarını** bulmak için ilginç olacaktır. Kapsam içindeki tüm **ana bilgisayarlar** üzerinde bir **zafiyet testi** gerçekleştirmek ve bu IP'lerdeki **alan adlarını** aramak ilginç olacaktır.\
[**https://bgp.he.net/**](https://bgp.he.net) adresinde şirket **adı**, **IP** veya **alan adı** ile arama yapabilirsiniz.\
**Şirketin bölgesine bağlı olarak bu bağlantılar daha fazla veri toplamak için yararlı olabilir:** [**AFRINIC**](https://www.afrinic.net) **(Afrika),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Kuzey Amerika),** [**APNIC**](https://www.apnic.net) **(Asya),** [**LACNIC**](https://www.lacnic.net) **(Latin Amerika),** [**RIPE NCC**](https://www.ripe.net) **(Avrupa). Her durumda, tüm** yararlı bilgiler **(IP aralıkları ve Whois)** muhtemelen ilk bağlantıda zaten görünüyor.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Ayrıca, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'un** alt alan adı tespiti otomatik olarak taramanın sonunda ASN'leri toplar ve özetler.
```bash
bbot -t tesla.com -f subdomain-enum
...
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS394161 | 8.244.131.0/24      | 5            | TESLA          | Tesla Motors, Inc.         | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS16509  | 54.148.0.0/15       | 4            | AMAZON-02      | Amazon.com, Inc.           | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS394161 | 8.45.124.0/24       | 3            | TESLA          | Tesla Motors, Inc.         | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS3356   | 8.32.0.0/12         | 1            | LEVEL3         | Level 3 Parent, LLC        | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS3356   | 8.0.0.0/9           | 1            | LEVEL3         | Level 3 Parent, LLC        | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+

```
Organizasyonun IP aralıklarını [http://asnlookup.com/](http://asnlookup.com) (ücretsiz API'ye sahiptir) kullanarak bulabilirsiniz.\
Bir alanın IP'sini ve ASN'sini [http://ipv4info.com/](http://ipv4info.com) kullanarak bulabilirsiniz.

### **Zaafiyet arayışı**

Bu noktada **kapsamdaki tüm varlıkları bildiğimizden**, izin verildiyse tüm ana bilgisayarlarda bazı **zafiyet taraması** (Nessus, OpenVAS) başlatabilirsiniz.\
Ayrıca, bazı [**port taramaları**](../pentesting-network/#discovering-hosts-from-the-outside) başlatabilir veya shodan gibi hizmetleri kullanarak **açık portları bulabilir ve bulduklarınıza bağlı olarak** bu kitapta çalıştırılan çeşitli olası hizmetleri nasıl pentest edeceğinize bakmalısınız.\
**Ayrıca, varsayılan kullanıcı adı** ve **şifre listeleri hazırlayabilir ve [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) ile hizmetleri** brute force ile deneyebilirsiniz.

## Alanlar

> Kapsamdaki tüm şirketleri ve varlıklarını bildiğimiz için, kapsamdaki alanları bulma zamanı geldi.

_Lütfen, aşağıda önerilen tekniklerde alt alanlar da bulabileceğinizi ve bu bilginin göz ardı edilmemesi gerektiğini unutmayın._

Öncelikle her şirketin **ana alanını** aramalısınız. Örneğin, _Tesla Inc._ için _tesla.com_ olacaktır.

### **Ters DNS**

Alanların tüm IP aralıklarını bulduğunuzda, bu IP'ler üzerinde **ters dns aramaları** yaparak **kapsamdaki daha fazla alanı bulmaya çalışabilirsiniz**. Kurbanın bazı dns sunucularını veya bazı iyi bilinen dns sunucularını (1.1.1.1, 8.8.8.8) kullanmaya çalışın.
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Bu işlem için yöneticinin PTR'yi manuel olarak etkinleştirmesi gerekmektedir.\
Bu bilgiyi almak için çevrimiçi bir araç da kullanabilirsiniz: [http://ptrarchive.com/](http://ptrarchive.com)

### **Ters Whois (döngü)**

**Whois** içinde **kuruluş adı**, **adres**, **e-postalar**, telefon numaraları gibi birçok ilginç **bilgi** bulabilirsiniz. Ancak daha da ilginç olanı, **şirketle ilgili daha fazla varlık** bulabilirsiniz eğer bu alanlardan herhangi biriyle **ters whois aramaları gerçekleştirirseniz** (örneğin aynı e-postanın göründüğü diğer whois kayıtları).\
Çevrimiçi araçlar kullanabilirsiniz:

* [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Ücretsiz**
* [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Ücretsiz**
* [https://www.reversewhois.io/](https://www.reversewhois.io) - **Ücretsiz**
* [https://www.whoxy.com/](https://www.whoxy.com) - **Ücretsiz** web, ücretsiz API değil.
* [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Ücretsiz değil
* [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Ücretsiz değil (sadece **100 ücretsiz** arama)
* [https://www.domainiq.com/](https://www.domainiq.com) - Ücretsiz değil

Bu görevi [**DomLink** ](https://github.com/vysecurity/DomLink)(whoxy API anahtarı gerektirir) kullanarak otomatikleştirebilirsiniz.\
Ayrıca [amass](https://github.com/OWASP/Amass) ile otomatik ters whois keşfi yapabilirsiniz: `amass intel -d tesla.com -whois`

**Yeni bir alan bulduğunuzda her zaman daha fazla alan adı keşfetmek için bu tekniği kullanabileceğinizi unutmayın.**

### **İzleyiciler**

Aynı **izleyicinin aynı kimliğini** 2 farklı sayfada bulursanız, **her iki sayfanın** de **aynı ekip tarafından yönetildiğini** varsayabilirsiniz.\
Örneğin, birkaç sayfada aynı **Google Analytics kimliğini** veya aynı **Adsense kimliğini** görürseniz.

Bu izleyiciler ve daha fazlasıyla arama yapmanıza izin veren bazı sayfalar ve araçlar bulunmaktadır:

* [**Udon**](https://github.com/dhn/udon)
* [**BuiltWith**](https://builtwith.com)
* [**Sitesleuth**](https://www.sitesleuth.io)
* [**Publicwww**](https://publicwww.com)
* [**SpyOnWeb**](http://spyonweb.com)

### **Favicon**

Hedefimize ait ilgili alan adlarını ve alt alan adlarını aynı favicon simgesi karmasını arayarak bulabileceğimizi biliyor muydunuz? İşte bunu [@m4ll0k2](https://twitter.com/m4ll0k2) tarafından yapılan [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) aracı tam olarak yapar. Kullanımı şöyle:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - aynı favicon ikonu hash'ine sahip alan adlarını keşfedin](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Basitçe söylemek gerekirse, favihash bize hedefimizle aynı favicon ikonu hash'ine sahip alanları keşfetmemizi sağlayacak.

Ayrıca, favicon hash'ini kullanarak teknolojileri arayabilirsiniz, [**bu blog yazısında**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139) açıklandığı gibi. Bu, web teknolojisinin savunmasız bir sürümünün favicon'unun hash'ini biliyorsanız, shodan'da arayabilir ve **daha fazla savunmasız yeri bulabilirsiniz**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
Bu, bir web sitesinin **favicon hash'ini hesaplamanın** yollarından biridir:
```python
import mmh3
import requests
import codecs

def fav_hash(url):
response = requests.get(url)
favicon = codecs.encode(response.content,"base64")
fhash = mmh3.hash(favicon)
print(f"{url} : {fhash}")
return fhash
```
### **Telif Hakkı / Benzersiz dize**

Aynı kuruluş içinde farklı web siteleri arasında paylaşılabilecek dizeleri aramak için web sayfalarının içinde arama yapın. **Telif hakkı dizesi** iyi bir örnek olabilir. Ardından bu dizeyi **google**, diğer **tarayıcılarda** hatta **shodan** da arayın: `shodan search http.html:"Telif hakkı dizesi"`

### **CRT Zamanı**

Genellikle şu gibi bir cron işi olması yaygındır:
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
Sunucudaki tüm alan sertifikalarını yenilemek için. Bu, bunun için kullanılan CA'nın Geçerlilik süresinde üretildiği zamanı ayarlamadığı anlamına gelse bile, **sertifika şeffaflık günlüklerinde aynı şirkete ait alanları bulmak mümkündür**.\
Daha fazla bilgi için [**bu yazıya bakın**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

### Posta DMARC bilgileri

[https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) gibi bir web sitesi veya [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) gibi bir araç kullanarak **aynı dmarc bilgilerini paylaşan alanları ve alt alanları bulabilirsiniz**.

### **Pasif Ele Geçirme**

Görünüşe göre insanlar alt alanları bulut sağlayıcılarına ait IP'lere atarlar ve bir noktada **o IP adresini kaybederler ancak DNS kaydını kaldırmayı unuturlar**. Bu nedenle, sadece bir VM oluşturarak (Digital Ocean gibi) aslında **bazı alt alanları devralırsınız**.

[**Bu yazı**](https://kmsec.uk/blog/passive-takeover/) bununla ilgili bir hikayeyi açıklar ve **DigitalOcean'da bir VM oluşturan**, yeni makinenin **IPv4**'ünü **alan** ve ona işaret eden **alt alan kayıtlarını Virustotal'da arayan** bir betik önerir.

### **Diğer Yöntemler**

**Bu tekniği kullanarak her yeni alan bulduğunuzda daha fazla alan adı keşfedebileceğinizi unutmayın.**

**Shodan**

IP alanına sahip olan kuruluşun adını zaten biliyorsunuz. Bu verilerle shodan'da şuna göre arama yapabilirsiniz: `org:"Tesla, Inc."` TLS sertifikasında yeni beklenmeyen alanları kontrol edin.

Ana web sayfasının **TLS sertifikasına** erişebilir, **Organizasyon adını** alabilir ve ardından **shodan** tarafından bilinen tüm web sayfalarının **TLS sertifikaları içinde** bu adı arayabilirsiniz: `ssl:"Tesla Motors"` veya [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) gibi bir araç kullanabilirsiniz.

**Assetfinder**

[**Assetfinder**](https://github.com/tomnomnom/assetfinder), ana alanla ilgili **alanları** ve bunların **alt alanlarını** arayan bir araçtır, oldukça etkileyici.

### **Zaafiyet Arayışı**

Bazı [alan ele geçirme](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover) durumlarını kontrol edin. Belki bir şirket **bir alan kullanıyor** ancak **sahipliğini kaybetti**. Eğer uygunsa kaydedin ve şirkete bildirin.

Varlık keşfi sırasında bulduğunuz IP'leri zaten bulduklarınızdan farklı olan herhangi bir **alanı kontrol etmelisiniz**, temel bir güvenlik açığı taraması yapmalısınız (Nessus veya OpenVAS kullanarak) ve **nmap/masscan/shodan** ile bazı [**port taraması**](../pentesting-network/#discovering-hosts-from-the-outside) yapmalısınız. Hangi hizmetlerin çalıştığına bağlı olarak, onları "saldırmak" için bu kitapta bazı ipuçları bulabilirsiniz.\
_Bazen alanın müşteri tarafından kontrol edilmeyen bir IP içinde barındırıldığını unutmayın, bu nedenle kapsamda değildir, dikkatli olun._

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**Hata ödülü ipucu**: **Intigriti'ye kaydolun**, hackerlar tarafından oluşturulan bir premium **hata ödülü platformu**! Bugün [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) adresinde bize katılın ve **100.000 $'a kadar ödüller kazanmaya başlayın**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Alt Alanlar

> Kapsamdaki tüm şirketleri, her şirketin tüm varlıklarını ve şirketlerle ilgili tüm alanları biliyoruz.

Her bulunan alanın tüm olası alt alanlarını bulma zamanı geldi.

{% hint style="success" %}
Alanları bulmak için bazı araçlar ve tekniklerin alt alanları bulmaya da yardımcı olabileceğini unutmayın!
{% endhint %}

### **DNS**

**DNS** kayıtlarından **alt alanları** almaya çalışalım. Ayrıca **Zone Transfer** için de denemeliyiz (Eğer savunmasızsa, rapor etmelisiniz).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Birçok alt alan adını elde etmenin en hızlı yolu, harici kaynaklarda arama yapmaktır. En çok kullanılan **araçlar** şunlardır (daha iyi sonuçlar için API anahtarlarını yapılandırın):

* [**BBOT**](https://github.com/blacklanternsecurity/bbot)
```bash
# subdomains
bbot -t tesla.com -f subdomain-enum

# subdomains (passive only)
bbot -t tesla.com -f subdomain-enum -rf passive

# subdomains + port scan + web screenshots
bbot -t tesla.com -f subdomain-enum -m naabu gowitness -n my_scan -o .
```
* [**Amass**](https://github.com/OWASP/Amass)
```bash
amass enum [-active] [-ip] -d tesla.com
amass enum -d tesla.com | grep tesla.com # To just list subdomains
```
* [**subfinder**](https://github.com/projectdiscovery/subfinder)
```bash
# Subfinder, use -silent to only have subdomains in the output
./subfinder-linux-amd64 -d tesla.com [-silent]
```
* [**findomain**](https://github.com/Edu4rdSHL/findomain/)
```bash
# findomain, use -silent to only have subdomains in the output
./findomain-linux -t tesla.com [--quiet]
```
* [**OneForAll**](https://github.com/shmilylty/OneForAll/tree/master/docs/en-us)
```bash
python3 oneforall.py --target tesla.com [--dns False] [--req False] [--brute False] run
```
* [**assetfinder**](https://github.com/tomnomnom/assetfinder)
```bash
assetfinder --subs-only <domain>
```
* [**Sudomy**](https://github.com/Screetsec/Sudomy)
```bash
# It requires that you create a sudomy.api file with API keys
sudomy -d tesla.com
```
* [**vita**](https://github.com/junnlikestea/vita)
```
vita -d tesla.com
```
* [**theHarvester**](https://github.com/laramies/theHarvester)
```bash
theHarvester -d tesla.com -b "anubis, baidu, bing, binaryedge, bingapi, bufferoverun, censys, certspotter, crtsh, dnsdumpster, duckduckgo, fullhunt, github-code, google, hackertarget, hunter, intelx, linkedin, linkedin_links, n45ht, omnisint, otx, pentesttools, projectdiscovery, qwant, rapiddns, rocketreach, securityTrails, spyse, sublist3r, threatcrowd, threatminer, trello, twitter, urlscan, virustotal, yahoo, zoomeye"
```
**Alt alan adlarını bulmaya doğrudan uzmanlaşmamış olsa da**, alt alan adlarını bulmada faydalı olabilecek **diğer ilginç araçlar/API'ler** bulunmaktadır, örneğin:

* [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Alt alan adlarını elde etmek için [https://sonar.omnisint.io](https://sonar.omnisint.io) API'sini kullanır
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
* [**JLDC ücretsiz API**](https://jldc.me/anubis/subdomains/google.com)
```bash
curl https://jldc.me/anubis/subdomains/tesla.com | jq -r ".[]"
```
* [**RapidDNS**](https://rapiddns.io) ücretsiz API
```bash
# Get Domains from rapiddns free API
rapiddns(){
curl -s "https://rapiddns.io/subdomain/$1?full=1" \
| grep -oE "[\.a-zA-Z0-9-]+\.$1" \
| sort -u
}
rapiddns tesla.com
```
* [**https://crt.sh/**](https://crt.sh)
```bash
# Get Domains from crt free API
crt(){
curl -s "https://crt.sh/?q=%25.$1" \
| grep -oE "[\.a-zA-Z0-9-]+\.$1" \
| sort -u
}
crt tesla.com
```
* [**gau**](https://github.com/lc/gau)**:** Belirli bir alan adı için AlienVault'ın Açık Tehdit Değişiminden, Wayback Machine'den ve Common Crawl'dan bilinen URL'leri alır.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
* [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Web'i tarayarak JS dosyalarını arar ve oradan alt alan adlarını çıkarırlar.
```bash
# Get only subdomains from SubDomainizer
python3 SubDomainizer.py -u https://tesla.com | grep tesla.com

# Get only subdomains from subscraper, this already perform recursion over the found results
python subscraper.py -u tesla.com | grep tesla.com | cut -d " " -f
```
* [**Shodan**](https://www.shodan.io/)
```bash
# Get info about the domain
shodan domain <domain>
# Get other pages with links to subdomains
shodan search "http.html:help.domain.com"
```
* [**Censys alt alan adı bulucu**](https://github.com/christophetd/censys-subdomain-finder)
```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```
* [**DomainTrail.py**](https://github.com/gatete/DomainTrail)
```bash
python3 DomainTrail.py -d example.com
```
* [**securitytrails.com**](https://securitytrails.com/), alt alan adları ve IP geçmişini aramak için ücretsiz bir API sunar
* [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Bu proje, **hata ödülü programlarıyla ilgili tüm alt alan adlarını ücretsiz olarak** sunar. Bu verilere [chaospy](https://github.com/dr-0x0x/chaospy) kullanarak erişebilir veya bu projenin kullandığı kapsamı [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list) adresinden de erişebilirsiniz.

Bu araçların **karşılaştırmasını** burada bulabilirsiniz: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Kaba kuvvet**

Mümkün alt alan adı adlarını kullanarak DNS sunucularını kaba kuvvetle arayarak yeni **alt alan adları** bulmaya çalışalım.

Bu işlem için bazı **ortak alt alan adları kelime listelerine** ihtiyacınız olacak:

* [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
* [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
* [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
* [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
* [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Ayrıca iyi DNS çözücülerin IP'lerine de ihtiyacınız olacak. Güvenilir DNS çözücüler listesi oluşturmak için [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) adresinden çözücüleri indirebilir ve bunları filtrelemek için [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) kullanabilirsiniz. Ya da [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt) adresini kullanabilirsiniz.

DNS kaba kuvvet için en çok önerilen araçlar:

* [**massdns**](https://github.com/blechschmidt/massdns): Bu, etkili bir DNS kaba kuvvet gerçekleştiren ilk araçtı. Çok hızlı olmasına rağmen yanlış pozitiflere duyarlıdır.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
* [**gobuster**](https://github.com/OJ/gobuster): Bence bu sadece 1 çözücü kullanıyor
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
* [**shuffledns**](https://github.com/projectdiscovery/shuffledns), aktif bruteforce kullanarak geçerli alt alanları numaralandırmanıza ve joker işleme sahip alt alanları çözmenize olanak tanıyan, go dilinde yazılmış `massdns` etrafında bir sarıcıdır ve giriş-çıkış desteği sağlar.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
* [**puredns**](https://github.com/d3mondev/puredns): Ayrıca `massdns` kullanır.
```
puredns bruteforce all.txt domain.com
```
* [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) alan adlarını asenkron olarak kaba kuvvet uygulamak için asyncio kullanır.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### İkinci DNS Kaba Kuvvet Turu

Açık kaynaklardan ve kaba kuvvet saldırısı ile alt alan adlarını bulduktan sonra bulunan alt alan adlarının değişikliklerini oluşturarak daha fazlasını bulmaya çalışabilirsiniz. Bu amaçla birkaç araç faydalıdır:

* [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Alan adları ve alt alan adlarını verilerek permütasyonlar oluşturur.
```bash
cat subdomains.txt | dnsgen -
```
* [**goaltdns**](https://github.com/subfinder/goaltdns): Alan adları ve alt alan adları verildiğinde permütasyonlar oluşturur.
* goaltdns permütasyonlarını **wordlist**'i [**buradan**](https://github.com/subfinder/goaltdns/blob/master/words.txt) alabilirsiniz.
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
* [**gotator**](https://github.com/Josue87/gotator)**:** Alan adları ve alt alan adları verildiğinde permutasyonlar oluşturur. Eğer permutasyon dosyası belirtilmemişse, gotator kendi dosyasını kullanacaktır.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
* [**altdns**](https://github.com/infosec-au/altdns): Alt alan adı permütasyonları oluşturmanın yanı sıra bunları çözmeye de çalışabilir (ancak önceki yorumlanmış araçları kullanmak daha iyidir).
* altdns permütasyonları **wordlist**'ini [**buradan**](https://github.com/infosec-au/altdns/blob/master/words.txt) alabilirsiniz.
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
* [**dmut**](https://github.com/bp0lr/dmut): Alt alan adlarının permutasyonlarını, mutasyonlarını ve değişikliklerini gerçekleştirmek için başka bir araç. Bu araç sonucu kaba kuvvet uygulayacak (dns joker karakterini desteklemez).
* dmut permutasyon kelime listesini [**buradan**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt) alabilirsiniz.
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
* [**alterx**](https://github.com/projectdiscovery/alterx)**:** Bir alan adına dayanarak, daha fazla alt alan adı keşfetmek için belirtilen desenlere dayalı olarak **yeni potansiyel alt alan adı adları oluşturur**.

#### Akıllı permütasyon oluşturma

* [**regulator**](https://github.com/cramppet/regulator): Daha fazla bilgi için bu [**gönderiyi**](https://cramppet.github.io/regulator/index.html) okuyun, ancak temel olarak **keşfedilen alt alan adlarından ana parçaları alacak** ve daha fazla alt alan adı bulmak için bunları karıştıracaktır.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
* [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_, oldukça basit ancak etkili bir DNS yanıtı rehberli algoritmayla eşleştirilmiş bir alt alan kaba kuvvet fuzzer'dır. Özel bir kelime listesi veya geçmiş DNS/TLS kayıtları gibi sağlanan bir dizi giriş verisini kullanarak daha fazla karşılık gelen alan adını doğru bir şekilde sentezlemek için DNS taraması sırasında toplanan bilgilere dayalı olarak döngü içinde genişletir.
```
echo www | subzuf facebook.com
```
### **Alt Alan Adı Keşfi İş Akışı**

Bu blog yazısını kontrol et, burada **Trickest iş akışlarını kullanarak alan adından alt alan adı keşfini otomatikleştirmenin** nasıl yapıldığı hakkında yazdım, böylece bilgisayarımda manuel olarak bir sürü aracı başlatmama gerek kalmaz:

{% embed url="https://trickest.com/blog/full-subdomain-discovery-using-workflow/" %}

{% embed url="https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/" %}

### **VHosts / Sanal Sunucular**

Eğer bir IP adresi bulursanız ve bu IP adresi alt alan adlarına ait **bir veya birkaç web sayfası** içeriyorsa, bu IP'de **diğer alt alan adlarını bulmaya çalışabilirsiniz**. Bunun için, IP'deki alan adlarını aramak için **OSINT kaynaklarına** veya **o IP'deki VHost alan adlarını brute force ile aramaya** çalışabilirsiniz.

#### OSINT

Bazı **IP'lerdeki VHost'ları** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **veya diğer API'ler kullanarak** bulabilirsiniz.

**Brute Force**

Eğer bir alt alan adının bir web sunucusunda gizli olabileceğinden şüpheleniyorsanız, bunu brute force ile deneyebilirsiniz:
```bash
ffuf -c -w /path/to/wordlist -u http://victim.com -H "Host: FUZZ.victim.com"

gobuster vhost -u https://mysite.com -t 50 -w subdomains.txt

wfuzz -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt --hc 400,404,403 -H "Host: FUZZ.example.com" -u http://example.com -t 100

#From https://github.com/allyshka/vhostbrute
vhostbrute.py --url="example.com" --remoteip="10.1.1.15" --base="www.example.com" --vhosts="vhosts_full.list"

#https://github.com/codingo/VHostScan
VHostScan -t example.com
```
{% hint style="info" %}
Bu teknikle, hatta dahili/gizli uç noktalara erişebilme olasılığınız olabilir.
{% endhint %}

### **CORS Kaba Kuvvet**

Bazen, yalnızca geçerli bir alan/alt alan belirtildiğinde _**Origin**_ başlığında _**Access-Control-Allow-Origin**_ başlığını döndüren sayfalar bulabilirsiniz. Bu senaryolarda, bu davranışı istismar ederek yeni **alt alanlar** **keşfedebilirsiniz**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Kovalama Yöntemleri**

**Alt alan adları** ararken, herhangi bir türde **bucket**'a **işaret edip etmediğini** kontrol edin ve bu durumda [**izinleri kontrol edin**](../../network-services-pentesting/pentesting-web/buckets/)**.**\
Ayrıca, bu noktada kapsamdaki tüm alan adlarını bildiğiniz için [**mümkün olan bucket adlarını kaba kuvvet uygulayın ve izinleri kontrol edin**](../../network-services-pentesting/pentesting-web/buckets/).

### **İzleme**

Bir alan adının **yeni alt alan adlarının** oluşturulup oluşturulmadığını **izleyebilirsiniz** [**Sertifika Şeffaflığı** Günlükleri](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) ile.

### **Zaafiyet Arayışı**

Mümkün [**alt alan adı ele geçirmelerini**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover) kontrol edin.\
Eğer **alt alan adı** bir **S3 bucket**'a işaret ediyorsa, [**izinleri kontrol edin**](../../network-services-pentesting/pentesting-web/buckets/).

Varlık keşfinde bulunduğunuz IP'lerden farklı bir IP'ye sahip **herhangi bir alt alan adı bulursanız**, temel bir zafiyet taraması yapmalısınız (Nessus veya OpenVAS kullanarak) ve **nmap/masscan/shodan** ile bazı [**port taraması**](../pentesting-network/#discovering-hosts-from-the-outside) yapmalısınız. Hangi hizmetlerin çalıştığına bağlı olarak, **bu kitapta onları "saldırmak" için bazı hileler bulabilirsiniz**.\
_Not: Bazen alt alan adı, müşteri tarafından kontrol edilmeyen bir IP içinde barındırılmış olabilir, bu nedenle kapsamda olmayabilir, dikkatli olun._

## IP'ler

Başlangıç adımlarında **bazı IP aralıkları, alan adları ve alt alan adları bulmuş olabilirsiniz**.\
Şimdi, bu aralıklardan **tüm IP'leri** ve **alan adları/alt alan adları (DNS sorguları)** toplama zamanı.

Aşağıdaki **ücretsiz api'lerden hizmetler kullanarak**, ayrıca **alan adları ve alt alan adları tarafından kullanılan önceki IP'leri** bulabilirsiniz. Bu IP'ler hala müşteriye ait olabilir (ve [**CloudFlare atlatmaları**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) bulmanıza izin verebilir)

* [**https://securitytrails.com/**](https://securitytrails.com/)

Ayrıca, [**hakip2host**](https://github.com/hakluke/hakip2host) aracını kullanarak belirli bir IP adresine işaret eden alan adlarını kontrol edebilirsiniz.

### **Zaafiyet Arayışı**

CDN'lere ait olmayan tüm IP'leri **port taraması yapın** (muhtemelen ilginç bir şey bulamayacaksınız). Keşfedilen çalışan hizmetlerde **zafiyetler bulabilirsiniz**.

**Ana bilgisayarları nasıl taramanız gerektiği** hakkında bir [**kılavuz**](../pentesting-network/) **bulun.**

## Web sunucuları avı

> Tüm şirketleri ve varlıklarını bulduk ve IP aralıklarını, alan adlarını ve kapsamdaki alt alan adlarını biliyoruz. Artık web sunucularını aramak zamanı geldi.

Önceki adımlarda muhtemelen keşfedilen IP'lerin ve alan adlarının keşfini zaten yapmış olabilirsiniz, bu nedenle **muhtemelen tüm olası web sunucuları zaten bulmuş olabilirsiniz**. Ancak, bulamadıysanız, şimdi kapsam içindeki web sunucularını aramak için **hızlı ipuçları** göreceğiz.

Lütfen, bu **web uygulamaları keşfi için yönlendirilecektir**, bu nedenle **izin verildiği takdirde** **zafiyet** ve **port taraması** da yapmalısınız.

[**masscan ile ilişkili açık portları keşfetmek için hızlı bir yöntem burada bulunabilir**](../pentesting-network/#http-port-discovery).\
Başka bir dostça araç web sunucularını aramak için [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) ve [**httpx**](https://github.com/projectdiscovery/httpx). Sadece bir alan adları listesi geçirirsiniz ve 80 (http) ve 443 (https) bağlanmaya çalışır. Ayrıca, diğer portları denemek için belirtebilirsiniz:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Ekran Görüntüleri**

Artık kapsamdaki **tüm web sunucularını** keşfettiğinize göre (şirketin **IP'leri** ve tüm **alan adları** ve **alt alan adları** arasında) muhtemelen **nereden başlayacağınızı bilmiyorsunuzdur**. Bu yüzden, basit tutarak hepsinin ekran görüntülerini almaya başlayalım. **Ana sayfaya** bir göz atarak daha **savunmasız** olma ihtimali daha **yüksek** olan garip uç noktaları bulabilirsiniz.

Önerilen fikri gerçekleştirmek için [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) veya [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**'ı** kullanabilirsiniz.

Ayrıca, daha sonra tüm **ekran görüntülerini** çalıştırmak için [**eyeballer**](https://github.com/BishopFox/eyeballer)'ı kullanabilirsiniz, size **olası savunabilir içeriği** ve olmayanı söylemek için.

## Genel Bulut Varlıkları

Bir şirkete ait potansiyel bulut varlıklarını bulmak için o şirketi tanımlayan kelimeler listesiyle başlamalısınız. Örneğin, bir kripto şirketi için "kripto", "cüzdan", "dao", "<alan_adı>", <"altalan_adılar"> gibi kelimeler kullanabilirsiniz.

Ayrıca, **kova**'larda kullanılan yaygın kelimelerin listelerine ihtiyacınız olacak:

* [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
* [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
* [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Sonra, bu kelimelerle **permutasyonlar** oluşturmalısınız (daha fazla bilgi için [**İkinci Tur DNS Kaba Kuvvet**](./#second-dns-bruteforce-round)'a bakın).

Elde edilen kelime listeleriyle [**cloud\_enum**](https://github.com/initstring/cloud\_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **veya** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**'ı** gibi araçları kullanabilirsiniz.

Bulut Varlıkları ararken **AWS**'deki kovalardan daha fazlasını aramalısınız.

### **Savunabilirlik Arayışı**

**Açık kovalar veya açığa çıkarılan bulut fonksiyonları** gibi şeyler bulursanız, onlara **erişmeli** ve size ne sunduklarını ve bunları kötüye kullanıp kullanamayacağınızı görmelisiniz.

## E-postalar

Kapsamdaki **alan adları** ve **alt alan adları** ile temelde e-posta aramaya başlamak için ihtiyacınız olan her şeye sahipsiniz. Bir şirketin e-postalarını bulmak için en iyi çalışan **API'ler** ve **araçlar** şunlardır:

* [**theHarvester**](https://github.com/laramies/theHarvester) - API'lerle
* [**https://hunter.io/**](https://hunter.io/) (ücretsiz sürüm) API'si
* [**https://app.snov.io/**](https://app.snov.io/) (ücretsiz sürüm) API'si
* [**https://minelead.io/**](https://minelead.io/) (ücretsiz sürüm) API'si

### **Savunabilirlik Arayışı**

E-postalar daha sonra **web girişlerini ve kimlik doğrulama hizmetlerini kaba kuvvet uygulamak** (örneğin SSH gibi) ve **spear phishing** için gereklidir. Ayrıca, bu API'lar size e-posta arkasındaki kişi hakkında daha fazla **bilgi verecektir**, bu da phishing kampanyası için faydalıdır.

## Kimlik Bilgisi Sızıntıları

**Alan adları**, **alt alan adları** ve **e-postalar** ile o e-postalara ait geçmişte sızdırılan kimlik bilgilerini aramaya başlayabilirsiniz:

* [https://leak-lookup.com](https://leak-lookup.com/account/login)
* [https://www.dehashed.com/](https://www.dehashed.com/)

### **Savunabilirlik Arayışı**

Eğer **geçerli sızdırılmış** kimlik bilgileri bulursanız, bu çok kolay bir kazançtır.

## Sırların Sızıntıları

Kimlik bilgisi sızıntıları, **duyarlı bilgilerin sızdırıldığı ve satıldığı** şirketlerin hack'leri ile ilgilidir. Ancak, şirketler, o veritabanlarında olmayan başka sızıntılardan da etkilenebilir:

### Github Sızıntıları

Kimlik bilgileri ve API'lar **şirketin** veya o github şirketinde çalışan **kullanıcıların** **genel depolarında** sızdırılmış olabilir.\
[**Leakos**](https://github.com/carlospolop/Leakos) aracını kullanarak bir **kuruluşun** ve **geliştiricilerinin** tüm **genel depolarını indirip** otomatik olarak üzerlerinde [**gitleaks**](https://github.com/zricethezav/gitleaks) çalıştırabilirsiniz.

**Leakos**, bazen **web sayfaları da sırlar içerebildiği için** tüm **URL'leri** üzerinden **gitleaks** çalıştırmak için de kullanılabilir.

#### Github Dorks

Saldırganlar veya sadece çalışanlar bazen **şirket içeriğini bir yapıştırma sitesinde yayınlar**. Bu **duyarlı bilgileri** içerebilir veya içermeyebilir, ancak aramak çok ilginçtir.\
[**Pastos**](https://github.com/carlospolop/Pastos) aracını aynı anda 80'den fazla yapıştırma sitesinde aramak için kullanabilirsiniz.

### Google Dorks

Eski ama altın google dorks'lar her zaman **orada olmamaları gereken bilgileri bulmak** için kullanışlıdır. Tek sorun, [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database)'in çalıştıramayacağınız birkaç bin olası sorgu içermesidir. Bu yüzden favori 10 tanesini alabilir veya hepsini çalıştırmak için [**Gorks**](https://github.com/carlospolop/Gorks) gibi bir **araç kullanabilirsiniz**.

_Regular Google tarayıcısını kullanarak tüm veritabanını çalıştırmayı bekleyen araçlar çok kısa sürede engellenecektir._

### **Savunabilirlik Arayışı**

Eğer **geçerli sızdırılmış** kimlik bilgileri veya API belirteçleri bulursanız, bu çok kolay bir kazançtır.

## Genel Kod Savunabilirlikleri

Şirketin **açık kaynak kodu** olduğunu tespit ettiyseniz, onu **analiz edebilir** ve üzerinde **savunabilirlikler** arayabilirsiniz.

**Dile bağlı olarak** farklı **araçlar** kullanabilirsiniz:

{% content-ref url="../../network-services-pentesting/pentesting-web/code-review-tools.md" %}
[code-review-tools.md](../../network-services-pentesting/pentesting-web/code-review-tools.md)
{% endcontent-ref %}

Ayrıca, şunun gibi ücretsiz hizmetlerle **genel depoları tarayabilirsiniz**:

* [**Snyk**](https://app.snyk.io/)
## [**Web Uygulama Test Metodolojisi**](../../network-services-pentesting/pentesting-web/)

**Hata avcıları** tarafından bulunan **çoğu zayıflık**, genellikle **web uygulamalarında** bulunur, bu nedenle bu noktada bir **web uygulama test metodolojisi** hakkında konuşmak istiyorum ve [**bu bilgiyi burada bulabilirsiniz**](../../network-services-pentesting/pentesting-web/).

Ayrıca, [**Web Otomatik Tarama Açık Kaynaklı Araçlar**](../../network-services-pentesting/pentesting-web/#automatic-scanners) bölümüne özel bir vurgu yapmak istiyorum, çünkü çok hassas zayıflıkları bulmalarını beklememelisiniz, ancak **bazı başlangıç web bilgilerini elde etmek için iş akışlarına uygulamak için faydalıdırlar.**

## Özet

> Tebrikler! Bu noktada zaten **tüm temel numaralandırmayı** gerçekleştirdiniz. Evet, temel çünkü daha fazla numaralandırma yapılabilir (daha sonra daha fazla hile göreceğiz).

Şimdiye kadar şunları yaptınız:

1. Kapsam içindeki **tüm şirketleri** buldunuz
2. Şirketlere ait **tüm varlıkları** buldunuz (ve kapsam içindeyse bazı zayıflık taraması yaptınız)
3. Şirketlere ait **tüm alan adlarını** buldunuz
4. Alan adlarına ait **tüm alt alan adlarını** buldunuz (herhangi bir alt alan adı ele geçirme?)
5. Kapsam içindeki **CDN'lerden ve olmayan IP'leri** buldunuz.
6. **Web sunucularını** buldunuz ve onların **ekran görüntüsünü** aldınız (derinlemesine bakmaya değer garip bir şey var mı?)
7. Şirkete ait **potansiyel halka açık bulut varlıklarını** buldunuz.
8. Size **kolayca büyük bir kazanç sağlayabilecek** **e-postaları**, **kimlik bilgileri sızıntılarını** ve **gizli sızıntıları** buldunuz.
9. Bulduğunuz tüm web sitelerini **pentest ettiniz**

## **Tam Kapsamlı Otomatik Araçlar**

Belirli bir kapsam için önerilen eylemlerin bir kısmını gerçekleştirecek birçok araç mevcuttur.

* [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
* [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
* [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
* [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Biraz eski ve güncellenmemiş

## **Referanslar**

* [**@Jhaddix**](https://twitter.com/Jhaddix)'in tüm ücretsiz kurslarına göz atın, örneğin [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)

<figure><img src="../../.gitbook/assets/image (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Eğer **hacking kariyeri**ne ilgi duyuyorsanız ve hacklenemez olanı hacklemek istiyorsanız - **işe alıyoruz!** (_akıcı şekilde yazılı ve konuşulan Lehçe gereklidir_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek veya HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 **Discord grubuna** katılın (https://discord.gg/hRep4RUj7f) veya **telegram grubuna** (https://t.me/peass) veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'da takip edin.**
* **Hacking hilelerinizi paylaşarak PR'ler göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına destek olun.

</details>
