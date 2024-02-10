# Harici Keşif Metodolojisi

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya bizi **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**'da takip edin**.
* Hacking hilelerinizi göndererek HackTricks ve HackTricks Cloud github depolarına **PR göndererek** hilelerinizi paylaşın.

</details>

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**Bounty ipucu**: **Hackerlar tarafından oluşturulan premium bir ödül avı platformu olan Intigriti'ye** kaydolun! Bugün [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) adresinde bize katılın ve **100.000 $'a kadar ödüller kazanmaya başlayın**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Varlıkların Keşfi

> Yani, size bir şirkete ait her şeyin kapsamda olduğu söylendi ve bu şirketin gerçekte neye sahip olduğunu bulmak istiyorsunuz.

Bu aşamanın amacı, **ana şirkete ait olan tüm şirketleri** ve ardından bu şirketlerin **varlıklarını** elde etmektir. Bunun için şunları yapacağız:

1. Ana şirketin satın almalarını bulmak, bu bize kapsam içindeki şirketleri verecektir.
2. Her şirketin ASN'sini (varsa) bulmak, bu bize her şirketin sahip olduğu IP aralıklarını verecektir.
3. İlkine ilişkin diğer girişleri (kuruluş adları, alan adları vb.) aramak için ters whois aramalarını kullanmak (bu rekürsif olarak yapılabilir).
4. Shodan `org` ve `ssl` filtreleri gibi diğer teknikleri kullanarak diğer varlıkları aramak (`ssl` hilesi rekürsif olarak yapılabilir).

### **Satın Alımlar**

İlk olarak, **ana şirket tarafından satın alınan diğer şirketleri** bilmemiz gerekiyor.\
Bir seçenek, [https://www.crunchbase.com/](https://www.crunchbase.com) adresini ziyaret etmek, **ana şirketi aramak** ve "**satın almalar**" üzerine **tıklamak**. Orada ana şirket tarafından satın alınan diğer şirketleri göreceksiniz.\
Diğer bir seçenek, ana şirketin **Wikipedia** sayfasını ziyaret etmek ve **satın almaları** aramaktır.

> Tamam, bu noktada kapsam içindeki tüm şirketleri bilmelisiniz. Şimdi varlıklarını nasıl bulacağımızı görelim.

### **ASN'ler**

Bir otonom sistem numarası (**ASN**), **Internet Assigned Numbers Authority (IANA)** tarafından bir **otonom sistem** (AS) için atanan **benzersiz bir numaradır**.\
Bir **AS**, harici ağlara erişim için belirli bir tanımlanmış politikaya sahip **IP adresi bloklarından** oluşur ve tek bir kuruluş tarafından yönetilir, ancak birkaç operatörden oluşabilir.

Şirketin **herhangi bir ASN atayıp atamadığını** bulmak, **IP aralıklarını** bulmak için ilginç olacaktır. Kapsam içindeki **tüm ana bilgisayarlara karşı bir zafiyet testi** yapmak ve bu IP'lerin içindeki **alan adlarını** aramak ilginç olacaktır.\
[**https://bgp.he.net/**](https://bgp.he.net)**'te** şirket **adı**, **IP** veya **alan adı** ile **arama** yapabilirsiniz.\
**Şirketin bölgesine bağlı olarak bu bağlantılar daha fazla veri toplamak için faydalı olabilir:** [**AFRINIC**](https://www.afrinic.net) **(Afrika),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Kuzey Amerika),** [**APNIC**](https://www.apnic.net) **(Asya),** [**LACNIC**](https://www.lacnic.net) **(Latin Amerika),** [**RIPE NCC**](https://www.ripe.net) **(Avrupa). Her durumda,** kullanışlı bilgiler **(IP aralıkları ve Whois)** zaten ilk bağlantıda görünür.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Ayrıca, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'un** alt alan taraması otomatik olarak ASN'leri taramanın sonunda bir araya getirir ve özetler.
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
Bir kuruluşun IP aralıklarını [http://asnlookup.com/](http://asnlookup.com) (ücretsiz API'ye sahiptir) kullanarak bulabilirsiniz.\
Bir alanın IP ve ASN'sini [http://ipv4info.com/](http://ipv4info.com) kullanarak bulabilirsiniz.

### **Zaafiyetleri arama**

Bu noktada, **kapsam içindeki tüm varlıkları biliyoruz**, bu yüzden izin veriliyorsa tüm ana bilgisayarlarda bir **zafiyet taraması** (Nessus, OpenVAS) başlatabilirsiniz.\
Ayrıca, bazı [**port taramaları**](../pentesting-network/#discovering-hosts-from-the-outside) başlatabilir veya shodan gibi hizmetleri kullanarak açık portları bulabilir ve bulduğunuz şeylere bağlı olarak bu kitapta nasıl birkaç olası hizmeti pentest edeceğinizi inceleyebilirsiniz.\
**Ayrıca, varsayılan kullanıcı adı** ve **parola** listeleri hazırlayabilir ve [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) ile hizmetleri brute force yöntemiyle deneyebilirsiniz.

## Alanlar

> Kapsam içindeki tüm şirketleri ve varlıklarını biliyoruz, şimdi kapsam içindeki alanları bulma zamanı.

_Lütfen, aşağıdaki önerilen tekniklerde alt alanlar da bulabileceğinizi ve bu bilginin küçümsenmemesi gerektiğini unutmayın._

Öncelikle, her şirketin **ana alan adını** bulmalısınız. Örneğin, _Tesla Inc._ için _tesla.com_ olacaktır.

### **Ters DNS**

Alanların IP aralıklarını bulduğunuzda, bu IP'ler üzerinde **ters dns sorguları** yaparak kapsam içinde daha fazla alan bulmaya çalışabilirsiniz. Kurbanın bir DNS sunucusunu veya bilinen bir DNS sunucusunu (1.1.1.1, 8.8.8.8) kullanmaya çalışın.
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Bu işin çalışması için yöneticinin PTR'yi manuel olarak etkinleştirmesi gerekmektedir.\
Bu bilgileri almak için çevrimiçi bir araç da kullanabilirsiniz: [http://ptrarchive.com/](http://ptrarchive.com)

### **Ters Whois (döngü)**

Bir **whois** içinde, **organizasyon adı**, **adres**, **e-postalar**, telefon numaraları gibi birçok ilginç **bilgi** bulabilirsiniz... Ancak daha da ilginç olan şey, bu alanlardan herhangi biriyle **ters whois aramaları yaparak şirketle ilgili daha fazla varlık bulabileceğinizdir** (örneğin aynı e-postanın göründüğü diğer whois kayıtları).\
Aşağıdaki gibi çevrimiçi araçları kullanabilirsiniz:

* [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Ücretsiz**
* [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Ücretsiz**
* [https://www.reversewhois.io/](https://www.reversewhois.io) - **Ücretsiz**
* [https://www.whoxy.com/](https://www.whoxy.com) - **Ücretsiz** web, ücretsiz API değil.
* [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Ücretsiz değil
* [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Ücretsiz değil (sadece **100 ücretsiz** arama)
* [https://www.domainiq.com/](https://www.domainiq.com) - Ücretsiz değil

Bu görevi [**DomLink** ](https://github.com/vysecurity/DomLink)(whoxy API anahtarı gerektirir) kullanarak otomatikleştirebilirsiniz.\
Ayrıca [amass](https://github.com/OWASP/Amass) ile bazı otomatik ters whois keşifleri yapabilirsiniz: `amass intel -d tesla.com -whois`

**Bu teknikle her yeni alan adı bulduğunuzda daha fazla alan adı keşfedebilirsiniz.**

### **İzleyiciler**

Aynı izleyicinin **aynı kimliğini** 2 farklı sayfada bulursanız, **her iki sayfanın da aynı ekibin yönettiğini** varsayabilirsiniz.\
Örneğin, birkaç sayfada aynı **Google Analytics Kimliği** veya aynı **Adsense Kimliği**'ni görürseniz.

Bu izleyiciler ve daha fazlasıyla arama yapmanıza izin veren bazı sayfalar ve araçlar vardır:

* [**Udon**](https://github.com/dhn/udon)
* [**BuiltWith**](https://builtwith.com)
* [**Sitesleuth**](https://www.sitesleuth.io)
* [**Publicwww**](https://publicwww.com)
* [**SpyOnWeb**](http://spyonweb.com)

### **Favicon**

Hedefimize ait ilgili alan adlarını ve alt alan adlarını aynı favicon simgesi karmasını arayarak bulabileceğimizi biliyor muydunuz? İşte [@m4ll0k2](https://twitter.com/m4ll0k2) tarafından yapılan [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) aracı tam olarak bunu yapar. İşte nasıl kullanılır:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - Aynı favicon simge karmasına sahip alan adlarını keşfedin](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Basitçe söylemek gerekirse, favihash hedefimizle aynı favicon simge karmasına sahip alan adlarını keşfetmemizi sağlayacaktır.

Ayrıca, favicon karmasını kullanarak teknolojileri arayabilirsiniz, [**bu blog yazısında**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139) açıklandığı gibi. Bu, zayıf bir web teknolojisinin karmasını biliyorsanız, shodan'da arama yaparak **daha fazla zayıf nokta bulabileceğiniz** anlamına gelir:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
Bu, bir web sitesinin **favicon hash'ini hesaplamanın** nasıl yapıldığını gösterir:

1. İlk adım olarak, hedef web sitesinin favicon.ico dosyasını bulmanız gerekmektedir. Bu dosya genellikle web sitesinin kök dizininde bulunur.

2. Favicon.ico dosyasını indirin ve bir metin düzenleyici ile açın.

3. Dosyanın içeriğini bir dize olarak kopyalayın.

4. Kopyaladığınız dizeyi bir hash fonksiyonuna (örneğin, MD5 veya SHA-1) geçirin. Bu, dizenin benzersiz bir kriptografik özetini oluşturacaktır.

5. Elde ettiğiniz hash değerini kaydedin. Bu, favicon'un hash değeri olacaktır.

Favicon hash değeri, web sitesinin favicon'unun benzersiz bir tanımlayıcısıdır. Bu değeri kullanarak, web sitesinin favicon'unun değişip değişmediğini veya başka bir web sitesiyle paylaşılıp paylaşılmadığını kontrol edebilirsiniz.
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

Aynı kuruluş içinde farklı web siteleri arasında paylaşılabilecek **dizeleri** web sayfalarında arayın. **Telif hakkı dizesi** iyi bir örnek olabilir. Ardından bu dizeyi **Google**, diğer **tarayıcılarda** veya hatta **shodan**'da arayın: `shodan search http.html:"Telif hakkı dizesi"`

### **CRT Zamanı**

Genellikle bir cron işi gibi bir şeye sahip olmak yaygındır.
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
Sunucudaki tüm alan adı sertifikalarını yenilemek için aşağıdaki adımları izleyebilirsiniz. Bu, bu iş için kullanılan CA'nın Geçerlilik süresinde oluşturulma zamanını belirlemediği anlamına gelse bile, **sertifika şeffaflık günlüklerinde aynı şirkete ait alan adlarını bulmak mümkündür**.\
Daha fazla bilgi için [**bu yazıya**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/) göz atabilirsiniz.

### **Pasif Ele Geçirme**

Görünüşe göre insanlar, alt alan adlarını bulut sağlayıcılarına ait IP'lere atamakta ve bu IP adresini bir noktada **kaybetmekte, ancak DNS kaydını kaldırmayı unutmaktadır**. Bu nedenle, sadece bir bulutta (örneğin Digital Ocean gibi) bir sanal makine oluşturarak, aslında bazı alt alan adlarını **ele geçirebilirsiniz**.

[**Bu yazı**](https://kmsec.uk/blog/passive-takeover/) bununla ilgili bir hikayeyi açıklıyor ve bir script öneriyor. Bu script, **DigitalOcean'da bir sanal makine oluşturur**, yeni makinenin **IPv4**'ünü alır ve ona işaret eden alt alan adı kayıtlarını Virustotal'de arar.

### **Diğer Yollar**

**Not: Bu teknikle her yeni alan adı bulduğunuzda daha fazla alan adı keşfedebilirsiniz.**

**Shodan**

IP alanına sahip olan kuruluşun adını zaten biliyorsunuz. Bu veriyi kullanarak shodan'da arama yapabilirsiniz: `org:"Tesla, Inc."` Bulunan ana bilgisayarlarda TLS sertifikasında yeni beklenmeyen alan adlarını kontrol edin.

Ana web sayfasının **TLS sertifikasına** erişebilir, **Kuruluş adını** alabilir ve ardından **shodan** tarafından bilinen tüm web sayfalarının **TLS sertifikalarında** bu adı arayabilirsiniz. Filtre olarak şunu kullanabilirsiniz: `ssl:"Tesla Motors"` veya [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) gibi bir araç kullanabilirsiniz.

**Assetfinder**

[**Assetfinder**](https://github.com/tomnomnom/assetfinder), ana bir alan adıyla ilişkili **alan adlarını** ve bunların **alt alan adlarını** arayan bir araçtır, oldukça etkileyici.

### **Zaafiyetleri Arama**

[Alan ele geçirme](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover) için kontrol edin. Belki bir şirket **bir alan adı kullanıyor** ancak **sahipliğini kaybetmiş**. Eğer uygunsa kaydedin ve şirkete bildirin.

Varlık keşfi sırasında bulunan varlıklardan farklı bir IP'ye sahip olan herhangi bir **alan adını** bulursanız, temel bir zafiyet taraması (Nessus veya OpenVAS kullanarak) ve **nmap/masscan/shodan** ile bazı [**port taramaları**](../pentesting-network/#discovering-hosts-from-the-outside) yapmalısınız. Hangi hizmetlerin çalıştığına bağlı olarak, **bu kitapta onları "saldırmak" için bazı hileler bulabilirsiniz**.\
_Unutmayın, bazen alan adı, müşteri tarafından kontrol edilmeyen bir IP içinde barındırıldığından, kapsamda değildir, dikkatli olun._

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**Bug bounty ipucu**: **Intigriti'ye kaydolun**, hackerlar tarafından oluşturulan bir premium **bug bounty platformu**! Bugün [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) adresinde bize katılın ve **100.000 $'a kadar ödüller kazanmaya başlayın**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Alt Alan Adları

> Kapsam dahilindeki tüm şirketleri, her şirketin varlıklarını ve şirketlerle ilgili tüm alan adlarını biliyoruz.

Her bulunan alan adının tüm olası alt alan adlarını bulmak için aşağıdaki adımları izleyebilirsiniz.

### **DNS**

**DNS** kayıtlarından **alt alan adlarını** almaya çalışalım. Ayrıca **Zone Transfer** için de denemeliyiz (Eğer zayıfsa, bunu bildirmelisiniz).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Birçok alt alan adını hızlı bir şekilde elde etmenin en hızlı yolu, harici kaynaklarda arama yapmaktır. En çok kullanılan **araçlar** aşağıdakilerdir (daha iyi sonuçlar için API anahtarlarını yapılandırın):

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
* [**OneForAll**](https://github.com/shmilylty/OneForAll/tree/master/docs/tr-tr)
```bash
python3 oneforall.py --target tesla.com [--dns False] [--req False] [--brute False] run
```
* [**assetfinder**](https://github.com/tomnomnom/assetfinder)

Bu araç, bir hedef alan adı için alt alanları bulmak için kullanılır.
```bash
assetfinder --subs-only <domain>
```
* [**Sudomy**](https://github.com/Screetsec/Sudomy)

Sudomy, bir hedefin dış keşif aşamasında kullanılan bir araçtır. Bu araç, hedefin alan adı, IP adresi veya ASN numarası gibi bilgilerini kullanarak, hedef hakkında çeşitli bilgiler toplar. Sudomy, alt alan adları, IP adresleri, açık portlar, servisler ve daha fazlası gibi bilgileri keşfetmek için çeşitli kaynakları taramak için kullanılır. Bu bilgiler, hedefin saldırı yüzeyini belirlemek ve zayıf noktalarını tespit etmek için kullanılabilir. Sudomy, harici keşif metodolojisi sırasında kullanılan bir araçtır ve hedef hakkında daha fazla bilgi edinmek için etkili bir seçenektir.
```bash
# It requires that you create a sudomy.api file with API keys
sudomy -d tesla.com
```
* [**vita**](https://github.com/junnlikestea/vita)
```
vita -d tesla.com
```
* [**theHarvester**](https://github.com/laramies/theHarvester)

theHarvester, bir dış kaynak keşif aracıdır. Açık kaynaklıdır ve Python ile yazılmıştır. Bu araç, hedefle ilgili bilgileri toplamak için çeşitli kaynakları sorgular. Bu kaynaklar arasında arama motorları, DNS veritabanları, sızıntılar ve sosyal medya platformları bulunur. theHarvester, hedef hakkında genel bir görüntü sağlamak için kullanılabilir ve hedefe yönelik saldırılar için önemli bir bilgi kaynağı olabilir.
```bash
theHarvester -d tesla.com -b "anubis, baidu, bing, binaryedge, bingapi, bufferoverun, censys, certspotter, crtsh, dnsdumpster, duckduckgo, fullhunt, github-code, google, hackertarget, hunter, intelx, linkedin, linkedin_links, n45ht, omnisint, otx, pentesttools, projectdiscovery, qwant, rapiddns, rocketreach, securityTrails, spyse, sublist3r, threatcrowd, threatminer, trello, twitter, urlscan, virustotal, yahoo, zoomeye"
```
Aşağıda, alt alan adlarını bulmak için doğrudan uzmanlaşmamış olsa da, alt alan adlarını bulmak için yararlı olabilecek **diğer ilginç araçlar/API'ler** bulunmaktadır:

* [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Alt alan adlarını elde etmek için [https://sonar.omnisint.io](https://sonar.omnisint.io) API'sini kullanır.
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
* [**gau**](https://github.com/lc/gau)**:** AlienVault'un Açık Tehdit Değişiminden, Wayback Machine'den ve Common Crawl'dan bilinen URL'leri alır.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
* [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Web'i tarayarak JS dosyalarını arar ve oradan alt alan adlarını çıkarır.
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
* [**Censys alt alan adı bulucusu**](https://github.com/christophetd/censys-subdomain-finder)
```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```
* [**DomainTrail.py**](https://github.com/gatete/DomainTrail)
```bash
python3 DomainTrail.py -d example.com
```
* [**securitytrails.com**](https://securitytrails.com/) ücretsiz bir API sunar ve alt alan adlarını ve IP geçmişini aramanıza olanak sağlar.
* [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/) Bu proje, **bug-bounty programlarıyla ilgili tüm alt alan adlarını ücretsiz olarak sunar**. Bu verilere [chaospy](https://github.com/dr-0x0x/chaospy) kullanarak veya bu projenin kullandığı kapsamı [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list) adresinden erişebilirsiniz.

Bu araçların bir **karşılaştırmasını** burada bulabilirsiniz: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Mümkün olan alt alan adı isimlerini kullanarak DNS sunucularını brute-force yaparak yeni **alt alan adları** bulmaya çalışalım.

Bu işlem için aşağıdaki gibi bazı **ortak alt alan adı kelime listelerine** ihtiyacınız olacak:

* [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
* [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
* [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
* [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
* [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Ayrıca iyi DNS çözücülerinin IP'lerine de ihtiyacınız olacak. Güvenilir DNS çözücülerinin bir listesini oluşturmak için [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) adresinden çözücüleri indirebilir ve bunları filtrelemek için [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) kullanabilirsiniz. Veya [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt) adresini kullanabilirsiniz.

DNS brute-force için en çok önerilen araçlar:

* [**massdns**](https://github.com/blechschmidt/massdns): Bu, etkili bir DNS brute-force gerçekleştiren ilk araçtır. Çok hızlıdır, ancak yanlış pozitiflere eğilimlidir.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
* [**gobuster**](https://github.com/OJ/gobuster): Bunu sadece 1 çözücü kullanıyor gibi düşünüyorum.
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
* [**shuffledns**](https://github.com/projectdiscovery/shuffledns), go ile yazılmış `massdns` etrafında bir sarmalayıcıdır. Aktif bruteforce kullanarak geçerli alt alanları numaralandırmanıza, joker karakterleriyle başa çıkmanıza ve kolay giriş-çıkış desteği sağlamanıza olanak tanır.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
* [**puredns**](https://github.com/d3mondev/puredns): Ayrıca `massdns` kullanır.
```
puredns bruteforce all.txt domain.com
```
* [**aiodnsbrute**](https://github.com/blark/aiodnsbrute), asyncio kullanarak alan adlarını asenkron olarak brute force yapmak için kullanılır.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### İkinci DNS Brute-Force Turu

Açık kaynakları ve brute-force yöntemini kullanarak alt alan adlarını bulduktan sonra, bulunan alt alan adlarının değişikliklerini oluşturarak daha fazlasını bulmaya çalışabilirsiniz. Bu amaçla birkaç araç kullanışlıdır:

* [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Alan adları ve alt alan adları verildiğinde permutasyonlar oluşturur.
```bash
cat subdomains.txt | dnsgen -
```
* [**goaltdns**](https://github.com/subfinder/goaltdns): Alan adları ve alt alan adları verildiğinde permutasyonlar oluşturur.
* goaltdns permutasyonları için **wordlist**'i [**buradan**](https://github.com/subfinder/goaltdns/blob/master/words.txt) alabilirsiniz.
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
* [**gotator**](https://github.com/Josue87/gotator)**:** Alan adları ve alt alan adları verildiğinde permutasyonlar oluşturur. Eğer permutasyon dosyası belirtilmezse, gotator kendi dosyasını kullanır.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
* [**altdns**](https://github.com/infosec-au/altdns): Alt alan adı permütasyonları oluşturmanın yanı sıra, bunları çözmeye de çalışabilir (ancak önceki yorumlanan araçları kullanmak daha iyidir).
* altdns permütasyonları **wordlist**'ini [**buradan**](https://github.com/infosec-au/altdns/blob/master/words.txt) alabilirsiniz.
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
* [**dmut**](https://github.com/bp0lr/dmut): Alt alan adlarının permutasyonlarını, mutasyonlarını ve değişikliklerini gerçekleştirmek için başka bir araç. Bu araç sonucu brute force yöntemiyle bulmaktadır (dns wild card desteklememektedir).
* dmut permutasyonları kelime listesini [**buradan**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt) alabilirsiniz.
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
* [**alterx**](https://github.com/projectdiscovery/alterx)**:** Bir alan adına dayanarak, daha fazla alt alan adı keşfetmek için belirtilen desenlere dayalı olarak yeni potansiyel alt alan adı adları oluşturur.

#### Akıllı permütasyon üretimi

* [**regulator**](https://github.com/cramppet/regulator): Daha fazla bilgi için bu [**gönderiyi**](https://cramppet.github.io/regulator/index.html) okuyun, ancak temel olarak **keşfedilen alt alan adlarının** ana bölümlerini alacak ve daha fazla alt alan adı bulmak için karıştıracaktır.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
* [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_, bir alt alan brute-force fuzzer'ıdır ve son derece basit ama etkili bir DNS yanıt rehberli algoritma ile birleştirilmiştir. Özel bir kelime listesi veya geçmiş DNS/TLS kayıtları gibi sağlanan bir giriş veri kümesini kullanarak, DNS taraması sırasında toplanan bilgilere dayanarak daha fazla ilgili alan adını doğru bir şekilde sentezlemek ve bunları daha da genişletmek için bir döngüde kullanır.
```
echo www | subzuf facebook.com
```
### **Alt Alan Adı Keşfi İş Akışı**

Bilgisayarımda manuel olarak bir dizi aracı başlatmam gerekmeyeceği için, bir alan adından **alt alan adı keşfini otomatikleştirmenin** nasıl yapıldığını anlatan bu blog yazısına göz atın:

{% embed url="https://trickest.com/blog/full-subdomain-discovery-using-workflow/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

{% embed url="https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### **VHosts / Sanal Sunucular**

Eğer bir IP adresi içinde **bir veya birkaç alt alan adına ait web sayfaları** bulduysanız, bu IP içinde **diğer alt alan adlarını bulmaya çalışabilirsiniz**. Bunun için, bir IP içindeki alan adlarını **OSINT kaynaklarında** arayarak veya **VHost alan adlarını brute force yöntemiyle** bulabilirsiniz.

#### OSINT

[**HostHunter**](https://github.com/SpiderLabs/HostHunter) **veya diğer API'ler** kullanarak bazı **IP'lerdeki VHost'ları** bulabilirsiniz.

**Brute Force**

Eğer bir alt alan adının bir web sunucusunda gizli olabileceğinden şüpheleniyorsanız, brute force yöntemiyle deneyebilirsiniz:
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
Bu teknikle, hatta dahili/gizli uç noktalara bile erişebilirsiniz.
{% endhint %}

### **CORS Brute Force**

Bazen, yalnızca geçerli bir alan/ad alanı _**Origin**_ başlığında ayarlandığında _**Access-Control-Allow-Origin**_ başlığını döndüren sayfalar bulabilirsiniz. Bu senaryolarda, bu davranışı istismar ederek yeni **alt alanlar** keşfedebilirsiniz.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Bucket Kaba Kuvvet**

**Alt alan adları** ararken, herhangi bir türde **bucket**a işaret edip etmediğini görmek için dikkatli olun ve bu durumda [**izinleri kontrol edin**](../../network-services-pentesting/pentesting-web/buckets/)**.**\
Ayrıca, bu noktada kapsam içindeki tüm alan adlarını bildiğiniz için, [**mümkün olan bucket isimlerini kaba kuvvet uygulayın ve izinleri kontrol edin**](../../network-services-pentesting/pentesting-web/buckets/).

### **İzleme**

Bir alan adının **yeni alt alan adları** oluşturulup oluşturulmadığını **Sertifika Şeffaflığı** Günlüklerini izleyerek **izleyebilirsiniz**. [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)bu işlemi yapar.

### **Zaafiyet Arayışı**

Mümkün olan [**alt alan adı ele geçirmelerini**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover) kontrol edin.\
Eğer **alt alan adı** bir **S3 bucket**a işaret ediyorsa, [**izinleri kontrol edin**](../../network-services-pentesting/pentesting-web/buckets/).

Eğer var olan varlık keşfinde bulduğunuz IP'lerden farklı bir IP'ye sahip bir **alt alan adı** bulursanız, temel bir zafiyet taraması (Nessus veya OpenVAS kullanarak) ve **nmap/masscan/shodan** ile bazı [**port taraması**](../pentesting-network/#discovering-hosts-from-the-outside) yapmalısınız. Hangi hizmetlerin çalıştığına bağlı olarak, **bu kitapta onları "saldırmak" için bazı hileler bulabilirsiniz**.\
_Unutmayın ki bazen alt alan adı, müşteri tarafından kontrol edilmeyen bir IP içinde barındırılır, bu yüzden kapsamda değildir, dikkatli olun._

## IP'ler

İlk adımlarda **IP aralıkları, alan adları ve alt alan adları bulmuş olabilirsiniz**.\
Bu aralıklardan gelen **tüm IP'leri** ve **alan adları/alt alan adları (DNS sorguları)** için **tekrar toplamak zamanı geldi**.

Aşağıdaki **ücretsiz api hizmetlerini** kullanarak, ayrıca **alan adları ve alt alan adları tarafından kullanılan önceki IP'leri** bulabilirsiniz. Bu IP'ler hala müşteriye ait olabilir (ve size [**CloudFlare bypassları**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) bulma imkanı verebilir)

* [**https://securitytrails.com/**](https://securitytrails.com/)

Ayrıca, [**hakip2host**](https://github.com/hakluke/hakip2host) aracını kullanarak belirli bir IP adresine işaret eden alan adlarını kontrol edebilirsiniz.

### **Zaafiyet Arayışı**

CDN'ye ait olmayan tüm IP'leri (muhtemelen ilginç bir şey bulamayacağınız için) **port taraması** yapın. Keşfedilen çalışan hizmetlerde **zaafiyetler bulabilirsiniz**.

**Ana bilgisayarları tarama hakkında bir** [**rehber**](../pentesting-network/) **bulun.**

## Web sunucularının avlanması

> Tüm şirketleri ve varlıklarını bulduk ve IP aralıklarını, alan adlarını ve alt alan adlarını kapsam içinde biliyoruz. Şimdi web sunucularını aramak için zamanı geldi.

Önceki adımlarda muhtemelen keşfedilen IP'ler ve alan adlarının **keşfini zaten yapmış olabilirsiniz**, bu yüzden muhtemelen **tüm olası web sunucuları** zaten bulmuş olabilirsiniz. Ancak, yapmadıysanız, şimdi kapsam içindeki web sunucularını aramak için bazı **hızlı hilelere** bakacağız.

Lütfen, bunun **web uygulamalarının keşfi için yönlendirildiğini** unutmayın, bu yüzden kapsam tarafından **izin verildiği takdirde** **zaafiyet taraması** ve **port taraması** da yapmalısınız.

[**masscan** kullanarak** web** sunucularıyla ilgili **açık portları** keşfetmek için hızlı bir yöntem burada bulunabilir](../pentesting-network/#http-port-discovery).\
Web sunucularını aramak için başka bir kullanışlı araç [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) ve [**httpx**](https://github.com/projectdiscovery/httpx). Bir alan adı listesi geçirirsiniz ve 80 (http) ve 443 (https) bağlantı noktalarına bağlanmaya çalışır. Ek olarak, diğer bağlantı noktalarını denemek için belirtebilirsiniz:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Ekran Görüntüleri**

Kapsamda bulunan **tüm web sunucularını** (şirketin **IP'leri** ve tüm **alan adları** ve **alt alan adları**) keşfettiğinizde muhtemelen **nereden başlayacağınızı bilemezsiniz**. Bu yüzden, işi basit tutmak için hepsinin ekran görüntülerini alarak başlayalım. **Ana sayfaya** bir göz atarak, daha **savunmasız** olma olasılığı daha yüksek olan garip uç noktalar bulabilirsiniz.

Önerilen fikri gerçekleştirmek için [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/) veya [**webscreenshot**](https://github.com/maaaaz/webscreenshot) kullanabilirsiniz.

Ayrıca, daha sonra tüm **ekran görüntülerini** analiz etmek için [**eyeballer**](https://github.com/BishopFox/eyeballer) kullanabilirsiniz ve hangilerinin muhtemelen **savunmasızlıklar içerdiğini** ve hangilerinin içermediğini size söyleyebilir.

## Halka Açık Bulut Varlıkları

Bir şirkete ait potansiyel bulut varlıklarını bulmak için o şirketi tanımlayan **kelimelerin bir listesiyle başlamalısınız**. Örneğin, bir kripto şirketi için "crypto", "wallet", "dao", "<domain_name>", "<subdomain_names>" gibi kelimeleri kullanabilirsiniz.

Ayrıca, kovalarda kullanılan **ortak kelimelerin** wordlist'lerine ihtiyacınız olacak:

* [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
* [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
* [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Ardından, bu kelimelerle **permutasyonlar** oluşturmalısınız (daha fazla bilgi için [**İkinci Tur DNS Brute-Force**](./#second-dns-bruteforce-round) bölümüne bakın).

Elde edilen wordlist'lerle [**cloud\_enum**](https://github.com/initstring/cloud\_enum), [**CloudScraper**](https://github.com/jordanpotti/CloudScraper), [**cloudlist**](https://github.com/projectdiscovery/cloudlist) veya [**S3Scanner**](https://github.com/sa7mon/S3Scanner) gibi araçları kullanabilirsiniz.

Bulut Varlıklarını ararken, yalnızca AWS'deki kovalardan daha fazlasını aramalısınız.

### **Savunmasızlıkları Arama**

Açık kovalar veya açığa çıkarılan bulut işlevleri gibi şeyler bulursanız, bunlara **erişmeli** ve ne sunduklarını ve onları kötüye kullanıp kullanamayacağınızı görmeye çalışmalısınız.

## E-postalar

Kapsam içindeki **alan adları** ve **alt alan adları** ile birlikte şirketin e-postalarını aramaya başlamak için ihtiyacınız olan her şeye zaten sahipsiniz. Bir şirketin e-postalarını bulmak için en iyi çalışan **API'ler** ve **araçlar** bunlardır:

* [**theHarvester**](https://github.com/laramies/theHarvester) - API'lerle birlikte
* [**https://hunter.io/**](https://hunter.io/) (ücretsiz sürüm) API'si
* [**https://app.snov.io/**](https://app.snov.io/) (ücretsiz sürüm) API'si
* [**https://minelead.io/**](https://minelead.io/) (ücretsiz sürüm) API'si

### **Savunmasızlıkları Arama**

E-postalar daha sonra web oturum açma ve kimlik doğrulama hizmetlerini (SSH gibi) **brute-force** etmek için kullanışlı olacaktır. Ayrıca, **phishing** için gereklidir. Dahası, bu API'ler size e-postanın arkasındaki kişi hakkında daha fazla bilgi verecektir, bu da phishing kampanyası için kullanışlıdır.

## Kimlik Bilgisi Sızıntıları

**Alan adları**, **alt alan adları** ve **e-postalar** ile geçmişte sızdırılan bu e-postalara ait kimlik bilgilerini aramaya başlayabilirsiniz:

* [https://leak-lookup.com](https://leak-lookup.com/account/login)
* [https://www.dehashed.com/](https://www.dehashed.com/)

### **Savunmasızlıkları Arama**

Geçerli sızdırılmış kimlik bilgileri bulursanız, bu çok kolay bir kazançtır.

## Sızıntılar

Kimlik bilgisi sızıntıları, **hassas bilgilerin sızdırıldığı ve satıldığı** şirketlerin hack'lenmesiyle ilgilidir. Bununla birlikte, şirketler, bu veritabanlarında olmayan başka sızıntılardan da etkilenebilir:

### Github Sızıntıları

Kimlik bilgileri ve API'ler, **şirketin veya github şirketinde çalışan kullanıcıların** **genel depolarında** sızdırılabilir.\
[**Leakos**](https://github.com/carlospolop/Leakos) aracını kullanarak bir **kuruluşun** ve **geliştiricilerinin** tüm **genel depolarını** indirebilir ve otomatik olarak üzerlerinde [**gitleaks**](https://github.com/zricethezav/gitleaks) çalıştırabilirsiniz.

**Leakos**, bazen **web sayfaları da sırlar içerdiği için**, kendisine **URL'lerin geçirildiği tüm metinleri** çalıştırmak için de kullanılabilir.

#### Github Dorks

Saldırdığınız kuruluşta arayabileceğiniz potansiyel **github dorks** için bu **sayfayı** da kontrol edin:

{% content-ref url="github-leaked-secrets.md" %}
[github-leaked-secrets.md](github-leaked-secrets.md)
{% endcontent-ref %}

### Pastes Sızıntıları

Bazen saldırganlar veya sadece çalışanlar **şirket içeriğini bir yapıştırma sitesinde yayınlar**. Bu, **hassas bilgiler** içerebilir veya içermeyebilir, ancak aramak için çok ilginçtir.\
[**Pastos**](https://github.com/carlospolop/Pastos) aracını kullanarak aynı anda 80'den fazla yapıştırma sitesinde arama yapabilirsiniz.

### Google Dorks

Eski ama altın google dorks, **orada olmaması gereken açığa çıkarılmış bilgileri** bulmak için her zaman kullanışlıdır. Tek sorun, [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database)'in çalıştırmanız mümkün olmayan birkaç bin olası sorgu içermesidir. Bu yüzden en sevdiğiniz 10 tanesini alabilir veya hepsini çalıştırmak için [**Gorks**](https://github.com/carlospolop/Gorks) gibi bir araç kullanabilirsiniz.

_Unutmayın, düzenli Google tarayıcısını kullanarak tüm veritabanını çalıştırmayı bekleyen araçlar çok çok hızlı bir şekilde engellenecektir._

### **Savunmasızlıkları Arama**

Geçerli sızdırılmış kimlik bilgileri veya API tokenları bulursanız, bu çok kolay bir kazançtır.

## Halka Açık Kod Savunmasızlıkları

Şirketin **açık kaynak kodu** olduğunu tespit ettiyseniz, onu analiz edebilir ve üzerinde **savunmasızlıkları** arayabilirsiniz.

**Dile bağlı olarak** kullanabileceğiniz farklı **araçlar** vardır:

{% content-ref url="../../network-services-pentesting/pentesting-web/code-review-tools.md" %}
[code-review-tools.md](../../network-services-pentesting/pentesting-web/code-review-tools.md)
{% endcontent-ref %}

Ayrıca, [**Snyk**](https://app.snyk.io/) gibi ücretsiz hizmetlerle **genel depoları tarayabilirsiniz**.
## [**Web Pentesting Metodolojisi**](../../network-services-pentesting/pentesting-web/)

Bulucular tarafından bulunan **zayıflıkların çoğunluğu** web uygulamalarında bulunur, bu yüzden bu noktada bir **web uygulama test metodolojisi** hakkında konuşmak istiyorum ve bu bilgilere [**buradan ulaşabilirsiniz**](../../network-services-pentesting/pentesting-web/).

Ayrıca, [**Web Otomatik Tarama açık kaynaklı araçlar**](../../network-services-pentesting/pentesting-web/#automatic-scanners) bölümüne özel bir vurgu yapmak istiyorum, çünkü çok hassas zayıflıkları bulmalarını beklememelisiniz, ancak **bazı başlangıç web bilgilerini elde etmek için iş akışlarına yardımcı olurlar.**

## Özet

> Tebrikler! Bu noktada zaten **tüm temel numaralandırmayı** gerçekleştirdiniz. Evet, temel çünkü daha fazla numaralandırma yapılabilir (daha sonra daha fazla hile göreceğiz).

Şimdiye kadar şunları yaptınız:

1. Kapsam içindeki **şirketleri** buldunuz.
2. Şirketlere ait olan **varlıkları** buldunuz (ve kapsam içindeyse bazı zayıflık taramaları gerçekleştirdiniz).
3. Şirketlere ait olan **alan adlarını** buldunuz.
4. Alan adlarının **alt alan adlarını** buldunuz (herhangi bir alt alan adı ele geçirme durumu var mı?).
5. Kapsam içindeki **CDN'lerden ve CDN'lerden olmayan IP'leri** buldunuz.
6. **Web sunucularını** buldunuz ve onların bir **ekran görüntüsünü** aldınız (daha derinlemesine bir bakmaya değer garip bir şey var mı?).
7. Şirkete ait olan **potansiyel halka açık bulut varlıklarını** buldunuz.
8. Size **kolayca büyük bir kazanç sağlayabilecek** **e-postaları**, **kimlik bilgileri sızıntılarını** ve **gizli sızıntıları** buldunuz.
9. Bulduğunuz tüm web sitelerini **pentest ettiniz**.

## **Tam Kapsamlı Otomatik Araçlar**

Verilen bir kapsam için önerilen eylemlerin bir kısmını gerçekleştirecek birkaç araç bulunmaktadır.

* [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
* [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
* [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
* [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Biraz eski ve güncellenmemiş

## **Referanslar**

* [**@Jhaddix**](https://twitter.com/Jhaddix)'in tüm ücretsiz kursları, örneğin [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**Bug bounty ipucu**: Hackerlar tarafından oluşturulan bir premium **bug bounty platformu olan Intigriti'ye kaydolun**! Bugün [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) adresinde bize katılın ve **100.000 $'a kadar ödüller kazanmaya başlayın**!

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **tanıtmak veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya bizi **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**'da takip edin**.
* Hacking hilelerinizi **HackTricks** ve **HackTricks Cloud** github depolarına PR göndererek paylaşın.

</details>
