# macOS Ağ Hizmetleri ve Protokolleri

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* Hacking hilelerinizi **HackTricks** ve **HackTricks Cloud** github depolarına PR göndererek paylaşın.

</details>

## Uzaktan Erişim Hizmetleri

Bunlar, uzaktan erişim için yaygın olarak kullanılan macOS hizmetleridir.\
Bu hizmetleri `Sistem Ayarları` --> `Paylaşım` bölümünde etkinleştirebilir/devre dışı bırakabilirsiniz.

* **VNC**, "Ekran Paylaşımı" olarak bilinir (tcp:5900)
* **SSH**, "Uzak Oturum Açma" olarak adlandırılır (tcp:22)
* **Apple Uzak Masaüstü** (ARD) veya "Uzak Yönetim" (tcp:3283, tcp:5900)
* **AppleEvent**, "Uzak Apple Etkinliği" olarak bilinir (tcp:3031)

Etkin olan birini kontrol etmek için çalıştırın:
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\*.88|\*.445|\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### ARD Pentesting

Apple Remote Desktop (ARD), macOS için özel olarak tasarlanmış [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) 'in geliştirilmiş bir versiyonudur ve ek özellikler sunar. ARD'deki dikkate değer bir güvenlik açığı, kontrol ekranı parolası için kullanılan kimlik doğrulama yöntemidir. Bu yöntem sadece parolanın ilk 8 karakterini kullanır ve bu da [Hydra](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) veya [GoRedShell](https://github.com/ahhh/GoRedShell/) gibi araçlarla [brute force saldırılarına](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) karşı savunmasız hale getirir, çünkü varsayılan bir hız sınırlaması yoktur.

Zayıf noktalara sahip olan örnekler, **nmap**'in `vnc-info` komutuyla tespit edilebilir. `VNC Authentication (2)`'yi destekleyen hizmetler, 8 karakterlik parola kırpılması nedeniyle brute force saldırılarına özellikle savunmasızdır.

Ayrıcalık yükseltme, GUI erişimi veya kullanıcı izleme gibi çeşitli yönetimsel görevler için ARD'yi etkinleştirmek için aşağıdaki komutu kullanın:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD, Gözlem, Paylaşılan Kontrol ve Tam Kontrol gibi çok yönlü kontrol seviyeleri sağlar ve kullanıcı şifre değişikliklerinden sonra bile oturumlar devam eder. Unix komutlarını doğrudan göndermeye olanak tanır ve yönetici kullanıcılar için root olarak çalıştırır. Görev zamanlama ve Uzaktan Spotlight arama, hassas dosyaların birden fazla makinede uzaktan, düşük etkili aramalarını kolaylaştıran dikkate değer özelliklerdir.


## Bonjour Protokolü

Bonjour, Apple tarafından tasarlanan bir teknoloji olan **aynı ağdaki cihazların birbirlerinin sunulan hizmetlerini algılamasına** olanak sağlar. Rendezvous, Zero Configuration veya Zeroconf olarak da bilinen Bonjour, bir cihazın bir TCP/IP ağına katılmasını, **otomatik olarak bir IP adresi seçmesini** ve hizmetlerini diğer ağ cihazlarına yayınlamasını sağlar.

Bonjour tarafından sağlanan Zero Configuration Networking, cihazların aşağıdaki işlemleri gerçekleştirmesini sağlar:
* Bir DHCP sunucusu olmadan bile **otomatik olarak bir IP adresi almak**.
* Bir DNS sunucusu gerektirmeden **adı-adrese çeviri** yapmak.
* Ağda mevcut olan **hizmetleri keşfetmek**.

Bonjour kullanan cihazlar, kendilerine **169.254/16 aralığından bir IP adresi atar** ve bu adresin ağda benzersiz olduğunu doğrular. Mac'ler, bu alt ağ için bir yönlendirme tablosu girişi tutar ve `netstat -rn | grep 169` komutuyla doğrulanabilir.

Bonjour, DNS için **Multicast DNS (mDNS) protokolünü** kullanır. mDNS, **5353/UDP bağlantı noktası** üzerinden çalışır ve **standart DNS sorgularını** kullanır, ancak **224.0.0.251 çoklu yayın adresine** yöneliktir. Bu yaklaşım, ağdaki tüm dinleyen cihazların sorguları almasını ve yanıtlamasını sağlar, böylece kayıtlarını güncellemeleri kolaylaşır.

Ağa katıldığında, her cihaz kendiliğinden bir isim seçer, genellikle **.local** ile biten bir isim olur ve bu isim, ana bilgisayar adından veya rastgele oluşturulmuş olabilir.

Ağ içindeki hizmet keşfi, **DNS Service Discovery (DNS-SD)** tarafından kolaylaştırılır. DNS SRV kayıtlarının formatını kullanan DNS-SD, birden fazla hizmetin listelenmesini sağlamak için **DNS PTR kayıtlarını** kullanır. Belirli bir hizmeti arayan bir istemci, `<Hizmet>.<Alan>` için bir PTR kaydı isteyecek ve birden fazla sunucudan hizmet mevcutsa, `<Örnek>.<Hizmet>.<Alan>` formatında bir PTR kayıt listesi alacaktır.


**dns-sd** yardımcı programı, ağ hizmetlerini **keşfetmek ve reklam yapmak** için kullanılabilir. İşte kullanım örneklerinden bazıları:

### SSH Hizmetlerini Arama

Ağda SSH hizmetlerini aramak için aşağıdaki komut kullanılır:
```bash
dns-sd -B _ssh._tcp
```
Bu komut, _ssh._tcp hizmetlerini tarar ve zaman damgası, bayraklar, arayüz, alan adı, hizmet türü ve örnek adı gibi ayrıntıları çıktılar.

### Bir HTTP Hizmeti Reklamı

Bir HTTP hizmeti reklamı yapmak için şunu kullanabilirsiniz:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
Bu komut, `/index.html` yolunda 80 numaralı bağlantı noktasında "Index" adında bir HTTP hizmeti kaydeder.

Ardından ağda HTTP hizmetlerini aramak için:
```bash
dns-sd -B _http._tcp
```
Bir hizmet başladığında, varlığını çoklu yayın yaparak alt ağdaki tüm cihazlara duyurur. Bu hizmetlere ilgi duyan cihazlar, istek göndermek yerine sadece bu duyuruları dinleyerek hizmetleri bulabilir.

Daha kullanıcı dostu bir arayüz için, Apple App Store'da bulunan **Discovery - DNS-SD Browser** uygulaması yerel ağınızda sunulan hizmetleri görselleştirebilir.

Alternatif olarak, `python-zeroconf` kütüphanesini kullanarak hizmetleri taramak ve bulmak için özel betikler yazılabilir. [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) betiği, `_http._tcp.local.` hizmetleri için bir hizmet tarayıcısı oluşturmayı ve eklenen veya kaldırılan hizmetleri yazdırmayı göstermektedir:
```python
from zeroconf import ServiceBrowser, Zeroconf

class MyListener:

def remove_service(self, zeroconf, type, name):
print("Service %s removed" % (name,))

def add_service(self, zeroconf, type, name):
info = zeroconf.get_service_info(type, name)
print("Service %s added, service info: %s" % (name, info))

zeroconf = Zeroconf()
listener = MyListener()
browser = ServiceBrowser(zeroconf, "_http._tcp.local.", listener)
try:
input("Press enter to exit...\n\n")
finally:
zeroconf.close()
```
### Bonjour Devre Dışı Bırakma
Eğer güvenlikle ilgili endişeler varsa veya Bonjour'u devre dışı bırakmak için başka nedenler varsa, aşağıdaki komut kullanılarak devre dışı bırakılabilir:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## Referanslar

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana dönüşmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI'na**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerimizden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'i keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek** paylaşın.

</details>
