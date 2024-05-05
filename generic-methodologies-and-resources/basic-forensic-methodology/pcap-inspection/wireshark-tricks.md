# Wireshark ipuçları

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklam görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünleri**](https://peass.creator-spring.com)'ni edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)'da **takip edin**.
* **Hacking ipuçlarınızı paylaşarak PR göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io), şirketin veya müşterilerinin **hırsız kötü amaçlı yazılımlar** tarafından **kompromize edilip edilmediğini** kontrol etmek için **ücretsiz** işlevler sunan **dark-web** destekli bir arama motorudur.

WhiteIntel'in başlıca amacı, bilgi çalan kötü amaçlı yazılımlardan kaynaklanan hesap ele geçirmeleri ve fidye saldırılarıyla mücadele etmektir.

Websitesini ziyaret edebilir ve motorlarını **ücretsiz** deneyebilirsiniz:

{% embed url="https://whiteintel.io" %}

***

## Wireshark becerilerinizi geliştirin

### Eğitimler

Aşağıdaki eğitimler, bazı harika temel ipuçları öğrenmek için harikadır:

* [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
* [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
* [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
* [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Analiz Edilen Bilgiler

**Uzman Bilgiler**

_Analyze_ --> **Expert Information** üzerine tıkladığınızda, **analiz edilen** paketlerde neler olduğuna dair bir **genel bakış** elde edersiniz:

![](<../../../.gitbook/assets/image (256).png>)

**Çözülen Adresler**

_Statistics --> Çözülen Adresler_ altında, wireshark tarafından çözülen port/taşıma protokolüne, MAC'ten üreticiye vb. gibi çeşitli **bilgileri** bulabilirsiniz. İletişimde neyin etkilendiğini bilmek ilginçtir.

![](<../../../.gitbook/assets/image (893).png>)

**Protokol Hiyerarşisi**

_Statistics --> Protokol Hiyerarşisi_ altında, iletişimde yer alan **protokolleri** ve bunlarla ilgili verileri bulabilirsiniz.

![](<../../../.gitbook/assets/image (586).png>)

**Konuşmalar**

_Statistics --> Konuşmalar_ altında, iletişimdeki **konuşmaların özetini** ve bunlarla ilgili verileri bulabilirsiniz.

![](<../../../.gitbook/assets/image (453).png>)

**Uç Noktalar**

_Statistics --> Uç Noktalar_ altında, iletişimdeki **uç noktaların özetini** ve her biri hakkındaki verileri bulabilirsiniz.

![](<../../../.gitbook/assets/image (896).png>)

**DNS bilgisi**

_Statistics --> DNS_ altında, yakalanan DNS isteği hakkında istatistikler bulabilirsiniz.

![](<../../../.gitbook/assets/image (1063).png>)

**I/O Grafik**

_Statistics --> I/O Grafik_ altında, bir **iletişim grafiğini** bulabilirsiniz.

![](<../../../.gitbook/assets/image (992).png>)

### Filtreler

Burada, protokole bağlı olarak wireshark filtresi bulabilirsiniz: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Diğer ilginç filtreler:

* `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
* HTTP ve başlangıç HTTPS trafiği
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
* HTTP ve başlangıç HTTPS trafiği + TCP SYN
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
* HTTP ve başlangıç HTTPS trafiği + TCP SYN + DNS istekleri

### Arama

Oturumların **paketlerindeki içeriği aramak** istiyorsanız _CTRL+f_ tuşuna basın. Ana bilgi çubuğuna yeni katmanlar ekleyebilirsiniz (No., Zaman, Kaynak, vb.) sağ tıkladıktan sonra sütunu düzenleyerek.

### Ücretsiz pcap labları

**Ücretsiz zorluklarla pratik yapın:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Alan Adlarını Tanımlama

Host HTTP başlığını gösteren bir sütun ekleyebilirsiniz:

![](<../../../.gitbook/assets/image (639).png>)

Ve başlatılan bir HTTPS bağlantısından Sunucu adını ekleyen bir sütun:

![](<../../../.gitbook/assets/image (408) (1).png>)

## Yerel ana bilgisayar adlarını tanımlama

### DHCP'den

Mevcut Wireshark'ta `bootp` yerine `DHCP` aramalısınız

![](<../../../.gitbook/assets/image (1013).png>)

### NBNS'den

![](<../../../.gitbook/assets/image (1003).png>)

## TLS'nin Şifresini Çözme

### Sunucu özel anahtarı ile https trafiğini çözme

_düzenle>t tercih>protokol>ssl>_

![](<../../../.gitbook/assets/image (1103).png>)

_Düzenle_ düğmesine basın ve sunucunun ve özel anahtarın tüm verilerini ekleyin (_IP, Port, Protokol, Anahtar dosyası ve şifre_)

### Simetrik oturum anahtarları ile https trafiğini çözme

Hem Firefox hem de Chrome, Wireshark'ın TLS trafiğini çözmek için kullanabileceği TLS oturum anahtarlarını kaydetme yeteneğine sahiptir. Bu, güvenli iletişimin detaylı analizine olanak tanır. Bu şifre çözümünü nasıl gerçekleştireceğinizle ilgili daha fazla ayrıntıya [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/) rehberinde bulabilirsiniz.

Bunu tespit etmek için ortam içinde `SSLKEYLOGFILE` değişkenini arayın

Paylaşılan anahtarlar dosyası şuna benzer olacaktır:

![](<../../../.gitbook/assets/image (820).png>)

Bunu wireshark'a içe aktarmak için \_düzenle > tercih > protokol > ssl > ve içe aktarın (Pre)-Master-Secret log dosya adı:

![](<../../../.gitbook/assets/image (989).png>)
## ADB iletişimi

APK'nın gönderildiği bir ADB iletişiminden APK çıkarın:
```python
from scapy.all import *

pcap = rdpcap("final2.pcapng")

def rm_data(data):
splitted = data.split(b"DATA")
if len(splitted) == 1:
return data
else:
return splitted[0]+splitted[1][4:]

all_bytes = b""
for pkt in pcap:
if Raw in pkt:
a = pkt[Raw]
if b"WRTE" == bytes(a)[:4]:
all_bytes += rm_data(bytes(a)[24:])
else:
all_bytes += rm_data(bytes(a))
print(all_bytes)

f = open('all_bytes.data', 'w+b')
f.write(all_bytes)
f.close()
```
### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io), şirketin veya müşterilerinin **hırsız kötü amaçlı yazılımlar** tarafından **kompromize** edilip edilmediğini kontrol etmek için **ücretsiz** işlevler sunan **karanlık ağ** destekli bir arama motorudur.

WhiteIntel'in asıl amacı, bilgi çalan kötü amaçlı yazılımlardan kaynaklanan hesap ele geçirmeleri ve fidye yazılımı saldırılarıyla mücadele etmektir.

Websitesini ziyaret edebilir ve motorlarını **ücretsiz** deneyebilirsiniz:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahramana kadar AWS hacklemeyi öğrenin!</summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **💬 [Discord grubuna](https://discord.gg/hRep4RUj7f) katılın veya [telegram grubuna](https://t.me/peass) katılın veya bizi Twitter'da takip edin** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
