# Wireshark ipuçları

## Wireshark ipuçları

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana kadar öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> ile!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na göz atın (https://github.com/sponsors/carlospolop)!
* [**Resmi PEASS & HackTricks ürünleri**]'ni edinin (https://peass.creator-spring.com)
* [**The PEASS Family**]'yi keşfedin (https://opensea.io/collection/the-peass-family), özel [**NFT'lerimiz**]'in koleksiyonu
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking ipuçlarınızı paylaşarak PR'lar göndererek HackTricks** (https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

## Wireshark becerilerinizi geliştirin

### Eğitimler

Aşağıdaki eğitimler bazı harika temel ipuçları öğrenmek için harikadır:

* [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
* [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
* [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
* [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Analiz Edilen Bilgiler

**Uzman Bilgiler**

_Analyze_ --> _Expert Information_ üzerine tıkladığınızda, **analiz edilen** paketlerde neler olduğuna dair bir **genel bakış** elde edersiniz:

![](<../../../.gitbook/assets/image (253).png>)

**Çözülen Adresler**

_Statistics --> Çözülen Adresler_ altında, wireshark tarafından çözülen birçok **bilgiyi** bulabilirsiniz, örneğin port/taşıma protokolüne, MAC adresinden üreticiye vb. İletişimde neyin etkilendiğini bilmek ilginçtir.

![](<../../../.gitbook/assets/image (890).png>)

**Protokol Hiyerarşisi**

_Statistics --> Protokol Hiyerarşisi_ altında, iletişimde yer alan **protokolleri** ve bunlarla ilgili verileri bulabilirsiniz.

![](<../../../.gitbook/assets/image (583).png>)

**Konuşmalar**

_Statistics --> Konuşmalar_ altında, iletişimdeki **konuşmaların özetini** ve bunlarla ilgili verileri bulabilirsiniz.

![](<../../../.gitbook/assets/image (450).png>)

**Uç Noktalar**

_Statistics --> Uç Noktalar_ altında, iletişimdeki **uç noktaların özetini** ve her biri hakkındaki verileri bulabilirsiniz.

![](<../../../.gitbook/assets/image (893).png>)

**DNS bilgisi**

_Statistics --> DNS_ altında, yakalanan DNS isteği hakkında istatistikler bulabilirsiniz.

![](<../../../.gitbook/assets/image (1060).png>)

**I/O Grafik**

_Statistics --> I/O Grafik_ altında, bir **iletişim grafiğini** bulabilirsiniz.

![](<../../../.gitbook/assets/image (989).png>)

### Filtreler

Burada, protokole bağlı olarak wireshark filtresi bulabilirsiniz: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Diğer ilginç filtreler:

* `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
* HTTP ve başlangıçtaki HTTPS trafiği
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
* HTTP ve başlangıçtaki HTTPS trafiği + TCP SYN
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
* HTTP ve başlangıçtaki HTTPS trafiği + TCP SYN + DNS istekleri

### Arama

Oturumların paketlerindeki **içerik** için **arama** yapmak istiyorsanız _CTRL+f_ tuşuna basın. Ana bilgi çubuğuna yeni katmanlar ekleyebilirsiniz (No., Zaman, Kaynak, vb.) sağ tıkladıktan sonra sütunu düzenleyerek.

### Ücretsiz pcap laboratuvarları

**Ücretsiz zorluklarla pratik yapın:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Alanları Tanımlama

HTTP başlığı Host'u gösteren bir sütun ekleyebilirsiniz:

![](<../../../.gitbook/assets/image (635).png>)

Ve başlatılan bir HTTPS bağlantısından Sunucu adını ekleyen bir sütun:

![](<../../../.gitbook/assets/image (408) (1).png>)

## Yerel ana bilgisayar adlarını tanımlama

### DHCP'den

Mevcut Wireshark'ta `bootp` yerine `DHCP` aramalısınız

![](<../../../.gitbook/assets/image (1010).png>)

### NBNS'den

![](<../../../.gitbook/assets/image (1000).png>)

## TLS'nin Şifresini Çözme

### Sunucu özel anahtarı ile https trafiğini çözme

_düzenle>tercih>protokol>ssl>_

![](<../../../.gitbook/assets/image (1100).png>)

_Düzenle_ düğmesine basın ve sunucunun ve özel anahtarın tüm verilerini ekleyin (_IP, Port, Protokol, Anahtar dosyası ve şifre_)

### Simetrik oturum anahtarları ile https trafiğini çözme

Hem Firefox hem de Chrome, Wireshark'ın TLS trafiğini çözmek için kullanabileceği TLS oturum anahtarlarını kaydetme yeteneğine sahiptir. Bu, güvenli iletişimin detaylı analizine olanak tanır. Bu şifre çözümünü nasıl gerçekleştireceğinizle ilgili daha fazla bilgiye [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/) adresindeki bir kılavuzda bulunabilir.

Bunu tespit etmek için ortam içinde `SSLKEYLOGFILE` değişkenini arayın

Paylaşılan anahtarlar dosyası şuna benzer olacaktır:

![](<../../../.gitbook/assets/image (817).png>)

Bunu wireshark'a içe aktarmak için \_düzenle > tercih > protokol > ssl > ve (Pre)-Master-Secret log dosya adına içe aktarın:

![](<../../../.gitbook/assets/image (986).png>)

## ADB ile iletişim

APK'nın gönderildiği bir ADB iletişiminden APK çıkarma:
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
<details>

<summary><strong>Sıfırdan kahraman olmaya kadar AWS hacklemeyi öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'da takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
