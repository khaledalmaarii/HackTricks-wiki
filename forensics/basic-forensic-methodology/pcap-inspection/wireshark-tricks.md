# Wireshark hileleri

## Wireshark hileleri

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)'ı takip edin.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek** paylaşın.

</details>

## Wireshark becerilerinizi geliştirin

### Öğreticiler

Aşağıdaki öğreticiler, bazı harika temel hileler öğrenmek için mükemmeldir:

* [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
* [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
* [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
* [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Analiz Edilen Bilgiler

**Uzman Bilgisi**

_Analyze_ --> _Expert Information_ üzerine tıklayarak, **analiz edilen** paketlerde neler olduğuna dair bir **genel bakış** elde edebilirsiniz:

![](<../../../.gitbook/assets/image (570).png>)

**Çözümlenen Adresler**

_Statistics_ --> _Resolved Addresses_ altında, wireshark tarafından "**çözümlenen**" birkaç **bilgi** bulabilirsiniz. Bu, iletişimde neyin etkilendiğini bilmek açısından ilginçtir.

![](<../../../.gitbook/assets/image (571).png>)

**Protokol Hiyerarşisi**

_Statistics_ --> _Protocol Hierarchy_ altında, iletişimde yer alan **protokoller** ve bunlar hakkında veriler bulabilirsiniz.

![](<../../../.gitbook/assets/image (572).png>)

**Konuşmalar**

_Statistics_ --> _Conversations_ altında, iletişimdeki **konuşmaların özetini** ve bunlar hakkında verileri bulabilirsiniz.

![](<../../../.gitbook/assets/image (573).png>)

**Uç Noktalar**

_Statistics_ --> _Endpoints_ altında, iletişimdeki **uç noktaların özetini** ve her biri hakkında verileri bulabilirsiniz.

![](<../../../.gitbook/assets/image (575).png>)

**DNS bilgisi**

_Statistics_ --> _DNS_ altında, yakalanan DNS istekleri hakkında istatistikler bulabilirsiniz.

![](<../../../.gitbook/assets/image (577).png>)

**I/O Grafik**

_Statistics_ --> _I/O Graph_ altında, iletişimin bir **grafiksel gösterimini** bulabilirsiniz.

![](<../../../.gitbook/assets/image (574).png>)

### Filtreler

Burada, protokole bağlı olarak wireshark filtrelerini bulabilirsiniz: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Diğer ilginç filtreler:

* `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
* HTTP ve başlangıç HTTPS trafiği
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
* HTTP ve başlangıç HTTPS trafiği + TCP SYN
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
* HTTP ve başlangıç HTTPS trafiği + TCP SYN + DNS istekleri

### Arama

Oturumların paketlerindeki **içeriği aramak** isterseniz _CTRL+f_ tuşuna basın. Ana bilgi çubuğuna yeni katmanlar ekleyebilirsiniz (No., Zaman, Kaynak, vb.) sağ tıklayarak ve ardından sütun düzenleme seçeneğini seçerek.

### Ücretsiz pcap laboratuvarları

**Ücretsiz zorluklarla pratik yapın: [https://www.malware-traffic-analysis.net/](https://www.malware-traffic-analysis.net)**

## Alanları Tanımlama

HTTP başlığı Host'u gösteren bir sütun ekleyebilirsiniz:

![](<../../../.gitbook/assets/image (403).png>)

Ve başlatan bir HTTPS bağlantısından Sunucu adını ekleyen bir sütun:

![](<../../../.gitbook/assets/image (408) (1).png>)

## Yerel ana bilgisayar adlarını tanımlama

### DHCP'den

Mevcut Wireshark'ta `bootp` yerine `DHCP` aramanız gerekmektedir.

![](<../../../.gitbook/assets/image (404).png>)

### NBNS'den

![](<../../../.gitbook/assets/image (405).png>)

## TLS'nin Şifresini Çözme

### Sunucu özel anahtarıyla https trafiğini çözme

_düzenle>tercih>protokol>ssl>_

![](<../../../.gitbook/assets/image (98).png>)

_Düzenle_ düğmesine basın ve sunucu ve özel anahtarın tüm verilerini (_IP, Port, Protokol, Anahtar dosyası ve parola_) ekleyin.

### Simetrik oturum anahtarlarıyla https trafiğini çözme

Firefox ve Chrome, TLS oturum anahtarlarını kaydetme yeteneğine sahiptir, bu anahtarlar Wireshark ile birlikte kullanılarak TLS trafiği çözülebilir. Bu, güvenli iletişimin detaylı analizine olanak sağlar. Bu şifrelemeyi nasıl gerçekleştireceğinizle ilgili daha fazla bilgiye [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/) rehberinde bulabilirsiniz.

Bunu tespit etmek için ortam içinde `SSLKEYLOGFILE` değişkenini arayın.

Paylaşılan anahtarlar dosyası şuna benzer olacaktır:

![](<../../../.gitbook/assets/image (99).png>)

Bu dosyayı Wireshark'a içe aktarmak için \_düzenle > tercih > protokol > ssl > ve (Pre)-Master-Secret log dosya adına içe aktarın:

![](<../../../.gitbook/assets/image (100).png>)

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
<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek isterseniz** veya **HackTricks'i PDF olarak indirmek isterseniz** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)'ı **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>
