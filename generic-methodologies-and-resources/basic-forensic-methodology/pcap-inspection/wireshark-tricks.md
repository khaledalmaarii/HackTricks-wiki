# Wireshark tricks

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** bizi takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}


## Wireshark becerilerinizi geliştirin

### Eğitimler

Aşağıdaki eğitimler bazı harika temel ipuçlarını öğrenmek için mükemmeldir:

* [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
* [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
* [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
* [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Analiz Edilen Bilgiler

**Uzman Bilgisi**

_**Analyze** --> **Expert Information**_ seçeneğine tıkladığınızda, **analiz edilen** paketlerde neler olduğunu görebilirsiniz:

![](<../../../.gitbook/assets/image (256).png>)

**Çözülmüş Adresler**

_**Statistics --> Resolved Addresses**_ altında, wireshark tarafından "**çözülen**" çeşitli **bilgiler** bulabilirsiniz; örneğin port/taşıyıcıdan protokole, MAC'tan üreticiye vb. İletişimde nelerin yer aldığını bilmek ilginçtir.

![](<../../../.gitbook/assets/image (893).png>)

**Protokol Hiyerarşisi**

_**Statistics --> Protocol Hierarchy**_ altında, iletişimde yer alan **protokolleri** ve bunlarla ilgili verileri bulabilirsiniz.

![](<../../../.gitbook/assets/image (586).png>)

**Görüşmeler**

_**Statistics --> Conversations**_ altında, iletişimdeki **görüşmelerin** bir özetini ve bunlarla ilgili verileri bulabilirsiniz.

![](<../../../.gitbook/assets/image (453).png>)

**Uç Noktalar**

_**Statistics --> Endpoints**_ altında, iletişimdeki **uç noktaların** bir özetini ve her biriyle ilgili verileri bulabilirsiniz.

![](<../../../.gitbook/assets/image (896).png>)

**DNS bilgisi**

_**Statistics --> DNS**_ altında, yakalanan DNS isteği hakkında istatistikler bulabilirsiniz.

![](<../../../.gitbook/assets/image (1063).png>)

**G/Ç Grafiği**

_**Statistics --> I/O Graph**_ altında, iletişimin bir **grafiğini** bulabilirsiniz.

![](<../../../.gitbook/assets/image (992).png>)

### Filtreler

Burada protokole bağlı olarak wireshark filtrelerini bulabilirsiniz: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Diğer ilginç filtreler:

* `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
* HTTP ve başlangıç HTTPS trafiği
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
* HTTP ve başlangıç HTTPS trafiği + TCP SYN
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
* HTTP ve başlangıç HTTPS trafiği + TCP SYN + DNS istekleri

### Arama

Eğer oturumların **paketleri** içinde **içerik** aramak istiyorsanız _CTRL+f_ tuşlarına basın. Ana bilgi çubuğuna (No., Zaman, Kaynak vb.) yeni katmanlar eklemek için sağ tıklayıp ardından sütunu düzenleyebilirsiniz.

### Ücretsiz pcap laboratuvarları

**Ücretsiz zorluklarla pratik yapın:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Alan Adlarını Tanımlama

HTTP başlığını gösteren bir sütun ekleyebilirsiniz:

![](<../../../.gitbook/assets/image (639).png>)

Ve bir HTTPS bağlantısını başlatan sunucu adını ekleyen bir sütun (**ssl.handshake.type == 1**):

![](<../../../.gitbook/assets/image (408) (1).png>)

## Yerel Alan Adlarını Tanımlama

### DHCP'den

Mevcut Wireshark'ta `bootp` yerine `DHCP` aramanız gerekiyor.

![](<../../../.gitbook/assets/image (1013).png>)

### NBNS'den

![](<../../../.gitbook/assets/image (1003).png>)

## TLS'yi Şifre Çözme

### Sunucu özel anahtarı ile https trafiğini şifre çözme

_edit>preference>protocol>ssl>_

![](<../../../.gitbook/assets/image (1103).png>)

Sunucu ve özel anahtarın tüm verilerini (_IP, Port, Protokol, Anahtar dosyası ve şifre_) eklemek için _Edit_ seçeneğine basın.

### Simetrik oturum anahtarları ile https trafiğini şifre çözme

Hem Firefox hem de Chrome, TLS oturum anahtarlarını kaydetme yeteneğine sahiptir; bu anahtarlar Wireshark ile TLS trafiğini şifre çözmek için kullanılabilir. Bu, güvenli iletişimlerin derinlemesine analizine olanak tanır. Bu şifre çözme işlemini nasıl gerçekleştireceğinizle ilgili daha fazla ayrıntı [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/) kılavuzunda bulunabilir.

Bunu tespit etmek için ortamda `SSLKEYLOGFILE` değişkenini arayın.

Paylaşılan anahtarların bir dosyası şöyle görünecektir:

![](<../../../.gitbook/assets/image (820).png>)

Bunu wireshark'a aktarmak için _edit > preference > protocol > ssl > ve (Pre)-Master-Secret log filename_ kısmına aktarın:

![](<../../../.gitbook/assets/image (989).png>)

## ADB iletişimi

APK'nın gönderildiği bir ADB iletişiminden bir APK çıkarın:
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
{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
