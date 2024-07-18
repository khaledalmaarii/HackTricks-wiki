# Wireshark tricks

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

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) є **пошуковою системою**, що працює на основі **темного вебу**, яка пропонує **безкоштовні** функції для перевірки, чи була компанія або її клієнти **компрометовані** **шкідливими програмами**.

Основна мета WhiteIntel - боротися з захопленням облікових записів та атаками програм-вимагачів, що виникають внаслідок шкідливих програм, які крадуть інформацію.

Ви можете перевірити їхній вебсайт і спробувати їхній двигун **безкоштовно** за адресою:

{% embed url="https://whiteintel.io" %}

***

## Improve your Wireshark skills

### Tutorials

Наступні навчальні посібники чудово підходять для вивчення деяких основних трюків:

* [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
* [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
* [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
* [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Analysed Information

**Expert Information**

Клацнувши на _**Analyze** --> **Expert Information**_, ви отримаєте **огляд** того, що відбувається в **аналізованих** пакетах:

![](<../../../.gitbook/assets/image (256).png>)

**Resolved Addresses**

У розділі _**Statistics --> Resolved Addresses**_ ви можете знайти кілька **інформацій**, які були "**розв'язані**" Wireshark, таких як порт/транспорт до протоколу, MAC до виробника тощо. Цікаво знати, що залучено в комунікацію.

![](<../../../.gitbook/assets/image (893).png>)

**Protocol Hierarchy**

У розділі _**Statistics --> Protocol Hierarchy**_ ви можете знайти **протоколи**, **залучені** в комунікацію, та дані про них.

![](<../../../.gitbook/assets/image (586).png>)

**Conversations**

У розділі _**Statistics --> Conversations**_ ви можете знайти **резюме розмов** у комунікації та дані про них.

![](<../../../.gitbook/assets/image (453).png>)

**Endpoints**

У розділі _**Statistics --> Endpoints**_ ви можете знайти **резюме кінцевих точок** у комунікації та дані про кожну з них.

![](<../../../.gitbook/assets/image (896).png>)

**DNS info**

У розділі _**Statistics --> DNS**_ ви можете знайти статистику про захоплені DNS запити.

![](<../../../.gitbook/assets/image (1063).png>)

**I/O Graph**

У розділі _**Statistics --> I/O Graph**_ ви можете знайти **графік комунікації.**

![](<../../../.gitbook/assets/image (992).png>)

### Filters

Тут ви можете знайти фільтри Wireshark в залежності від протоколу: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Інші цікаві фільтри:

* `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
* HTTP та початковий HTTPS трафік
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
* HTTP та початковий HTTPS трафік + TCP SYN
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
* HTTP та початковий HTTPS трафік + TCP SYN + DNS запити

### Search

Якщо ви хочете **шукати** **вміст** всередині **пакетів** сесій, натисніть _CTRL+f_. Ви можете додати нові шари до основної інформаційної панелі (No., Time, Source тощо), натиснувши праву кнопку миші, а потім редагуючи стовпець.

### Free pcap labs

**Практикуйтеся з безкоштовними завданнями на:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Identifying Domains

Ви можете додати стовпець, який показує заголовок Host HTTP:

![](<../../../.gitbook/assets/image (639).png>)

І стовпець, який додає ім'я сервера з ініціюючого HTTPS з'єднання (**ssl.handshake.type == 1**):

![](<../../../.gitbook/assets/image (408) (1).png>)

## Identifying local hostnames

### From DHCP

У сучасному Wireshark замість `bootp` вам потрібно шукати `DHCP`

![](<../../../.gitbook/assets/image (1013).png>)

### From NBNS

![](<../../../.gitbook/assets/image (1003).png>)

## Decrypting TLS

### Decrypting https traffic with server private key

_edit>preference>protocol>ssl>_

![](<../../../.gitbook/assets/image (1103).png>)

Натисніть _Edit_ і додайте всі дані сервера та приватний ключ (_IP, Port, Protocol, Key file and password_)

### Decrypting https traffic with symmetric session keys

Як Firefox, так і Chrome мають можливість записувати TLS сесійні ключі, які можна використовувати з Wireshark для розшифровки TLS трафіку. Це дозволяє проводити детальний аналіз захищених комунікацій. Більше деталей про те, як виконати цю розшифровку, можна знайти в посібнику на [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).

Щоб виявити це, шукайте в середовищі змінну `SSLKEYLOGFILE`

Файл спільних ключів виглядатиме так:

![](<../../../.gitbook/assets/image (820).png>)

Щоб імпортувати це в Wireshark, перейдіть до _edit > preference > protocol > ssl > і імпортуйте його в (Pre)-Master-Secret log filename:

![](<../../../.gitbook/assets/image (989).png>)

## ADB communication

Витягніть APK з ADB комунікації, де APK був надісланий:
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

[**WhiteIntel**](https://whiteintel.io) — це **пошукова система**, що працює на основі **темного вебу**, яка пропонує **безкоштовні** функції для перевірки, чи була компанія або її клієнти **компрометовані** **шкідливими програмами-крадіями**.

Основна мета WhiteIntel — боротися з захопленням облікових записів та атаками програм-вимагачів, що виникають внаслідок шкідливих програм, які крадуть інформацію.

Ви можете перевірити їхній вебсайт і спробувати їхній двигун **безкоштовно** за адресою:

{% embed url="https://whiteintel.io" %}

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
