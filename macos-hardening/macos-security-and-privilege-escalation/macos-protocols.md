# macOS Mrežne Usluge i Protokoli

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}

## Usluge Daljinskog Pristupa

Ovo su uobičajene macOS usluge za daljinski pristup.\
Možete omogućiti/isključiti ove usluge u `System Settings` --> `Sharing`

* **VNC**, poznat kao “Deljenje Ekrana” (tcp:5900)
* **SSH**, nazvan “Daljinska Prijava” (tcp:22)
* **Apple Remote Desktop** (ARD), ili “Daljinsko Upravljanje” (tcp:3283, tcp:5900)
* **AppleEvent**, poznat kao “Daljinski Apple Događaj” (tcp:3031)

Proverite da li je neka od ovih usluga omogućena pokretanjem:
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\*.88|\*.445|\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### Pentesting ARD

Apple Remote Desktop (ARD) je unapređena verzija [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) prilagođena za macOS, koja nudi dodatne funkcije. Značajna ranjivost u ARD-u je njegova metoda autentifikacije za lozinku kontrolne ekrana, koja koristi samo prvih 8 karaktera lozinke, što je čini podložnom [brute force napadima](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) sa alatima kao što su Hydra ili [GoRedShell](https://github.com/ahhh/GoRedShell/), jer ne postoje podrazumevani ograničenja brzine.

Ranjive instance se mogu identifikovati korišćenjem **nmap**-ovog `vnc-info` skripta. Usluge koje podržavaju `VNC Authentication (2)` su posebno podložne brute force napadima zbog skraćivanja lozinke na 8 karaktera.

Da biste omogućili ARD za razne administrativne zadatke kao što su eskalacija privilegija, GUI pristup ili praćenje korisnika, koristite sledeću komandu:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD pruža svestrane nivoe kontrole, uključujući posmatranje, deljenu kontrolu i punu kontrolu, sa sesijama koje traju čak i nakon promene korisničke lozinke. Omogućava slanje Unix komandi direktno, izvršavajući ih kao root za administrativne korisnike. Planiranje zadataka i daljinsko Spotlight pretraživanje su značajne karakteristike, olakšavajući daljinsko, niskoprofilno pretraživanje osetljivih datoteka na više mašina.

## Bonjour Protokol

Bonjour, tehnologija koju je dizajnirao Apple, omogućava **uređajima na istoj mreži da otkriju usluge koje nude jedni drugima**. Poznat i kao Rendezvous, **Zero Configuration**, ili Zeroconf, omogućava uređaju da se pridruži TCP/IP mreži, **automatski odabere IP adresu**, i emitira svoje usluge drugim mrežnim uređajima.

Zero Configuration Networking, koji pruža Bonjour, osigurava da uređaji mogu:
* **Automatski dobiti IP adresu** čak i u odsustvu DHCP servera.
* Izvršiti **prevod imena u adresu** bez potrebe za DNS serverom.
* **Otkrivati usluge** dostupne na mreži.

Uređaji koji koriste Bonjour dodeljuju sebi **IP adresu iz opsega 169.254/16** i proveravaju njenu jedinstvenost na mreži. Mac računari održavaju unos u tabeli rutiranja za ovu podmrežu, koji se može proveriti putem `netstat -rn | grep 169`.

Za DNS, Bonjour koristi **Multicast DNS (mDNS) protokol**. mDNS funkcioniše preko **porta 5353/UDP**, koristeći **standardne DNS upite** ali cilja **multicast adresu 224.0.0.251**. Ovaj pristup osigurava da svi uređaji koji slušaju na mreži mogu primati i odgovarati na upite, olakšavajući ažuriranje njihovih zapisa.

Prilikom pridruživanja mreži, svaki uređaj samostalno bira ime, obično završava sa **.local**, koje može biti izvedeno iz imena hosta ili nasumično generisano.

Otkrivanje usluga unutar mreže olakšano je **DNS Service Discovery (DNS-SD)**. Iskorišćavajući format DNS SRV zapisa, DNS-SD koristi **DNS PTR zapise** da omogući listanje više usluga. Klijent koji traži određenu uslugu će zatražiti PTR zapis za `<Service>.<Domain>`, primajući zauzvrat listu PTR zapisa formatiranih kao `<Instance>.<Service>.<Domain>` ako je usluga dostupna sa više hostova.

Alat `dns-sd` može se koristiti za **otkrivanje i oglašavanje mrežnih usluga**. Evo nekoliko primera njegove upotrebe:

### Pretraživanje SSH Usluga

Da biste pretražili SSH usluge na mreži, koristi se sledeća komanda:
```bash
dns-sd -B _ssh._tcp
```
Ova komanda pokreće pretragu za _ssh._tcp servisima i prikazuje detalje kao što su vremenska oznaka, zastavice, interfejs, domen, tip servisa i ime instance.

### Oglašavanje HTTP Servisa

Da biste oglasili HTTP servis, možete koristiti:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
Ova komanda registruje HTTP servis pod imenom "Index" na portu 80 sa putanjom `/index.html`.

Da biste zatim pretražili HTTP servise na mreži:
```bash
dns-sd -B _http._tcp
```
Kada usluga počne, ona najavljuje svoju dostupnost svim uređajima na podmreži putem multicast-a. Uređaji zainteresovani za ove usluge ne moraju slati zahteve, već jednostavno slušaju ove najave.

Za korisnički prijatniji interfejs, aplikacija **Discovery - DNS-SD Browser** dostupna na Apple App Store-u može vizualizovati usluge koje se nude na vašoj lokalnoj mreži.

Alternativno, mogu se napisati prilagođeni skripti za pretraživanje i otkrivanje usluga koristeći `python-zeroconf` biblioteku. Skripta [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) demonstrira kreiranje pretraživača usluga za `_http._tcp.local.` usluge, štampajući dodate ili uklonjene usluge:
```python
from zeroconf import ServiceBrowser, Zeroconf

class MyListener:

def remove_service(self, zeroconf, type, name):
print("Service %s removed" % (name,))

def add_service(self, zeroconf, type, name):
info = zeroconf.get_service_info(type, name)
print("Service %s added, service info: %s" % (name, info))

zeroconf = Zeroconf()
listener = MyListener()
browser = ServiceBrowser(zeroconf, "_http._tcp.local.", listener)
try:
input("Press enter to exit...\n\n")
finally:
zeroconf.close()
```
### Onemogućavanje Bonjour
Ako postoje zabrinutosti u vezi sa bezbednošću ili drugi razlozi za onemogućavanje Bonjour-a, može se isključiti pomoću sledeće komande:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## References

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
