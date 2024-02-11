# macOS Netwerkdienste en Protokolle

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## Afstandsbedieningsdienste

Dit is die algemene macOS-dienste om hulle afstandsbediening te gebruik.\
Jy kan hierdie dienste aktiveer/deaktiveer in `Sisteeminstellings` --> `Deel`

* **VNC**, bekend as "Skerm Deling" (tcp:5900)
* **SSH**, genoem "Afstandslogin" (tcp:22)
* **Apple Remote Desktop** (ARD), of "Afstandsbestuur" (tcp:3283, tcp:5900)
* **AppleEvent**, bekend as "Afstands Apple-gebeurtenis" (tcp:3031)

Kyk of enigeen geaktiveer is deur die volgende uit te voer:
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

Apple Remote Desktop (ARD) is 'n verbeterde weergawe van [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) wat aangepas is vir macOS en ekstra funksies bied. 'n Noemenswaardige kwesbaarheid in ARD is sy outentiseringsmetode vir die beheerskerm wagwoord, wat slegs die eerste 8 karakters van die wagwoord gebruik, wat dit vatbaar maak vir [brute force aanvalle](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) met gereedskap soos Hydra of [GoRedShell](https://github.com/ahhh/GoRedShell/), aangesien daar geen verstek tempo-beperkings is nie.

Kwesbare instansies kan geïdentifiseer word met behulp van die `vnc-info` skripsie van **nmap**. Dienste wat `VNC Authentication (2)` ondersteun, is veral vatbaar vir brute force aanvalle as gevolg van die 8-karakter wagwoord afsnyding.

Om ARD te aktiveer vir verskeie administratiewe take soos voorregverhoging, GUI-toegang of gebruikersmonitering, gebruik die volgende bevel:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD bied veelsydige beheervlakke, insluitend waarneming, gedeelde beheer en volle beheer, met sessies wat voortduur selfs nadat die gebruikerswagwoord verander is. Dit maak dit moontlik om Unix-opdragte direk te stuur en as root uit te voer vir administratiewe gebruikers. Taakbeplanning en afstandsbediening Spotlight-soektogte is opmerklike kenmerke wat afstandsbediening, lae-impak soektogte vir sensitiewe lêers oor verskeie masjiene fasiliteer.

## Bonjour-protokol

Bonjour, 'n tegnologie wat deur Apple ontwerp is, maak dit moontlik vir toestelle op dieselfde netwerk om mekaar se aangebiede dienste op te spoor. Dit staan ook bekend as Rendezvous, Zero Configuration of Zeroconf, en maak dit moontlik vir 'n toestel om by 'n TCP/IP-netwerk aan te sluit, outomaties 'n IP-adres te kies en sy dienste na ander netwerktoestelle uit te saai.

Zero Configuration Networking, wat deur Bonjour voorsien word, verseker dat toestelle die volgende kan doen:
* Outomaties 'n IP-adres bekom, selfs in die afwesigheid van 'n DHCP-bediener.
* Naam-na-adres-vertaling uitvoer sonder 'n DNS-bediener te vereis.
* Dienste beskikbaar op die netwerk opspoor.

Toestelle wat Bonjour gebruik, sal vir hulself 'n IP-adres uit die 169.254/16-reeks toewys en die uniekheid daarvan op die netwerk verifieer. Macs handhaaf 'n roetetabelinskrywing vir hierdie subnet, wat geverifieer kan word deur `netstat -rn | grep 169` uit te voer.

Vir DNS maak Bonjour gebruik van die Multicast DNS (mDNS)-protokol. mDNS werk oor poort 5353/UDP en gebruik standaard DNS-navrae, maar rig dit op die multicast-adres 224.0.0.251. Hierdie benadering verseker dat alle luisterende toestelle op die netwerk die navrae kan ontvang en daarop kan reageer, wat die opdatering van hul rekords fasiliteer.

By die aansluiting by die netwerk kies elke toestel self 'n naam, wat gewoonlik eindig met .local, en wat afgelei kan word van die gasheernaam of lukraak gegenereer kan word.

Dienstopsporing binne die netwerk word gefasiliteer deur DNS Service Discovery (DNS-SD). Deur gebruik te maak van die formaat van DNS SRV-rekords, gebruik DNS-SD DNS PTR-rekords om die lys van veelvuldige dienste moontlik te maak. 'n Kliënt wat 'n spesifieke diens soek, sal 'n PTR-rekord vir `<Dienste>.<Domein>` aanvra en as die diens beskikbaar is vanaf verskeie gasheerders, sal 'n lys van PTR-rekords in die formaat `<Instansie>.<Dienste>.<Domein>` ontvang.

Die hulpprogram `dns-sd` kan gebruik word om netwerkdienste op te spoor en te adverteer. Hier is 'n paar voorbeelde van die gebruik daarvan:

### Soek na SSH-dienste

Om na SSH-dienste op die netwerk te soek, word die volgende opdrag gebruik:
```bash
dns-sd -B _ssh._tcp
```
Hierdie bevel begin soek na _ssh._tcp dienste en gee besonderhede soos tydstempel, vlae, koppelvlak, domein, diens tipe, en instansie naam.

### Adverteer 'n HTTP Diens

Om 'n HTTP diens te adverteer, kan jy gebruik maak van:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
Hierdie bevel registreer 'n HTTP-diens genaamd "Index" op poort 80 met 'n pad van `/index.html`.

Om dan te soek na HTTP-dienste op die netwerk:
```bash
dns-sd -B _http._tcp
```
Wanneer 'n diens begin, kondig dit sy beskikbaarheid aan aan alle toestelle op die subnet deur sy teenwoordigheid te multicast. Toestelle wat belangstel in hierdie dienste hoef nie versoek te stuur nie, maar luister eenvoudig na hierdie aankondigings.

Vir 'n meer gebruikersvriendelike koppelvlak kan die **Discovery - DNS-SD Browser**-toep beskikbaar op die Apple App Store die dienste wat op jou plaaslike netwerk aangebied word, visualiseer.

Alternatiewelik kan aangepaste skripte geskryf word om dienste te blaai en te ontdek deur die `python-zeroconf`-biblioteek te gebruik. Die [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) skrips demonstreer die skep van 'n diensblaaier vir `_http._tcp.local.`-dienste, wat bygevoegde of verwyderde dienste druk:
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
### Bonjour uitskakel
As daar bekommernis is oor sekuriteit of ander redes om Bonjour uit te skakel, kan dit afgeskakel word met behulp van die volgende opdrag:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## Verwysings

* [**Die Mac Hacker se Handboek**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>
