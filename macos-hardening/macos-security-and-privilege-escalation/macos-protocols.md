# Huduma na Itifaki za Mtandao za macOS

<details>

<summary><strong>Jifunze kuhusu kuhack AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa katika HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Huduma za Kupata Kijijini

Hizi ni huduma za kawaida za macOS ambazo unaweza kuzifikia kijijini.\
Unaweza kuwezesha/kulemaza huduma hizi katika `Mipangilio ya Mfumo` --> `Kushiriki`

* **VNC**, inayojulikana kama "Screen Sharing" (tcp:5900)
* **SSH**, inayoitwa "Remote Login" (tcp:22)
* **Apple Remote Desktop** (ARD), au "Remote Management" (tcp:3283, tcp:5900)
* **AppleEvent**, inayojulikana kama "Remote Apple Event" (tcp:3031)

Angalia ikiwa yoyote imelemazwa kwa kukimbia:
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

Apple Remote Desktop (ARD) ni toleo lililoboreshwa la [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) lililobinafsishwa kwa macOS, likitoa huduma za ziada. Kasoro inayojulikana katika ARD ni njia yake ya uwakiki kwa nenosiri la skrini ya udhibiti, ambayo hutumia tu herufi 8 za kwanza za nenosiri, ikifanya iwe rahisi kwa [mashambulizi ya nguvu ya kijusi](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) kwa kutumia zana kama Hydra au [GoRedShell](https://github.com/ahhh/GoRedShell/), kwani hakuna mipaka ya kiwango cha kawaida.

Mifano yenye kasoro inaweza kutambuliwa kwa kutumia script ya `vnc-info` ya **nmap**. Huduma zinazounga mkono `VNC Authentication (2)` ziko katika hatari kubwa ya mashambulizi ya nguvu ya kijusi kutokana na kukatwa kwa nenosiri la herufi 8.

Ili kuwezesha ARD kwa kazi mbalimbali za utawala kama kuongeza mamlaka, kupata ufikivu wa GUI, au ufuatiliaji wa mtumiaji, tumia amri ifuatayo:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD hutoa viwango mbalimbali vya udhibiti, ikiwa ni pamoja na uangalizi, udhibiti ulioshirikishwa, na udhibiti kamili, na vikao vinaendelea hata baada ya mabadiliko ya nenosiri la mtumiaji. Inaruhusu kutuma amri za Unix moja kwa moja, kuzitekeleza kama mizizi kwa watumiaji wa utawala. Uwezo wa kupanga kazi na utafutaji wa mbali wa Spotlight ni vipengele muhimu, vinavyorahisisha utafutaji wa faili nyeti kwa njia ya mbali na athari ndogo kwenye mashine kadhaa.

## Itifaki ya Bonjour

Bonjour, teknolojia iliyoundwa na Apple, inaruhusu **vifaa kwenye mtandao huo huo kugundua huduma zinazotolewa na kila mmoja**. Inayojulikana pia kama Rendezvous, **Zero Configuration**, au Zeroconf, inawezesha kifaa kujiunga na mtandao wa TCP/IP, **kuchagua anwani ya IP kiotomatiki**, na kutangaza huduma zake kwa vifaa vingine kwenye mtandao.

Zero Configuration Networking, inayotolewa na Bonjour, inahakikisha kuwa vifaa vinaweza:
* **Kupata anwani ya IP kiotomatiki** hata kama hakuna seva ya DHCP.
* Kufanya **tafsiri ya jina-kuwa-anwani** bila kuhitaji seva ya DNS.
* **Kugundua huduma** zilizopo kwenye mtandao.

Vifaa vinavyotumia Bonjour vitajitengea wenyewe anwani ya **IP kutoka kwa safu ya 169.254/16** na kuhakikisha kuwa ni ya pekee kwenye mtandao. Macs inaingiza kuingia kwenye meza ya ujumbe kwa subnet hii, inayoweza kuthibitishwa kupitia `netstat -rn | grep 169`.

Kwa DNS, Bonjour hutumia **Itifaki ya Multicast DNS (mDNS)**. mDNS inafanya kazi kupitia **bandari 5353/UDP**, ikitumia **mambo ya kawaida ya DNS** lakini ikilenga **anwani ya multicast 224.0.0.251**. Njia hii inahakikisha kuwa vifaa vyote vinavyosikiliza kwenye mtandao vinaweza kupokea na kujibu maswali, ikirahisisha sasisho la rekodi zao.

Baada ya kujiunga na mtandao, kila kifaa huchagua jina lake, kawaida likiishia na **.local**, ambalo linaweza kutokana na jina la mwenyeji au kuzalishwa kwa nasibu.

Ugunduzi wa huduma ndani ya mtandao unafanikishwa na **Ugunduzi wa Huduma za DNS (DNS-SD)**. Kwa kutumia muundo wa rekodi za DNS SRV, DNS-SD hutumia **rekodi za DNS PTR** kuwezesha orodha ya huduma nyingi. Mteja anayetafuta huduma maalum atauliza rekodi ya PTR kwa `<Huduma>.<Kikoa>`, na kupokea orodha ya rekodi za PTR zilizoandaliwa kama `<Kipengele>.<Huduma>.<Kikoa>` ikiwa huduma inapatikana kutoka kwa watumishi wengi.

Zana ya `dns-sd` inaweza kutumika kwa **ugunduzi na matangazo ya huduma za mtandao**. Hapa kuna mifano ya matumizi yake:

### Kutafuta Huduma za SSH

Kutafuta huduma za SSH kwenye mtandao, tumia amri ifuatayo:
```bash
dns-sd -B _ssh._tcp
```
Amri hii inaanzisha utafutaji wa huduma za _ssh._tcp na kutoa maelezo kama vile muda, bendera, kiolesura, kikoa, aina ya huduma, na jina la kesi.

### Kutangaza Huduma ya HTTP

Ili kutangaza huduma ya HTTP, unaweza kutumia:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
Amri hii inasajili huduma ya HTTP iliyoitwa "Index" kwenye bandari 80 na njia ya `/index.html`.

Kisha kutafuta huduma za HTTP kwenye mtandao:
```bash
dns-sd -B _http._tcp
```
Wakati huduma inapoanza, inatangaza upatikanaji wake kwa vifaa vyote kwenye mtandao wa eneo kwa kutuma habari kwa wote. Vifaa vinavyopendezwa na huduma hizi havitaji kutuma maombi bali tu kusikiliza matangazo haya.

Kwa kiolesura cha mtumiaji rafiki zaidi, programu ya **Discovery - DNS-SD Browser** inapatikana kwenye Duka la App la Apple inaweza kuonyesha huduma zinazotolewa kwenye mtandao wako wa ndani.

Kwa upande mwingine, hati za desturi zinaweza kuandikwa ili kuvinjari na kugundua huduma kwa kutumia maktaba ya `python-zeroconf`. Hati ya [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) inaonyesha jinsi ya kuunda kivinjari cha huduma kwa huduma za `_http._tcp.local.`, kuchapisha huduma zilizoongezwa au kuondolewa:
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
### Kulemaza Bonjour
Ikiwa kuna wasiwasi kuhusu usalama au sababu nyingine za kulemaza Bonjour, inaweza kuzimwa kwa kutumia amri ifuatayo:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## Marejeo

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
