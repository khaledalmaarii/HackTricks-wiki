# Uchambuzi wa Pcap ya Wifi

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Angalia BSSIDs

Unapopokea kichwa ambacho trafiki kuu ni ya Wifi ukitumia WireShark unaweza kuanza kuchunguza SSIDs zote za kichwa hicho na _Wireless --> WLAN Traffic_:

![](<../../../.gitbook/assets/image (103).png>)

![](<../../../.gitbook/assets/image (489).png>)

### Brute Force

Moja ya nguzo za skrini hiyo inaonyesha ikiwa **uthibitisho wowote ulipatikana ndani ya pcap**. Ikiwa hivyo ndivyo, unaweza kujaribu kufanya Brute force kwa kutumia `aircrack-ng`:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
## Data katika Beacons / Channel ya Upande

Ikiwa una shaka kwamba **data inavuja ndani ya beacons ya mtandao wa Wifi** unaweza kuangalia beacons ya mtandao kwa kutumia filter kama hii: `wlan contains <JINA LA MTANDAO>`, au `wlan.ssid == "JINA LA MTANDAO"` tafuta ndani ya pakiti zilizofanyiwa filter kwa strings za shaka.

## Pata Anwani za MAC Zisizojulikana kwenye Mtandao wa Wifi

Kiungo kifuatacho kitakuwa muhimu kwa kutafuta **mashine zinazoingiza data ndani ya Mtandao wa Wifi**:

* `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Ikiwa tayari unajua **anwani za MAC unaweza kuziondoa kutoka kwa matokeo** kwa kuongeza ukaguzi kama huu: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Baada ya kugundua **anwani za MAC zisizojulikana** zinazotuma data ndani ya mtandao unaweza kutumia **filters** kama hii: `wlan.addr==<anwani ya MAC> && (ftp || http || ssh || telnet)` kufanya filter ya trafiki yake. Kumbuka kwamba filters za ftp/http/ssh/telnet ni muhimu ikiwa umedecrypt trafiki.

## Decrypt Trafiki

Hariri --> Mapendeleo --> Itifaki --> IEEE 802.11--> Hariri

![](<../../../.gitbook/assets/image (496).png>)

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
