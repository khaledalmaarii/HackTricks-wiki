<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inayotangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>


# Angalia BSSIDs

Unapopokea kuchukua ambayo trafiki kuu ni Wifi ukitumia WireShark, unaweza kuanza uchunguzi wa SSIDs zote za kuchukua na _Wireless --> WLAN Traffic_:

![](<../../../.gitbook/assets/image (424).png>)

![](<../../../.gitbook/assets/image (425).png>)

## Brute Force

Moja ya nguzo za skrini hiyo inaonyesha ikiwa **uthibitisho wowote ulipatikana ndani ya pcap**. Ikiwa hivyo ndivyo, unaweza kujaribu kudukua kwa kutumia `aircrack-ng`:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
Kwa mfano, itapata neno la siri la WPA linalolinda PSK (pre shared-key), ambalo litahitajika kufichua trafiki baadaye.

# Data katika Beacons / Side Channel

Ikiwa una shaka kwamba **data inavuja ndani ya beacons ya mtandao wa Wifi**, unaweza kuangalia beacons za mtandao kwa kutumia filter kama ifuatavyo: `wlan contains <JINA LA MTANDAO>`, au `wlan.ssid == "JINA LA MTANDAO"` tafuta ndani ya pakiti zilizofanyiwa filter kwa herufi za mashaka.

# Tafuta Anwani za MAC Isiyojulikana katika Mtandao wa Wifi

Kiungo kifuatacho kitakuwa cha manufaa kupata **mashine zinazotuma data ndani ya Mtandao wa Wifi**:

* `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Ikiwa tayari unajua **anwani za MAC unaweza kuziondoa kutoka kwa matokeo** kwa kuongeza ukaguzi kama huu: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Baada ya kugundua **anwani za MAC zisizojulikana** zinazoshirikiana ndani ya mtandao, unaweza kutumia **filters** kama ifuatavyo: `wlan.addr==<Anwani ya MAC> && (ftp || http || ssh || telnet)` kuchuja trafiki yake. Kumbuka kuwa filters za ftp/http/ssh/telnet ni muhimu ikiwa umefichua trafiki.

# Fichua Trafiki

Edit --> Preferences --> Protocols --> IEEE 802.11--> Edit

![](<../../../.gitbook/assets/image (426).png>)





<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
