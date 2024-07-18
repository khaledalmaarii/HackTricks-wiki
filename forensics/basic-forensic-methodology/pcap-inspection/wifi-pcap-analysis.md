{% hint style="success" %}
Jifunze na zoezi la AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks ya Mtaalam wa Timu Nyekundu ya AWS (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na zoezi la GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks ya Mtaalam wa Timu Nyekundu ya GCP (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa michango**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}


# Angalia BSSIDs

Unapopokea kifaa cha kuchukua data ambacho trafiki yake kuu ni Wifi ukitumia WireShark unaweza kuanza uchunguzi wa SSIDs zote za kifaa hicho kwa kutumia _Wireless --> WLAN Traffic_:

![](<../../../.gitbook/assets/image (424).png>)

![](<../../../.gitbook/assets/image (425).png>)

## Brute Force

Moja ya safu za skrini hiyo inaonyesha ikiwa **uthibitisho wowote ulipatikana ndani ya pcap**. Ikiwa hivyo ndivyo, unaweza kujaribu kufanya Brute force kwa kutumia `aircrack-ng`:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
```markdown
Kwa mfano itapata neno la siri la WPA linalolinda PSK (pre shared-key), ambalo litahitajika kufichua trafiki baadaye.

# Data katika Beacons / Channel ya Upande

Ikiwa una shaka kwamba **data inavuja ndani ya beacons ya mtandao wa Wifi** unaweza kuangalia beacons ya mtandao kwa kutumia filter kama hii: `wlan contains <JINA laMTANDAO>`, au `wlan.ssid == "JINA laMTANDAO"` tafuta ndani ya pakiti zilizofanyiwa filter kwa herufi shahidi.

# Pata Anwani za MAC Zisizojulikana katika Mtandao wa Wifi

Kiungo kifuatacho kitakuwa muhimu kwa kupata **mashine zinazoingiza data ndani ya Mtandao wa Wifi**:

* `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Ikiwa tayari unajua **anwani za MAC unaweza kuziondoa kutoka kwa matokeo** kwa kuongeza ukaguzi kama huu: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Baada ya kugundua **anwani za MAC zisizojulikana** zinazotuma data ndani ya mtandao unaweza kutumia **filters** kama hii: `wlan.addr==<anwani ya MAC> && (ftp || http || ssh || telnet)` kufanya filter ya trafiki yake. Kumbuka kuwa filters za ftp/http/ssh/telnet ni muhimu ikiwa umefichua trafiki.

# Fichua Trafiki

Hariri --> Mapendeleo --> Itifaki --> IEEE 802.11--> Hariri

![](<../../../.gitbook/assets/image (426).png>)
```
