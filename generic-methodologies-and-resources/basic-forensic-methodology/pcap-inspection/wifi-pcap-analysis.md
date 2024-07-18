# Wifi Pcap Analysis

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Check BSSIDs

Unapopokea kukamata ambayo trafiki yake kuu ni Wifi ukitumia WireShark unaweza kuanza kuchunguza SSIDs zote za kukamata kwa kutumia _Wireless --> WLAN Traffic_:

![](<../../../.gitbook/assets/image (106).png>)

![](<../../../.gitbook/assets/image (492).png>)

### Brute Force

Moja ya nguzo za skrini hiyo inaonyesha kama **uthibitisho wowote ulipatikana ndani ya pcap**. Ikiwa hiyo ni hali unaweza kujaribu kuifanya Brute force kwa kutumia `aircrack-ng`:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
Kwa mfano, itapata WPA passphrase inayolinda PSK (pre shared-key), ambayo itahitajika kufungua trafiki baadaye.

## Data katika Beacons / Kituo cha Kando

Ikiwa unashuku kwamba **data inavuja ndani ya beacons za mtandao wa Wifi** unaweza kuangalia beacons za mtandao kwa kutumia chujio kama ifuatavyo: `wlan contains <NAMEofNETWORK>`, au `wlan.ssid == "NAMEofNETWORK"` tafuta ndani ya pakiti zilizochujwa kwa nyuzi za kutatanisha.

## Pata Anwani za MAC zisizojulikana katika Mtandao wa Wifi

Kiungo kinachofuata kitakuwa na manufaa kutafuta **mashine zinazotuma data ndani ya Mtandao wa Wifi**:

* `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Ikiwa tayari unajua **anwani za MAC unaweza kuondoa hizo kutoka kwa matokeo** ukiongeza ukaguzi kama huu: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Mara tu unapogundua **anwani za MAC zisizojulikana** zinazowasiliana ndani ya mtandao unaweza kutumia **vichujio** kama ifuatavyo: `wlan.addr==<MAC address> && (ftp || http || ssh || telnet)` kuchuja trafiki yake. Kumbuka kwamba vichujio vya ftp/http/ssh/telnet ni vya manufaa ikiwa umepata ufunguo wa trafiki.

## Fungua Trafiki

Hariri --> Mipendeleo --> Protokali --> IEEE 802.11--> Hariri

![](<../../../.gitbook/assets/image (499).png>)

{% hint style="success" %}
Jifunze & fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze & fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **fuata** sisi kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
