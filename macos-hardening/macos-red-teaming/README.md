# macOS Red Teaming

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Kutumia MDMs kwa Udukuzi

* JAMF Pro: `jamf checkJSSConnection`
* Kandji

Ikiwa unaweza **kudukua vibali vya admin** ili kupata ufikiaji wa jukwaa la usimamizi, unaweza **kudukua kompyuta zote** kwa kusambaza programu hasidi kwenye mashine.

Kwa timu nyekundu katika mazingira ya MacOS, ni muhimu sana kuwa na uelewa fulani wa jinsi MDMs wanavyofanya kazi:

{% content-ref url="macos-mdm/" %}
[macos-mdm](macos-mdm/)
{% endcontent-ref %}

### Kutumia MDM kama C2

MDM itakuwa na ruhusa ya kufunga, kuuliza au kuondoa maelezo ya usanidi, kufunga programu, kuunda akaunti za admin za ndani, kuweka nenosiri la firmware, kubadilisha ufunguo wa FileVault...

Ili kuendesha MDM yako mwenyewe, unahitaji **CSR yako isainiwe na muuzaji** ambayo unaweza kujaribu kupata kwa kutumia [**https://mdmcert.download/**](https://mdmcert.download/). Na ili kuendesha MDM yako mwenyewe kwa vifaa vya Apple, unaweza kutumia [**MicroMDM**](https://github.com/micromdm/micromdm).

Hata hivyo, ili kufunga programu kwenye kifaa kilichosajiliwa, bado unahitaji iwe isainiwe na akaunti ya msanidi programu... hata hivyo, baada ya usajili wa MDM, **kifaa huongeza cheti cha SSL cha MDM kama CA inayotegemewa**, kwa hivyo sasa unaweza kusaini chochote.

Ili kusajili kifaa kwenye MDM, unahitaji kufunga faili ya **`mobileconfig`** kama mizizi, ambayo inaweza kutolewa kupitia faili ya **pkg** (unaweza kuipunguza kwenye zip na wakati inapakuliwa kutoka safari itafunguliwa).

**Mawakala wa Mythic Orthrus** hutumia mbinu hii.

### Kudukua JAMF PRO

JAMF inaweza kukimbia **maandishi desturi** (maandishi yaliyoundwa na msimamizi wa mfumo), **malipo ya asili** (uundaji wa akaunti za ndani, kuweka nenosiri la EFI, ufuatiliaji wa faili/mchakato...) na **MDM** (usanidi wa kifaa, vyeti vya kifaa...).

#### Usajili wa JAMF mwenyewe

Nenda kwenye ukurasa kama `https://<jina-la-kampuni>.jamfcloud.com/enroll/` kuona ikiwa wana **usajili wa kujisajili wenyewe**. Ikiwa wana, inaweza **kuomba vibali vya ufikiaji**.

Unaweza kutumia maandishi [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) kufanya shambulio la kusambaza nywila.

Zaidi ya hayo, baada ya kupata vibali sahihi, unaweza kuwa na uwezo wa kuvunja nguvu majina mengine ya mtumiaji na fomu ifuatayo:

![](<../../.gitbook/assets/image (7) (1) (1).png>)

#### Uthibitishaji wa Kifaa cha JAMF

<figure><img src="../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Faili ya **`jamf`** ina siri ya kufungua keychain ambayo wakati wa ugunduzi ilikuwa **inashirikiwa** na kila mtu na ilikuwa: **`jk23ucnq91jfu9aj`**.\
Zaidi ya hayo, jamf **inadumu** kama **LaunchDaemon** katika **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### Kuchukua Udhibiti wa Kifaa cha JAMF

URL ya **JSS** (Jamf Software Server) ambayo **`jamf`** itatumia iko katika **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
Faili hii kimsingi ina URL:

{% code overflow="wrap" %}
```bash
plutil -convert xml1 -o - /Library/Preferences/com.jamfsoftware.jamf.plist

[...]
<key>is_virtual_machine</key>
<false/>
<key>jss_url</key>
<string>https://halbornasd.jamfcloud.com/</string>
<key>last_management_framework_change_id</key>
<integer>4</integer>
[...]
```
{% endcode %}

Hivyo, mshambuliaji anaweza kuweka pakiti mbaya (`pkg`) ambayo **inabadilisha faili hii** wakati inapowekwa na kuweka **URL kwa msikilizaji wa Mythic C2 kutoka kwa wakala wa Typhon** ili sasa iweze kutumia JAMF kama C2.

{% code overflow="wrap" %}
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
{% endcode %}

#### Udanganyifu wa JAMF

Ili **kuiga mawasiliano** kati ya kifaa na JMF unahitaji:

* **UUID** ya kifaa: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
* **JAMF keychain** kutoka: `/Library/Application\ Support/Jamf/JAMF.keychain` ambayo ina cheti cha kifaa

Ukiwa na habari hii, **unda VM** na **UUID** ya Vifaa **vilivyoibiwa** na **SIP imezimwa**, weka **JAMF keychain,** **funga** Jamf **agent** na ibebe habari zake.

#### Wizi wa Siri

<figure><img src="../../.gitbook/assets/image (11).png" alt=""><figcaption><p>a</p></figcaption></figure>

Pia unaweza kufuatilia eneo `/Library/Application Support/Jamf/tmp/` kwa **script za desturi** ambazo wahariri wanaweza kutaka kutekeleza kupitia Jamf kwani zinawekwa hapa, kutekelezwa na kuondolewa. Hizi script **zinaweza kuwa na siri**.

Hata hivyo, **siri** inaweza kupitishwa kwa njia ya script hizi kama **parameta**, kwa hivyo utahitaji kufuatilia `ps aux | grep -i jamf` (hata bila kuwa na ruhusa ya msingi).

Script [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) inaweza kusikiliza faili mpya zinazoongezwa na hoja mpya za mchakato.

### Upatikanaji wa Mbali wa macOS

Na pia kuhusu **itifaki za mtandao** za "maalum" za **MacOS**:

{% content-ref url="../macos-security-and-privilege-escalation/macos-protocols.md" %}
[macos-protocols.md](../macos-security-and-privilege-escalation/macos-protocols.md)
{% endcontent-ref %}

## Active Directory

Katika hali fulani utagundua kuwa **kompyuta ya MacOS imeunganishwa na AD**. Katika hali hii unapaswa kujaribu **kuorodhesha** active directory kama ulivyozoea. Pata **msaada** katika kurasa zifuatazo:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/active-directory-methodology/" %}
[active-directory-methodology](../../windows-hardening/active-directory-methodology/)
{% endcontent-ref %}

{% content-ref url="../../network-services-pentesting/pentesting-kerberos-88/" %}
[pentesting-kerberos-88](../../network-services-pentesting/pentesting-kerberos-88/)
{% endcontent-ref %}

Zana ya **lokal** ya MacOS ambayo inaweza kukusaidia pia ni `dscl`:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
Pia kuna zana kadhaa zilizoandaliwa kwa MacOS kwa kuchunguza moja kwa moja AD na kucheza na kerberos:

* [**Machound**](https://github.com/XMCyber/MacHound): MacHound ni nyongeza ya zana ya ukaguzi ya Bloodhound inayoruhusu kukusanya na kuingiza uhusiano wa Active Directory kwenye vifaa vya MacOS.
* [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost ni mradi wa Objective-C ulioundwa kuingiliana na Heimdal krb5 APIs kwenye macOS. lengo la mradi ni kuwezesha ukaguzi bora wa usalama kuhusu Kerberos kwenye vifaa vya macOS kwa kutumia APIs za asili bila kuhitaji fremu au pakiti nyingine kwenye lengo.
* [**Orchard**](https://github.com/its-a-feature/Orchard): Zana ya JavaScript for Automation (JXA) kufanya uchunguzi wa Active Directory. 

### Taarifa za Kikoa
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Watumiaji

Kuna aina tatu za watumiaji wa MacOS:

* **Watumiaji wa Ndani** - Wanadhibitiwa na huduma ya OpenDirectory ya ndani, hawana uhusiano wowote na Active Directory.
* **Watumiaji wa Mtandao** - Watumiaji wa muda mfupi wa Active Directory ambao wanahitaji kuunganishwa na seva ya DC ili kuthibitisha kitambulisho chao.
* **Watumiaji wa Simu** - Watumiaji wa Active Directory na nakala ya kuhifadhi ya ndani kwa kitambulisho chao na faili zao.

Maelezo ya ndani kuhusu watumiaji na vikundi huhifadhiwa katika folda _/var/db/dslocal/nodes/Default._\
Kwa mfano, maelezo kuhusu mtumiaji anayeitwa _mark_ huhifadhiwa katika _/var/db/dslocal/nodes/Default/users/mark.plist_ na maelezo kuhusu kikundi _admin_ yako katika _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Mbali na kutumia uhusiano wa HasSession na AdminTo, **MacHound inaongeza uhusiano mpya wa CanSSH, CanVNC, na CanAE** kwenye database ya Bloodhound:

* **CanSSH** - kifaa kinachoruhusiwa kufanya SSH kwenye mwenyeji
* **CanVNC** - kifaa kinachoruhusiwa kufanya VNC kwenye mwenyeji
* **CanAE** - kifaa kinachoruhusiwa kutekeleza hati za AppleEvent kwenye mwenyeji
```bash
#User enumeration
dscl . ls /Users
dscl . read /Users/[username]
dscl "/Active Directory/TEST/All Domains" ls /Users
dscl "/Active Directory/TEST/All Domains" read /Users/[username]
dscacheutil -q user

#Computer enumeration
dscl "/Active Directory/TEST/All Domains" ls /Computers
dscl "/Active Directory/TEST/All Domains" read "/Computers/[compname]$"

#Group enumeration
dscl . ls /Groups
dscl . read "/Groups/[groupname]"
dscl "/Active Directory/TEST/All Domains" ls /Groups
dscl "/Active Directory/TEST/All Domains" read "/Groups/[groupname]"

#Domain Information
dsconfigad -show
```
Maelezo zaidi katika [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)

## Kupata Ufikiaji wa Keychain

Keychain ina uwezekano mkubwa wa kuwa na habari nyeti ambayo ikiwa itapata ufikiaji bila kutoa onyo inaweza kusaidia katika kutekeleza zoezi la timu nyekundu:

{% content-ref url="macos-keychain.md" %}
[macos-keychain.md](macos-keychain.md)
{% endcontent-ref %}

## Huduma za Nje

Utekelezaji wa Timu Nyekundu wa MacOS ni tofauti na Utekelezaji wa Timu Nyekundu wa kawaida wa Windows kwa sababu kawaida **MacOS imeunganishwa na majukwaa kadhaa ya nje moja kwa moja**. Usanidi wa kawaida wa MacOS ni kupata kompyuta kwa kutumia **sifa zilizosawazishwa za OneLogin, na kupata huduma kadhaa za nje** (kama vile github, aws...) kupitia OneLogin.

## Mbinu Mbalimbali za Timu Nyekundu

### Safari

Wakati faili inapakuliwa kwenye Safari, ikiwa ni faili "salama", itafunguliwa **kiotomatiki**. Kwa hivyo, kwa mfano, ikiwa **unapakua zip**, itafunguliwa kiotomatiki:

<figure><img src="../../.gitbook/assets/image (12) (3).png" alt=""><figcaption></figcaption></figure>

## Marejeo

* [**https://www.youtube.com/watch?v=IiMladUbL6E**](https://www.youtube.com/watch?v=IiMladUbL6E)
* [**https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6**](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
* [**https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0**](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
* [**Come to the Dark Side, We Have Apples: Turning macOS Management Evil**](https://www.youtube.com/watch?v=pOQOh07eMxY)
* [**OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall**](https://www.youtube.com/watch?v=ju1IYWUv4ZA)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
