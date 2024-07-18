# Kufanya Udukuzi wa Red Teaming kwenye macOS

{% hint style="success" %}
Jifunze na zoea Udukuzi wa AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks kwa Wataalamu wa Timu Nyekundu ya AWS (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na zoea Udukuzi wa GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks kwa Wataalamu wa Timu Nyekundu ya GCP (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}

## Kutumia MDMs kwa Udukuzi

* JAMF Pro: `jamf checkJSSConnection`
* Kandji

Ikiwa unafanikiwa **kudukua vibali vya msimamizi** ili kupata upatikanaji wa jukwaa la usimamizi, unaweza **kudukua kompyuta zote** kwa kusambaza zisizo programu hasidi kwenye mashine.

Kwa red teaming katika mazingira ya MacOS, ni vyema kuwa na uelewa fulani wa jinsi MDMs zinavyofanya kazi:

{% content-ref url="macos-mdm/" %}
[macos-mdm](macos-mdm/)
{% endcontent-ref %}

### Kutumia MDM kama C2

MDM itakuwa na idhini ya kufunga, kuuliza au kuondoa maelezo, kufunga programu, kuunda akaunti za msimamizi wa ndani, kuweka nenosiri la firmware, kubadilisha ufunguo wa FileVault...

Ili kuendesha MDM yako mwenyewe unahitaji **CSR yako isainiwe na muuzaji** ambayo unaweza kujaribu kupata kwa kutumia [**https://mdmcert.download/**](https://mdmcert.download/). Na ili kuendesha MDM yako mwenyewe kwa vifaa vya Apple unaweza kutumia [**MicroMDM**](https://github.com/micromdm/micromdm).

Hata hivyo, ili kufunga programu kwenye kifaa kilichojiandikisha, bado unahitaji iwe imesainiwa na akaunti ya mwandishi... hata hivyo, baada ya usajili wa MDM **kifaa huongeza cheti cha SSL cha MDM kama CA inayoweza kudhibitika**, hivyo sasa unaweza kusaini chochote.

Ili kujiandikisha kifaa kwenye MDM unahitaji kufunga faili ya **`mobileconfig`** kama root, ambayo inaweza kutolewa kupitia faili ya **pkg** (unaweza kuipachika kwenye zip na unapoidownload kutoka safari itaondolewa kwenye zip).

**Mawakala wa Mythic Orthrus** hutumia mbinu hii.

### Kutumia JAMF PRO vibaya

JAMF inaweza kuendesha **maandishi ya desturi** (maandishi yaliyotengenezwa na msimamizi wa mfumo), **mizigo ya asili** (uundaji wa akaunti za ndani, kuweka nenosiri la EFI, ufuatiliaji wa faili/mchakato...) na **MDM** (mipangilio ya kifaa, vyeti vya kifaa...).

#### Usajili wa kujisajili wa JAMF

Nenda kwenye ukurasa kama vile `https://<jina-la-kampuni>.jamfcloud.com/enroll/` kuona ikiwa wana **ruhusa ya kujisajili wenyewe**. Ikiwa wana inaweza **kuomba vibali vya kupata**.

Unaweza kutumia maandishi [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) kufanya shambulio la kunyunyizia nenosiri.

Zaidi ya hayo, baada ya kupata vibali sahihi unaweza kuwa na uwezo wa kuvunja nguvu majina mengine ya mtumiaji na fomu ifuatayo:

![](<../../.gitbook/assets/image (107).png>)

#### Uthibitishaji wa Kifaa cha JAMF

<figure><img src="../../.gitbook/assets/image (167).png" alt=""><figcaption></figcaption></figure>

Faili ya **`jamf`** iliyomo siri ya kufungua keychain ambayo wakati wa ugunduzi ilikuwa **inashirikiwa** na kila mtu na ilikuwa: **`jk23ucnq91jfu9aj`**.\
Zaidi ya hayo, jamf **inaendelea** kama **LaunchDaemon** katika **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### Kuchukua Udhibiti wa Kifaa cha JAMF

URL ya **JSS** (Jamf Software Server) ambayo **`jamf`** itatumia iko katika **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
Faili hii kimsingi ina URL:
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

Kwa hivyo, mshambuliaji anaweza kuweka pakiti ya madhara (`pkg`) ambayo **inaandika upya faili hii** wakati inapowekwa kwa kuweka **URL kwa msikilizaji wa Mythic C2 kutoka kwa wakala wa Typhon** sasa kuweza kutumia JAMF kama C2.
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
{% endcode %}

#### Uigizaji wa JAMF

Ili **kuiga mawasiliano** kati ya kifaa na JMF unahitaji:

* **UUID** ya kifaa: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
* **Kifunguo cha JAMF** kutoka: `/Library/Application\ Support/Jamf/JAMF.keychain` ambayo ina cheti cha kifaa

Ukiwa na habari hizi, **unda VM** na **UUID iliyoporwa** ya Vifaa na **SIP imelemazwa**, achia **Kifunguo cha JAMF,** **unganishe** agizo la Jamf na ibebe habari zake.

#### Uibaji wa Siri

<figure><img src="../../.gitbook/assets/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

Unaweza pia kufuatilia eneo `/Library/Application Support/Jamf/tmp/` kwa **maandishi ya desturi** ambayo wasimamizi wanaweza kutaka kutekeleza kupitia Jamf kwani yanawekwa hapa, kutekelezwa na kuondolewa. Maandishi haya **yanaweza kuwa na siri**.

Hata hivyo, **siri** inaweza kupitishwa kupitia maandishi haya kama **parameta**, hivyo unahitaji kufuatilia `ps aux | grep -i jamf` (bila hata kuwa na mizizi).

Skripti [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) inaweza kusikiliza faili mpya zinazoongezwa na hoja mpya za mchakato.

### Upatikanaji wa Mbali wa macOS

Na pia kuhusu **itifaki** za **mtandao** za **"maalum" za MacOS**:

{% content-ref url="../macos-security-and-privilege-escalation/macos-protocols.md" %}
[macos-protocols.md](../macos-security-and-privilege-escalation/macos-protocols.md)
{% endcontent-ref %}

## Active Directory

Katika baadhi ya matukio utagundua kuwa **kompyuta ya MacOS imeunganishwa na AD**. Katika hali hii unapaswa kujaribu **kuorodhesha** active directory kama ulivyoizoea. Pata **msaada** katika kurasa zifuatazo:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/active-directory-methodology/" %}
[active-directory-methodology](../../windows-hardening/active-directory-methodology/)
{% endcontent-ref %}

{% content-ref url="../../network-services-pentesting/pentesting-kerberos-88/" %}
[pentesting-kerberos-88](../../network-services-pentesting/pentesting-kerberos-88/)
{% endcontent-ref %}

Zana ya **lokalini ya MacOS** ambayo inaweza pia kukusaidia ni `dscl`:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
Pia kuna zana zilizoandaliwa kwa MacOS kwa kuchunguza moja kwa moja AD na kucheza na kerberos:

* [**Machound**](https://github.com/XMCyber/MacHound): MacHound ni nyongeza ya zana ya ukaguzi wa Bloodhound inayoruhusu kukusanya na kuingiza mahusiano ya Active Directory kwenye mwenyeji wa MacOS.
* [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost ni mradi wa Objective-C ulioundwa kuingiliana na APIs za Heimdal krb5 kwenye macOS. Lengo la mradi huu ni kuwezesha upimaji bora wa usalama kuhusu Kerberos kwenye vifaa vya macOS kwa kutumia APIs za asili bila kuhitaji mfumo mwingine au pakiti yoyote kwenye lengo.
* [**Orchard**](https://github.com/its-a-feature/Orchard): Zana ya JavaScript for Automation (JXA) kufanya uchunguzi wa Active Directory.
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Watumiaji

Aina tatu za watumiaji wa MacOS ni:

- **Watumiaji wa Ndani** - Wanasimamiwa na huduma ya OpenDirectory ya ndani, hawajaunganishwa kwa njia yoyote na Active Directory.
- **Watumiaji wa Mtandao** - Watumiaji wa Active Directory wa muda wanaohitaji kuunganishwa kwa seva ya DC ili kuthibitisha.
- **Watumiaji wa Simu** - Watumiaji wa Active Directory wenye nakala rudufu ya ndani kwa ajili ya vitambulisho vyao na faili zao.

Maelezo ya ndani kuhusu watumiaji na vikundi hufanywa katika folda _/var/db/dslocal/nodes/Default._ Kwa mfano, maelezo kuhusu mtumiaji anayeitwa _mark_ hufanywa katika _/var/db/dslocal/nodes/Default/users/mark.plist_ na maelezo kuhusu kikundi _admin_ yapo katika _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Mbali na kutumia HasSession na AdminTo edges, **MacHound huongeza makali matatu mapya** kwenye database ya Bloodhound:

- **InawezaSSH** - kifaa kinachoruhusiwa kufanya SSH kwa mwenyeji
- **InawezaVNC** - kifaa kinachoruhusiwa kufanya VNC kwa mwenyeji
- **InawezaAE** - kifaa kinachoruhusiwa kutekeleza skripti za AppleEvent kwenye mwenyeji
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
More info in [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)

## Kupata Ufikiaji wa Keychain

Keychain ina uwezekano mkubwa wa kuwa na habari nyeti ambazo zikipatikana bila kutoa ombi la kuthibitisha zinaweza kusaidia katika kuendeleza zoezi la timu nyekundu:

{% content-ref url="macos-keychain.md" %}
[macos-keychain.md](macos-keychain.md)
{% endcontent-ref %}

## Huduma za Nje

Kuunda Timu Nyekundu ya MacOS ni tofauti na Timu Nyekundu ya kawaida ya Windows kwa kawaida **MacOS imeunganishwa na majukwaa kadhaa ya nje moja kwa moja**. Mazingira ya kawaida ya MacOS ni kupata kompyuta kwa kutumia **sifa zilizosawazishwa za OneLogin, na kupata huduma kadhaa za nje** (kama vile github, aws...) kupitia OneLogin.

## Mbinu za Timu Nyekundu za Kitaalam

### Safari

Wakati faili inapakuliwa kwenye Safari, ikiwa ni faili "salama", ita **funguliwa moja kwa moja**. Kwa mfano, ikiwa **unapakua zip**, itafunguliwa moja kwa moja:

<figure><img src="../../.gitbook/assets/image (226).png" alt=""><figcaption></figcaption></figure>

## Marejeo

* [**https://www.youtube.com/watch?v=IiMladUbL6E**](https://www.youtube.com/watch?v=IiMladUbL6E)
* [**https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6**](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
* [**https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0**](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
* [**Come to the Dark Side, We Have Apples: Turning macOS Management Evil**](https://www.youtube.com/watch?v=pOQOh07eMxY)
* [**OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall**](https://www.youtube.com/watch?v=ju1IYWUv4ZA)

{% hint style="success" %}
Jifunze & zoezi Hacking ya AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks ya Mtaalam wa Timu Nyekundu ya AWS (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze & zoezi Hacking ya GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks ya Mtaalam wa Timu Nyekundu ya GCP (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa michango**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
