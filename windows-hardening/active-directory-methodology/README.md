# Metodologija Active Directory

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJATELJE**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## Osnovni pregled

**Active Directory** služi kao osnovna tehnologija, omogućavajući **mrežnim administratorima** efikasno kreiranje i upravljanje **domenima**, **korisnicima** i **objektima** unutar mreže. Projektovan je da se skalira, olakšavajući organizaciju velikog broja korisnika u upravljive **grupe** i **podgrupe**, dok kontroliše **prava pristupa** na različitim nivoima.

Struktura **Active Directory-ja** se sastoji od tri osnovna sloja: **domeni**, **stablo** i **šume**. **Domen** obuhvata kolekciju objekata, kao što su **korisnici** ili **uređaji**, koji dele zajedničku bazu podataka. **Stabla** su grupe ovih domena povezanih zajedničkom strukturom, a **šuma** predstavlja kolekciju više stabala, povezanih putem **poverenja**, formirajući najviši sloj organizacione strukture. Specifična **prava pristupa** i **komunikacije** mogu biti određena na svakom od ovih nivoa.

Ključni koncepti unutar **Active Directory-ja** uključuju:

1. **Direktorijum** – Sadrži sve informacije koje se odnose na objekte Active Directory-ja.
2. **Objekat** – Označava entitete unutar direktorijuma, uključujući **korisnike**, **grupe** ili **deljene fascikle**.
3. **Domen** – Služi kao kontejner za direktorijumske objekte, sa mogućnošću da više domena koegzistira unutar **šume**, svaki održavajući svoju kolekciju objekata.
4. **Stablo** – Grupisanje domena koji dele zajednički korenski domen.
5. **Šuma** – Vrhunac organizacione strukture u Active Directory-ju, sastavljena od nekoliko stabala sa **poverenjima** među njima.

**Active Directory Domain Services (AD DS)** obuhvataju niz usluga ključnih za centralizovano upravljanje i komunikaciju unutar mreže. Ove usluge obuhvataju:

1. **Domen usluge** – Centralizuje skladištenje podataka i upravlja interakcijama između **korisnika** i **domena**, uključujući **autentifikaciju** i **pretragu**.
2. **Usluge sertifikata** – Nadgleda kreiranje, distribuciju i upravljanje sigurnim **digitalnim sertifikatima**.
3. **Usluge lakog direktorijuma** – Podržava aplikacije sa omogućenim direktorijumom putem **LDAP protokola**.
4. **Usluge federacije direktorijuma** – Pruža mogućnosti **jednokratne prijave** za autentifikaciju korisnika preko više veb aplikacija u jednoj sesiji.
5. **Upravljanje pravima** – Pomaže u zaštiti autorskih materijala regulišući njihovu neovlaštenu distribuciju i upotrebu.
6. **DNS usluga** – Ključna za razrešenje **imenâ domena**.

Za detaljnije objašnjenje pogledajte: [**TechTerms - Definicija Active Directory-ja**](https://techterms.com/definition/active\_directory)

### **Kerberos Autentikacija**

Da biste naučili kako **napasti AD** morate dobro da razumete **proces Kerberos autentikacije**.\
[**Pročitajte ovu stranicu ako još uvek ne znate kako funkcioniše.**](kerberos-authentication.md)

## Cheat Sheet

Možete posetiti [https://wadcoms.github.io/](https://wadcoms.github.io) da biste brzo videli koje komande možete pokrenuti za enumeraciju/eksploataciju AD-a.

## Rekon Active Directory (Bez kredencijala/sesija)

Ako imate pristup okruženju AD-a, ali nemate nikakve kredencijale/sesije, možete:

* **Pentestirati mrežu:**
* Skenirajte mrežu, pronađite mašine i otvorene portove i pokušajte **eksploatisati ranjivosti** ili **izvući kredencijale** sa njih (na primer, [štampači mogu biti veoma interesantni ciljevi](ad-information-in-printers.md).
* Enumeracija DNS-a može pružiti informacije o ključnim serverima u domenu kao što su veb, štampači, deljenja, VPN, mediji, itd.
* `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
* Pogledajte opštu [**Metodologiju Pentestiranja**](../../generic-methodologies-and-resources/pentesting-methodology.md) da biste saznali više o tome kako to uraditi.
* **Proverite null i Guest pristup na smb servisima** (ovo neće raditi na modernim verzijama Windows-a):
* `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
* `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
* `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
* Detaljniji vodič o tome kako enumerisati SMB server možete pronaći ovde:

{% content-ref url="../../network-services-pentesting/pentesting-smb/" %}
[pentesting-smb](../../network-services-pentesting/pentesting-smb/)
{% endcontent-ref %}

* **Enumeracija Ldap-a**
* `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
* Detaljniji vodič o tome kako enumerisati LDAP možete pronaći ovde (posebno obratite **pažnju na anoniman pristup**):

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

* **Trovanje mreže**
* Prikupite kredencijale [**impersonirajući servise sa Responder-om**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
* Pristupite hostu zloupotrebom [**relay napada**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
* Prikupite kredencijale **izlažući** [**lažne UPnP servise sa evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
* [**OSINT**](https://book.hacktricks.xyz/external-recon-methodology):
* Izvucite korisnička imena/ime sa internih dokumenata, društvenih medija, servisa (uglavnom veb) unutar okruženja domena i takođe iz javno dostupnih.
* Ako pronađete kompletne nazive radnika kompanije, možete probati različite AD **konvencije korisničkog imena (**[**pročitajte ovo**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Najčešće konvencije su: _ImePrezime_, _Ime.Prezime_, _ImePre_ (3 slova svako), _Ime.Prez_, _IPrezime_, _I.Prezime_, _PrezimeIme_, _Prezime.Ime_, _PrezimeI_, _Prezime.I_, 3 _slučajna slova i 3 slučajna broja_ (abc123).
* Alati:
* [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
* [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)
### Enumeracija korisnika

* **Anonimno SMB/LDAP nabrajanje:** Proverite [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/) i [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) stranice.
* **Kerbrute nabrajanje**: Kada se zatraži **neispravno korisničko ime**, server će odgovoriti koristeći **Kerberos grešku** kod _KRB5KDC\_ERR\_C\_PRINCIPAL\_UNKNOWN_, što nam omogućava da utvrdimo da je korisničko ime neispravno. **Ispravna korisnička imena** će izazvati ili **TGT u AS-REP** odgovoru ili grešku _KRB5KDC\_ERR\_PREAUTH\_REQUIRED_, što ukazuje da je korisniku potrebno izvršiti preautentikaciju.
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
```
* **OWA (Outlook Web Access) Server**

Ako pronađete jedan od ovih servera u mreži, takođe možete izvršiti **enumeraciju korisnika protiv njega**. Na primer, možete koristiti alat [**MailSniper**](https://github.com/dafthack/MailSniper):
```bash
ipmo C:\Tools\MailSniper\MailSniper.ps1
# Get info about the domain
Invoke-DomainHarvestOWA -ExchHostname [ip]
# Enumerate valid users from a list of potential usernames
Invoke-UsernameHarvestOWA -ExchHostname [ip] -Domain [domain] -UserList .\possible-usernames.txt -OutFile valid.txt
# Password spraying
Invoke-PasswordSprayOWA -ExchHostname [ip] -UserList .\valid.txt -Password Summer2021
# Get addresses list from the compromised mail
Get-GlobalAddressList -ExchHostname [ip] -UserName [domain]\[username] -Password Summer2021 -OutFile gal.txt
```
{% hint style="warning" %}
Možete pronaći liste korisničkih imena na [**ovom github repozitorijumu**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) i ovom ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).

Međutim, trebalo bi da imate **ime osoba koje rade u kompaniji** iz koraka istraživanja koje biste trebali da obavite pre ovoga. Sa imenom i prezimenom možete koristiti skriptu [**namemash.py**](https://gist.github.com/superkojiman/11076951) da generišete potencijalno validna korisnička imena.
{% endhint %}

### Poznavanje jednog ili više korisničkih imena

Dakle, znate da već imate validno korisničko ime ali ne i lozinke... Zatim pokušajte:

* [**ASREPRoast**](asreproast.md): Ako korisnik **nema** atribut _DONT\_REQ\_PREAUTH_, možete **zahtevati AS\_REP poruku** za tog korisnika koja će sadržati neke podatke enkriptovane derivatom lozinke korisnika.
* [**Password Spraying**](password-spraying.md): Pokušajte sa **najčešćim lozinkama** sa svakim otkrivenim korisnikom, možda neki korisnik koristi lošu lozinku (imajte na umu politiku lozinke!).
* Imajte na umu da takođe možete **prskati OWA servere** da biste pokušali da pristupite poštanskim serverima korisnika.

{% content-ref url="password-spraying.md" %}
[password-spraying.md](password-spraying.md)
{% endcontent-ref %}

### LLMNR/NBT-NS Trovanje

Možda ćete moći **dobiti** neke izazovne **hešove** za pucanje **trovanjem** nekih protokola **mreže**:

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

### NTML Prenos

Ako ste uspeli da nabrojite aktivni direktorijum, imaćete **više emailova i bolje razumevanje mreže**. Možda ćete moći da izvedete NTML [**prenosne napade**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) da biste pristupili AD okruženju.

### Ukradi NTLM podatke

Ako možete **pristupiti drugim računarima ili deljenim resursima** sa **null ili gost korisnikom**, možete **postaviti datoteke** (poput SCF datoteke) koje će, ako se na neki način pristupe, **pokrenuti NTML autentikaciju prema vama** tako da možete **ukrasti** **NTLM izazov** da ga puknete:

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

## Nabrojavanje aktivnog direktorijuma SA akreditacijama/sesijom

Za ovu fazu morate **kompromitovati akreditacije ili sesiju validnog domenskog naloga.** Ako imate neke validne akreditacije ili shell kao domenski korisnik, **trebalo bi da zapamtite da su opcije date ranije i dalje opcije za kompromitovanje drugih korisnika**.

Pre početka autentifikovanog nabrojavanja trebalo bi da znate šta je **Kerberos problem dvostrukog skoka**.

{% content-ref url="kerberos-double-hop-problem.md" %}
[kerberos-double-hop-problem.md](kerberos-double-hop-problem.md)
{% endcontent-ref %}

### Nabrojavanje

Imati kompromitovan nalog je **veliki korak za početak kompromitovanja celog domena**, jer ćete moći da započnete **Nabrojavanje aktivnog direktorijuma:**

Što se tiče [**ASREPRoast**](asreproast.md) sada možete pronaći svakog mogućeg ranjivog korisnika, a što se tiče [**Password Spraying**](password-spraying.md) možete dobiti **listu svih korisničkih imena** i probati lozinku kompromitovanog naloga, prazne lozinke i nove obećavajuće lozinke.

* Možete koristiti [**CMD za obavljanje osnovnog istraživanja**](../basic-cmd-for-pentesters.md#domain-info)
* Možete takođe koristiti [**powershell za istraživanje**](../basic-powershell-for-pentesters/) što će biti prikrivenije
* Možete takođe [**koristiti powerview**](../basic-powershell-for-pentesters/powerview.md) da izvučete detaljnije informacije
* Još jedan neverovatan alat za istraživanje u aktivnom direktorijumu je [**BloodHound**](bloodhound.md). Nije baš prikriven (zavisno o metodama prikupljanja koje koristite), ali **ako vam to nije važno**, svakako ga isprobajte. Pronađite gde korisnici mogu da RDP-uju, pronađite put do drugih grupa, itd.
* **Drugi automatizovani alati za nabrojavanje AD-a su:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
* [**DNS zapisi AD-a**](ad-dns-records.md) jer mogu sadržati zanimljive informacije.
* Alat sa **GUI-em** koji možete koristiti za nabrojavanje direktorijuma je **AdExplorer.exe** iz **SysInternal** Suite-a.
* Takođe možete pretraživati LDAP bazu podataka sa **ldapsearch** da biste tražili akreditacije u poljima _userPassword_ & _unixUserPassword_, ili čak u _Description_. cf. [Lozinka u komentaru AD korisnika na PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) za druge metode.
* Ako koristite **Linux**, takođe možete nabrojati domen koristeći [**pywerview**](https://github.com/the-useless-one/pywerview).
* Takođe možete probati automatizovane alate kao:
* [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
* [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
*   **Izdvajanje svih korisnika domena**

Veoma je lako dobiti sva korisnička imena domena sa Windows-om (`net user /domain`, `Get-DomainUser` ili `wmic useraccount get name,sid`). Na Linux-u, možete koristiti: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ili `enum4linux -a -u "user" -p "password" <DC IP>`

> Iako odeljak o Nabrojavanju izgleda mali, to je najvažniji deo svega. Pristupite linkovima (pre svega onom za cmd, powershell, powerview i BloodHound), naučite kako da nabrojite domen i vežbajte dok se ne osećate sigurno. Tokom procene, ovo će biti ključni trenutak za pronalaženje puta do DA ili odlučivanje da se ništa ne može uraditi.

### Kerberoast

Kerberoasting uključuje dobijanje **TGS karata** koje koriste usluge povezane sa korisničkim nalozima i pucanje njihove enkripcije—koja se zasniva na korisničkim lozinkama—**offline**.

Više o tome u:

{% content-ref url="kerberoast.md" %}
[kerberoast.md](kerberoast.md)
{% endcontent-ref %}
### Udaljena veza (RDP, SSH, FTP, Win-RM, itd)

Kada ste dobili određene akreditive, možete proveriti da li imate pristup bilo kojoj **mašini**. Za tu svrhu, možete koristiti **CrackMapExec** da biste pokušali povezivanje na nekoliko servera sa različitim protokolima, u skladu sa skeniranjem portova.

### Eskalacija lokalnih privilegija

Ako ste kompromitovali akreditive ili sesiju kao običan korisnik domena i imate **pristup** sa ovim korisnikom na **bilo kojoj mašini u domenu**, trebalo bi da pokušate da pronađete način da **eskališete privilegije lokalno i pretražujete akreditive**. To je zato što ćete samo sa lokalnim administratorskim privilegijama moći da **izvučete heševe drugih korisnika** iz memorije (LSASS) i lokalno (SAM).

Postoji kompletan odeljak u ovoj knjizi o [**eskalciji lokalnih privilegija u Windows-u**](../windows-local-privilege-escalation/) i [**checklista**](../checklist-windows-privilege-escalation.md). Takođe, ne zaboravite da koristite [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Trenutne sesijske ulaznice

Vrlo je **maloverovatno** da ćete pronaći **ulaznice** u trenutnom korisniku **koje vam daju dozvolu za pristup** neočekivanim resursima, ali možete proveriti:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTML Prenos

Ako ste uspeli da nabrojite aktivni direktorijum, imaćete **više mejlova i bolje razumevanje mreže**. Možda ćete moći da izvršite NTML [**prenos napada**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### **Traženje Kredencijala u Deljenim Računarima**

Sada kada imate neke osnovne kredencijale, trebalo bi da proverite da li možete **pronaći** bilo **koje zanimljive datoteke koje se dele unutar AD**. To biste mogli uraditi ručno, ali je veoma dosadan ponavljajući zadatak (posebno ako pronađete stotine dokumenata koje treba proveriti).

[**Pratite ovaj link da saznate o alatima koje možete koristiti.**](../../network-services-pentesting/pentesting-smb/#domain-shared-folders-search)

### Ukradi NTLM Kredencijale

Ako možete **pristupiti drugim računarima ili deljenim resursima**, možete **postaviti datoteke** (poput SCF datoteke) koje će, ako se na neki način pristupi, **pokrenuti NTML autentikaciju prema vama** kako biste mogli **ukrasti** **NTLM izazov** i probiti ga:

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Ova ranjivost je omogućila bilo kom autentifikovanom korisniku da **ugrozi kontroler domena**.

{% content-ref url="printnightmare.md" %}
[printnightmare.md](printnightmare.md)
{% endcontent-ref %}

## Eskalacija privilegija na Active Directory SA privilegovanim kredencijalima/sesijom

**Za sledeće tehnike, običan korisnik domena nije dovoljan, potrebne su vam posebne privilegije/kredencijali da biste izvršili ove napade.**

### Ekstrakcija heša

Nadamo se da ste uspeli da **ugrozite neki lokalni admin** nalog koristeći [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) uključujući preusmeravanje, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [eskalaranje privilegija lokalno](../windows-local-privilege-escalation/).\
Zatim, vreme je da izvučete sve heševe iz memorije i lokalno.\
[**Pročitajte ovu stranicu o različitim načinima dobijanja heševa.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Kada imate heš korisnika**, možete ga koristiti da ga **impersonirate**.\
Morate koristiti neki **alat** koji će **izvršiti** NTLM autentikaciju koristeći taj **heš**, **ili** možete kreirati novu **sesiju za prijavljivanje** i **ubaciti** taj **heš** unutar **LSASS**, tako da kada se izvrši bilo koja **NTLM autentikacija**, taj **heš će biti korišćen**. Poslednja opcija je ono što radi mimikatz.\
[**Pročitajte ovu stranicu za više informacija.**](../ntlm/#pass-the-hash)

### Over Pass the Hash/Pass the Key

Ovaj napad ima za cilj **korišćenje NTLM heša korisnika za zahtevanje Kerberos karata**, kao alternativu uobičajenom Pass The Hash preko NTLM protokola. Stoga, ovo bi moglo biti posebno **korisno u mrežama gde je NTLM protokol onemogućen** i dozvoljen je samo **Kerberos kao protokol autentifikacije**.

{% content-ref url="over-pass-the-hash-pass-the-key.md" %}
[over-pass-the-hash-pass-the-key.md](over-pass-the-hash-pass-the-key.md)
{% endcontent-ref %}

### Pass the Ticket

U metodi napada **Pass The Ticket (PTT)**, napadači **kradu autentifikacionu kartu korisnika** umesto njihove lozinke ili heš vrednosti. Ova ukradena karta se zatim koristi da se **impersonira korisnik**, stičući neovlašćen pristup resursima i uslugama unutar mreže.

{% content-ref url="pass-the-ticket.md" %}
[pass-the-ticket.md](pass-the-ticket.md)
{% endcontent-ref %}

### Ponovna upotreba kredencijala

Ako imate **heš** ili **lozinku** lokalnog **administratora**, trebalo bi da pokušate da se **prijavite lokalno** na druge **računare** sa njom.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
{% hint style="warning" %}
Imajte na umu da je ovo prilično **buka** i **LAPS** bi to **umirio**.
{% endhint %}

### Zloupotreba MSSQL-a i poverljivih veza

Ako korisnik ima privilegije da **pristupi MSSQL instancama**, može koristiti to da **izvršava komande** na MSSQL hostu (ako se izvršava kao SA), **ukrade** NetNTLM **hash** ili čak izvede **preusmeravanje** **napada**.\
Takođe, ako je MSSQL instanca poverljiva (veza sa bazom podataka) sa drugom MSSQL instancom. Ako korisnik ima privilegije nad poverljivom bazom podataka, moći će **iskoristiti poverenje da izvršava upite i na drugoj instanci**. Ova poverenja mogu biti povezana i u nekom trenutku korisnik može pronaći nekonfigurisanu bazu podataka gde može izvršavati komande.\
**Veze između baza podataka funkcionišu čak i preko poverenja šuma.**

{% content-ref url="abusing-ad-mssql.md" %}
[abusing-ad-mssql.md](abusing-ad-mssql.md)
{% endcontent-ref %}

### Neograničeno preusmeravanje

Ako pronađete bilo koji računarski objekat sa atributom [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx) i imate privilegije domena na računaru, moći ćete da izvučete TGT-ove iz memorije svih korisnika koji se prijavljuju na računar.\
Dakle, ako se **Administrator domena prijavi na računar**, moći ćete da izvučete njegov TGT i da ga personifikujete koristeći [Pass the Ticket](pass-the-ticket.md).\
Zahvaljujući ograničenom preusmeravanju, čak biste mogli **automatski kompromitovati Print Server** (nadamo se da će to biti DC).

{% content-ref url="unconstrained-delegation.md" %}
[unconstrained-delegation.md](unconstrained-delegation.md)
{% endcontent-ref %}

### Ograničeno preusmeravanje

Ako je korisniku ili računaru dozvoljeno "Ograničeno preusmeravanje", moći će da **personifikuje bilo kog korisnika da pristupi nekim uslugama na računaru**.\
Zatim, ako **kompromitujete hash** ovog korisnika/računara, moći ćete da **personifikujete bilo kog korisnika** (čak i administratorskih domena) da pristupi nekim uslugama.

{% content-ref url="constrained-delegation.md" %}
[constrained-delegation.md](constrained-delegation.md)
{% endcontent-ref %}

### Ograničeno preusmeravanje zasnovano na resursima

Imati **WRITE** privilegiju na objektu Active Directory-a udaljenog računara omogućava postizanje izvršenja koda sa **povišenim privilegijama**:

{% content-ref url="resource-based-constrained-delegation.md" %}
[resource-based-constrained-delegation.md](resource-based-constrained-delegation.md)
{% endcontent-ref %}

### Zloupotreba ACL-ova

Kompromitovani korisnik može imati neke **interesantne privilegije nad nekim objektima domena** koje bi vam mogle omogućiti da se **lateralno krećete**/**povišite** privilegije.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Zloupotreba servisa štampača

Otkrivanje **Spool servisa koji osluškuje** unutar domena može biti **zloupotrebljeno** za **dobijanje novih akreditacija** i **povišenje privilegija**.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Zloupotreba sesija trećih strana

Ako **drugi korisnici** **pristupe** **kompromitovanom** računaru, moguće je **prikupiti akreditacije iz memorije** i čak **ubaciti bekon u njihove procese** da ih personifikujete.\
Obično će korisnici pristupiti sistemu putem RDP-a, pa evo kako izvesti nekoliko napada preko sesija trećih strana RDP-a:

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### LAPS

**LAPS** pruža sistem za upravljanje **lozinkom lokalnog administratora** na računarima pridruženim domenu, osiguravajući da je **slučajna**, jedinstvena i često **menjana**. Ove lozinke se čuvaju u Active Directory-u i pristup se kontroliše putem ACL-ova samo ovlašćenim korisnicima. Sa dovoljnim dozvolama za pristup ovim lozinkama, postaje moguće preći na druge računare.

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

### Krađa sertifikata

**Sakupljanje sertifikata** sa kompromitovanog računara može biti način za povišenje privilegija unutar okruženja:

{% content-ref url="ad-certificates/certificate-theft.md" %}
[certificate-theft.md](ad-certificates/certificate-theft.md)
{% endcontent-ref %}

### Zloupotreba šablona sertifikata

Ako su konfigurisani **ranjivi šabloni**, moguće ih je zloupotrebiti za povišenje privilegija:

{% content-ref url="ad-certificates/domain-escalation.md" %}
[domain-escalation.md](ad-certificates/domain-escalation.md)
{% endcontent-ref %}

## Post-eksploatacija sa nalogom visokih privilegija

### Izvlačenje kredencijala domena

Kada dobijete **Administratora domena** ili čak bolje **Enterprise Admin** privilegije, možete **izvući** **bazu podataka domena**: _ntds.dit_.

[**Više informacija o DCSync napadu možete pronaći ovde**](dcsync.md).

[**Više informacija o tome kako ukrasti NTDS.dit možete pronaći ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Povišenje privilegija kao postojanost

Neke od tehnika koje su diskutovane ranije mogu se koristiti za postojanost.\
Na primer, možete:

*   Učiniti korisnike ranjivim na [**Kerberoast**](kerberoast.md)

```powershell
Set-DomainObject -Identity <korisničko_ime> -Set @{serviceprincipalname="lažni/NISTA"}r
```
*   Učiniti korisnike ranjivim na [**ASREPRoast**](asreproast.md)

```powershell
Set-DomainObject -Identity <korisničko_ime> -XOR @{UserAccountControl=4194304}
```
*   Dodeliti privilegije [**DCSync**](./#dcsync) korisniku

```powershell
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Srebrna karta

Napad **Srebrna karta** stvara **legitimnu kartu za uslugu dodeljivanja karata (TGS)** za određenu uslugu koristeći **NTLM hash** (na primer, **hash računa PC-a**). Ovaj metod se koristi za **pristup privilegijama usluge**.

{% content-ref url="silver-ticket.md" %}
[silver-ticket.md](silver-ticket.md)
{% endcontent-ref %}

### Zlatna karta

Napad **Zlatna karta** uključuje napadača koji dobija pristup **NTLM hash-u krbtgt naloga** u okruženju Active Directory (AD). Ovaj nalog je poseban jer se koristi za potpisivanje svih **karata za dodeljivanje karata (TGT)**, koje su ključne za autentifikaciju unutar AD mreže.

Kada napadač dobije ovaj hash, može kreirati **TGT** za bilo koji nalog koji odabere (napad srebrne karte).

{% content-ref url="golden-ticket.md" %}
[golden-ticket.md](golden-ticket.md)
{% endcontent-ref %}

### Dijamantska karta

Ove su kao zlatne karte izrađene na način koji **zaobilazi uobičajene mehanizme detekcije zlatnih karata**.

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}
### **Postojana Persistencija Naloga Sertifikata**

**Imati sertifikate naloga ili biti u mogućnosti da ih zatražite** je veoma dobar način da ostanete prisutni u korisničkom nalogu (čak i ako promeni lozinku):

{% content-ref url="ad-certificates/account-persistence.md" %}
[account-persistence.md](ad-certificates/account-persistence.md)
{% endcontent-ref %}

### **Persistencija Domena Sertifikata**

**Korišćenjem sertifikata takođe je moguće trajno ostati sa visokim privilegijama unutar domena:**

{% content-ref url="ad-certificates/domain-persistence.md" %}
[domain-persistence.md](ad-certificates/domain-persistence.md)
{% endcontent-ref %}

### Grupa AdminSDHolder

Objekat **AdminSDHolder** u Active Directory-u obezbeđuje sigurnost **privilegovanih grupa** (kao što su Domain Admins i Enterprise Admins) primenom standardne **Access Control List (ACL)** preko ovih grupa kako bi se sprečile neovlašćene promene. Međutim, ova funkcija može biti zloupotrebljena; ako napadač izmeni ACL AdminSDHolder-a kako bi dao pun pristup običnom korisniku, taj korisnik dobija obimnu kontrolu nad svim privilegovanim grupama. Ova sigurnosna mera, namenjena zaštiti, može se obrnuti, omogućavajući neovlašćen pristup ako se ne prati pažljivo.

[**Više informacija o grupi AdminDSHolder ovde.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Kredencijali

Unutar svakog **Domain Controller-a (DC)** postoji **lokalni administratorski** nalog. Dobijanjem administratorskih prava na takvoj mašini, lokalni Administrator hash može biti izvučen korišćenjem **mimikatz**-a. Nakon toga, potrebna je modifikacija registra da bi se **omogućila upotreba ove lozinke**, omogućavajući daljinski pristup lokalnom administratorskom nalogu.

{% content-ref url="dsrm-credentials.md" %}
[dsrm-credentials.md](dsrm-credentials.md)
{% endcontent-ref %}

### Persistencija ACL-a

Možete **dodeliti** neka **specijalna ovlašćenja** korisniku nad određenim domenskim objektima koji će omogućiti korisniku **eskalciju privilegija u budućnosti**.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Sigurnosni Deskriptori

**Sigurnosni deskriptori** se koriste za **čuvanje** **dozvola** koje **objekat** ima **nad** objektom. Ako možete **napraviti** **mali izmenu** u **sigurnosnom deskriptoru** objekta, možete dobiti veoma zanimljive privilegije nad tim objektom bez potrebe da budete član privilegovane grupe.

{% content-ref url="security-descriptors.md" %}
[security-descriptors.md](security-descriptors.md)
{% endcontent-ref %}

### Skeleton Ključ

Izmenite **LSASS** u memoriji da biste uspostavili **univerzalnu lozinku**, omogućavajući pristup svim domenskim nalozima.

{% content-ref url="skeleton-key.md" %}
[skeleton-key.md](skeleton-key.md)
{% endcontent-ref %}

### Prilagođeni SSP

[Saznajte šta je SSP (Security Support Provider) ovde.](../authentication-credentials-uac-and-efs/#security-support-provider-interface-sspi)\
Možete kreirati **svoj SSP** da **uhvatite** u **čistom tekstu** kredencijale korišćene za pristup mašini.\\

{% content-ref url="custom-ssp.md" %}
[custom-ssp.md](custom-ssp.md)
{% endcontent-ref %}

### DCShadow

Registrovanje **novog Domain Controller-a** u AD i korišćenje istog za **dodavanje atributa** (SIDHistory, SPN...) na određene objekte **bez** ostavljanja bilo kakvih **logova** u vezi sa **modifikacijama**. Potrebne su **DA privilegije** i biti unutar **root domena**.\
Imajte na umu da ako koristite pogrešne podatke, pojaviće se prilično ružni logovi.

{% content-ref url="dcshadow.md" %}
[dcshadow.md](dcshadow.md)
{% endcontent-ref %}

### LAPS Persistencija

Ranije smo razgovarali o tome kako eskalirati privilegije ako imate **dovoljno dozvola za čitanje LAPS lozinki**. Međutim, ove lozinke takođe mogu biti korišćene za **održavanje persistencije**.\
Proverite:

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

## Eskalacija Privilegija u Šumi - Poverenja Domena

Microsoft posmatra **Šumu** kao granicu sigurnosti. To implicira da **kompromitovanje jednog domena potencijalno može dovesti do kompromitovanja cele Šume**.

### Osnovne Informacije

[**Poverenje domena**](http://technet.microsoft.com/en-us/library/cc759554\(v=ws.10\).aspx) je sigurnosni mehanizam koji omogućava korisniku iz jednog **domena** pristup resursima u drugom **domenu**. Suštinski, stvara vezu između sistema za autentifikaciju dva domena, omogućavajući da se provere autentifikacije teku bez problema. Kada domeni uspostave poverenje, razmenjuju i zadržavaju specifične **ključeve** unutar svojih **Domain Controller-a (DC)**, koji su ključni za integritet poverenja.

U tipičnom scenariju, ako korisnik namerava da pristupi usluzi u **poverenom domenu**, prvo mora zatražiti posebnu karticu poznatu kao **inter-realm TGT** od svog sopstvenog domenskog DC-a. Ova TGT je enkriptovana sa deljenim **ključem** na koji su se oba domena složila. Korisnik zatim predstavlja ovu TGT **DC-u poverenog domena** da bi dobio uslužnu karticu (**TGS**). Nakon uspešne validacije inter-realm TGT-a od strane DC-a poverenog domena, izdaje TGS, dajući korisniku pristup usluzi.

**Koraci**:

1. **Klijentski računar** u **Domen 1** započinje proces koristeći svoj **NTLM hash** da zatraži **Ticket Granting Ticket (TGT)** od svog **Domain Controller-a (DC1)**.
2. DC1 izdaje novi TGT ako je klijent uspešno autentifikovan.
3. Klijent zatim zahteva **inter-realm TGT** od DC1, koji je potreban za pristup resursima u **Domen 2**.
4. Inter-realm TGT je enkriptovan sa **ključem poverenja** koji dele DC1 i DC2 kao deo dvosmernog poverenja domena.
5. Klijent odnosi inter-realm TGT **DC-u Domena 2 (DC2)**.
6. DC2 proverava inter-realm TGT koristeći svoj deljeni ključ poverenja i, ako je validan, izdaje **Ticket Granting Service (TGS)** za server u Domen 2 kojem klijent želi da pristupi.
7. Na kraju, klijent predstavlja ovaj TGS serveru, koji je enkriptovan sa hash-om naloga servera, da bi dobio pristup usluzi u Domen 2.

### Različita poverenja

Važno je primetiti da **poverenje može biti jednosmerno ili dvosmerno**. U opcijama sa dvosmernim poverenjem, oba domena će verovati jedan drugom, ali u **jednosmernom** odnosu poverenja jedan od domena će biti **poverljiv** a drugi **poverljivi** domen. U poslednjem slučaju, **samo ćete moći pristupiti resursima unutar poverljivog domena iz poverenog**.

Ako Domen A veruje Domen B, A je poverljivi domen a B je povereni. Nadalje, u **Domen A**, ovo bi bilo **Izlazno poverenje**; a u **Domen B**, ovo bi bilo **Ulazno poverenje**.

**Različiti odnosi poverenja**

* **Poverenja Roditelj-Dete**: Ovo je uobičajena postavka unutar iste šume, gde dete domena automatski ima dvosmerno tranzitivno poverenje sa svojim roditeljskim domenom. Suštinski, to znači da zahtevi za autentifikaciju mogu teći bez problema između roditelja i deteta.
* **Poverenja Prečice**: Poznata kao "poverenja prečice", ova se uspostavljaju između dečjih domena radi ubrzanja procesa upućivanja. U složenim šumama, upućivanja autentifikacije obično moraju putovati do korena šume pa zatim do ciljnog domena. Stvaranjem prečica, putovanje se skraćuje, što je posebno korisno u geografski razuđenim okruženjima.
* **Spoljna Poverenja**: Ova se uspostavljaju između različitih, nepovezanih domena i nisu tranzitivna prirodom. Prema [Microsoft-ovoj dokumentaciji](https://technet.microsoft.com/en-us/library/cc773178\(v=ws.10\).aspx), spoljna poverenja su korisna za pristup resursima u domenu van trenutne šume koji nije povezan poverenjem šume. Bezbednost se pojačava kroz filtriranje SID-ova sa spoljnim poverenjima.
* **Poverenja Koren-Stabla**: Ova poverenja se automatski uspostavljaju između korena šume i novog dodatog korena stabla. Iako se retko susreću, poverenja korena stabla su važna za dodavanje novih domenskih stabala u šumu, omogućavajući im da zadrže jedinstveno ime domena i osiguravajući dvosmernu tranzitivnost. Više informacija može se naći u [Microsoft-ovom vodiču](https://technet.microsoft.com/en-us/library/cc773178\(v=ws.10\).aspx).
* **Poverenja Šume**: Ovaj tip poverenja je dvosmerno tranzitivno poverenje između dva korena šuma, takođe primenjujući filtriranje SID-ova radi poboljšanja sigurnosnih mera.
* **MIT Poverenja**: Ova poverenja se uspostavljaju sa ne-Windows, [RFC4120-kompatibilnim](https://tools.ietf.org/html/rfc4120) Kerberos domenima. MIT poverenja su malo specijalizovana i prilagođena okruženjima koja zahtevaju integraciju sa sistemima zasnovanim na Kerberosu izvan Windows ekosistema.
#### Ostale razlike u **poverljivim odnosima**

* Poverljiv odnos može biti **tranzitivan** (A veruje B, B veruje C, onda A veruje C) ili **netranzitivan**.
* Poverljiv odnos može biti postavljen kao **dvosmerna veza poverenja** (oboje veruju jedno drugome) ili kao **jednosmerna veza poverenja** (samo jedan od njih veruje drugome).

### Put napada

1. **Nabrajanje** poverljivih odnosa
2. Provera da li bilo koji **bezbednosni princip** (korisnik/grupa/računar) ima **pristup** resursima **druge domene**, možda putem unosa ACE ili putem pripadnosti grupama druge domene. Potražite **odnose između domena** (verovatno je veza stvorena zbog toga).
1. U ovom slučaju, kerberoast bi mogao biti još jedna opcija.
3. **Kompromitovanje** **računa** koji mogu **preći** preko domena.

Napadači mogu pristupiti resursima u drugoj domeni putem tri osnovna mehanizma:

* **Članstvo u lokalnoj grupi**: Principali mogu biti dodati u lokalne grupe na mašinama, poput grupe "Administratori" na serveru, dajući im značajnu kontrolu nad tom mašinom.
* **Članstvo u stranoj domeni grupi**: Principali takođe mogu biti članovi grupa unutar strane domene. Međutim, efikasnost ovog metoda zavisi od prirode poverenja i opsega grupe.
* **Kontrole pristupa (ACL)**: Principali mogu biti navedeni u **ACL**, posebno kao entiteti u **ACE** unutar **DACL**, pružajući im pristup određenim resursima. Za one koji žele dublje istražiti mehaniku ACL, DACL i ACE, bela knjiga pod nazivom "[An ACE Up The Sleeve](https://specterops.io/assets/resources/an\_ace\_up\_the\_sleeve.pdf)" je neprocenjiv resurs.

### Eskalacija privilegija od deteta do roditelja u šumi
```
Get-DomainTrust

SourceName      : sub.domain.local    --> current domain
TargetName      : domain.local        --> foreign domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST       --> WITHIN_FOREST: Both in the same forest
TrustDirection  : Bidirectional       --> Trust direction (2ways in this case)
WhenCreated     : 2/19/2021 1:28:00 PM
WhenChanged     : 2/19/2021 1:28:00 PM
```
{% hint style="warning" %}
Postoje **2 pouzdana ključa**, jedan za _Dete --> Roditelj_ i drugi za _Roditelj_ --> _Dete_.\
Možete proveriti onaj koji se koristi za trenutni domen pomoću:
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
```
{% endhint %}

#### SID-History Injection

Eskalirajte kao Enterprise admin u dete/roditeljski domen zloupotrebom poverenja sa SID-History ubrizgavanjem:

{% content-ref url="sid-history-injection.md" %}
[sid-history-injection.md](sid-history-injection.md)
{% endcontent-ref %}

#### Iskoristite konfiguracioni NC koji se može pisati

Razumevanje kako se konfiguracioni Naming Context (NC) može iskoristiti je ključno. Konfiguracioni NC služi kao centralni repozitorijum za konfiguracione podatke širom šume u Active Directory (AD) okruženjima. Ovi podaci se replikuju na svaki Domain Controller (DC) unutar šume, pri čemu pisani DC-ovi održavaju pisani primerak Konfiguracionog NC. Da biste iskoristili ovo, morate imati **SYSTEM privilegije na DC-u**, po mogućstvu na DC-u deteta.

**Povežite GPO sa korenskim DC sajtom**

Kontejner Sajtova Konfiguracionog NC-a uključuje informacije o svim sajtovima računara pridruženih domenu unutar AD šume. Radeći sa SYSTEM privilegijama na bilo kom DC-u, napadači mogu povezati GPO-ove sa sajtovima korenskog DC-a. Ova akcija potencijalno kompromituje korenski domen manipulacijom politika koje se primenjuju na ove sajtove.

Za detaljnije informacije, možete istražiti istraživanje o [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Kompromitujte bilo koji gMSA u šumi**

Vektor napada uključuje ciljanje privilegovanih gMSA unutar domena. KDS Root ključ, bitan za izračunavanje lozinki gMSA, čuva se unutar Konfiguracionog NC-a. Sa SYSTEM privilegijama na bilo kom DC-u, moguće je pristupiti KDS Root ključu i izračunati lozinke za bilo koji gMSA širom šume.

Detaljna analiza može se pronaći u diskusiji o [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Napad na promenu šeme**

Ova metoda zahteva strpljenje, čekajući stvaranje novih privilegovanih AD objekata. Sa SYSTEM privilegijama, napadač može izmeniti AD šemu kako bi dao bilo kom korisniku potpunu kontrolu nad svim klasama. Ovo bi moglo dovesti do neovlašćenog pristupa i kontrole nad novostvorenim AD objektima.

Više informacija možete pronaći u [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**Od DA do EA sa ADCS ESC5**

Ranjivost ADCS ESC5 cilja kontrolu nad objektima Javnog Ključne Infrastrukture (PKI) kako bi se kreirala šablona sertifikata koja omogućava autentifikaciju kao bilo koji korisnik unutar šume. Pošto PKI objekti borave u Konfiguracionom NC-u, kompromitovanje pisanih DC-ova deteta omogućava izvođenje ESC5 napada.

Više detalja o ovome možete pročitati u [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). U scenarijima bez ADCS-a, napadač ima mogućnost da postavi neophodne komponente, kako je diskutovano u [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### Spoljni šumski domen - Jednosmerna (ulazna) ili dvosmerna
```powershell
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes :
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM
```
U ovom scenariju **vaš domen je poveren** od strane spoljnog, dajući vam **nepoznate dozvole** nad njim. Morate pronaći **koji principali vašeg domena imaju koje pristupe nad spoljnim domenom** i zatim pokušati da ga iskoristite:

{% content-ref url="external-forest-domain-oneway-inbound.md" %}
[external-forest-domain-oneway-inbound.md](external-forest-domain-oneway-inbound.md)
{% endcontent-ref %}

### Spoljni šumski domen - Jednosmerno (izlazno)
```powershell
Get-DomainTrust -Domain current.local

SourceName      : current.local   --> Current domain
TargetName      : external.local  --> Destination domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound        --> Outbound trust
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM
```
U ovom scenariju **vaš domen** poverava određene **privilegije** principu iz **različitih domena**.

Međutim, kada se **domen poverava** poverenjem domena, povereni domen **kreira korisnika** sa **predvidljivim imenom** koji koristi kao **šifru poverenu šifru**. Što znači da je moguće **pristupiti korisniku iz poverenog domena da bi se ušlo u povereni** i enumerisalo ga i pokušalo eskalirati više privilegija:

{% content-ref url="external-forest-domain-one-way-outbound.md" %}
[external-forest-domain-one-way-outbound.md](external-forest-domain-one-way-outbound.md)
{% endcontent-ref %}

Još jedan način da se ugrozi povereni domen je pronalaženje [**SQL poverenog linka**](abusing-ad-mssql.md#mssql-trusted-links) kreiranog u **suprotnom smeru** od poverenja domena (što nije vrlo često).

Još jedan način da se ugrozi povereni domen je čekanje na mašini gde **korisnik iz poverenog domena može pristupiti** da se prijavi putem **RDP**. Zatim, napadač bi mogao ubaciti kod u proces RDP sesije i **pristupiti domenu žrtve** odatle.\
Štaviše, ako je **žrtva montirala svoj hard disk**, iz procesa RDP sesije napadač bi mogao sačuvati **zadnja vrata** u **folder za pokretanje hard diska**. Ova tehnika se naziva **RDPInception.**

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### Zaštita od zloupotrebe poverenja domena

### **SID Filtriranje:**

* Rizik od napada koji iskorišćavaju atribut istorije SID-a preko šuma poverenja je umanjen SID Filtriranjem, koje je podrazumevano aktivirano na svim među-šumskim poverenjima. Ovo se zasniva na pretpostavci da su unutar-šumska poverenja sigurna, uzimajući u obzir šum, umesto domena, kao granicu sigurnosti prema stavu Microsoft-a.
* Međutim, postoji kvaka: SID filtriranje može poremetiti aplikacije i pristup korisnika, što dovodi do njegovog povremenog deaktiviranja.

### **Selektivna Autentifikacija:**

* Za među-šumska poverenja, korišćenje Selektivne Autentifikacije osigurava da se korisnici iz dva šuma ne autentifikuju automatski. Umesto toga, potrebne su eksplicitne dozvole korisnicima da pristupe domenima i serverima unutar poverenog domena ili šuma.
* Važno je napomenuti da ove mere ne štite od iskorišćavanja pisivog Konfiguracionog Imenskog Konteksta (NC) ili napada na nalog za poverenje.

[**Više informacija o poverenju domena na ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD

{% embed url="https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-lateral-movements/azure-ad-connect-hybrid-identity" %}

## Neke Opšte Odbrane

[**Saznajte više o tome kako zaštititi akreditive ovde.**](../stealing-credentials/credentials-protections.md)\\

### **Odbrambene Mere za Zaštitu Akreditiva**

* **Ograničenja Administratora Domena**: Preporučuje se da Administratori Domena treba da imaju dozvolu samo za prijavljivanje na Kontrolere Domena, izbegavajući njihovo korišćenje na drugim hostovima.
* **Privilegije Servisnih Naloga**: Servisi ne bi trebalo da se pokreću sa privilegijama Administratora Domena (DA) radi očuvanja sigurnosti.
* **Privremeno Ograničenje Privilegija**: Za zadatke koji zahtevaju privilegije Administratora Domena, njihovo trajanje bi trebalo da bude ograničeno. Ovo se može postići sa: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementiranje Tehnika Obmane**

* Implementiranje obmane uključuje postavljanje zamki, poput lažnih korisnika ili računara, sa funkcijama kao što su šifre koje ne ističu ili su označene kao Poverene za Delegaciju. Detaljan pristup uključuje kreiranje korisnika sa specifičnim pravima ili dodavanje u grupe visokih privilegija.
* Praktičan primer uključuje korišćenje alatki kao što su: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
* Više o implementiranju tehnika obmane može se pronaći na [Deploy-Deception na GitHub-u](https://github.com/samratashok/Deploy-Deception).

### **Identifikacija Obmane**

* **Za Korisničke Objekte**: Sumnjivi indikatori uključuju atipičan ObjectSID, retke prijave, datume kreiranja i nizak broj loših šifri.
* **Opšti Indikatori**: Upoređivanje atributa potencijalnih lažnih objekata sa onima pravih može otkriti neusaglašenosti. Alatke poput [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) mogu pomoći u identifikaciji takvih obmana.

### **Obilaženje Sistema Detekcije**

* **Obilaženje Detekcije Microsoft ATA**:
* **Enumeracija Korisnika**: Izbegavanje enumeracije sesija na Kontrolerima Domena kako bi se sprečila detekcija ATA.
* **Impersonacija Tiketa**: Korišćenje **aes** ključeva za kreiranje tiketa pomaže u izbegavanju detekcije ne spuštanjem na NTLM.
* **DCSync Napadi**: Izvršavanje sa ne-Kontrolera Domena kako bi se izbegla detekcija ATA se savetuje, jer direktno izvršavanje sa Kontrolera Domena će izazvati upozorenja.

## Reference

* [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
* [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** Proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
