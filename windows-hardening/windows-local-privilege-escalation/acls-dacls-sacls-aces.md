# ACLs - DACLs/SACLs/ACEs

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Koristite [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) da biste lako izgradili i **automatizovali radne tokove** uz pomoć najnaprednijih alata zajednice na svetu.\
Dobijte pristup danas:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **oglašavanje vaše kompanije u HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## **Access Control List (ACL)**

Lista kontrole pristupa (ACL) sastoji se od uređenog skupa unosa kontrole pristupa (ACE) koji određuju zaštitu objekta i njegovih svojstava. U osnovi, ACL definiše koje radnje od strane kojih sigurnosnih principala (korisnika ili grupa) su dozvoljene ili zabranjene na datom objektu.

Postoje dva tipa ACL-a:

- **Discretionary Access Control List (DACL):** Određuje koje korisnici i grupe imaju ili nemaju pristup objektu.
- **System Access Control List (SACL):** Upravlja nadzorom pokušaja pristupa objektu.

Proces pristupa datoteci uključuje sistem koji proverava sigurnosni deskriptor objekta u odnosu na korisnički pristupni token kako bi utvrdio da li treba odobriti pristup i obim tog pristupa, na osnovu ACE-ova.

### **Ključne komponente**

- **DACL:** Sadrži ACE-ove koji dodeljuju ili odbijaju dozvole za pristup korisnicima i grupama za objekat. To je suštinski glavni ACL koji određuje prava pristupa.

- **SACL:** Koristi se za nadzor pristupa objektima, gde ACE-ovi definišu vrste pristupa koje treba zabeležiti u bezbednosnom događaju. Ovo može biti neprocenjivo za otkrivanje neovlašćenih pokušaja pristupa ili rešavanje problema sa pristupom.

### **Interakcija sistema sa ACL-ovima**

Svaka korisnička sesija je povezana sa pristupnim tokenom koji sadrži relevantne sigurnosne informacije za tu sesiju, uključujući korisnika, identitete grupa i privilegije. Ovaj token takođe uključuje SID prijave koji jedinstveno identifikuje sesiju.

Lokalna sigurnosna vlast (LSASS) obrađuje zahteve za pristup objektima tako što pregleda DACL za ACE-ove koji se podudaraju sa sigurnosnim principalom koji pokušava pristupiti. Pristup se odmah odobrava ako nisu pronađeni relevantni ACE-ovi. U suprotnom, LSASS upoređuje ACE-ove sa SID-om sigurnosnog principala u pristupnom tokenu kako bi utvrdio pravo pristupa.

### **Sumirani proces**

- **ACL-ovi:** Definišu dozvole za pristup putem DACL-ova i pravila nadzora putem SACL-ova.
- **Pristupni token:** Sadrži informacije o korisniku, grupi i privilegijama za sesiju.
- **Odluka o pristupu:** Donosi se upoređivanjem DACL ACE-ova sa pristupnim tokenom; SACL-ovi se koriste za nadzor.

### ACE-ovi

Postoje **tri glavne vrste unosa kontrole pristupa (ACE)**:

- **Access Denied ACE**: Ovaj ACE eksplicitno zabranjuje pristup objektu određenim korisnicima ili grupama (u DACL-u).
- **Access Allowed ACE**: Ovaj ACE eksplicitno odobrava pristup objektu određenim korisnicima ili grupama (u DACL-u).
- **System Audit ACE**: Pozicioniran unutar System Access Control List (SACL), ovaj ACE je odgovoran za generisanje evidencija nadzora prilikom pokušaja pristupa objektu od strane korisnika ili grupa. Dokumentuje da li je pristup odobren ili odbijen i prirodu pristupa.

Svaki ACE ima **četiri ključne komponente**:

1. **Sigurnosni identifikator (SID)** korisnika ili grupe (ili njihovo ime principala u grafičkom prikazu).
2. **Zastava** koja identifikuje vrstu ACE-a (zabranjen pristup, odobren pristup ili sistemski nadzor).
3. **Zastave nasleđivanja** koje određuju da li deca objekti mogu naslediti ACE od svojih roditelja.
4. **[Maska pristupa](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN)**, 32-bitna vrednost koja određuje dodeljena prava objekta.

Odluka o pristupu se vrši sekvencijalnim pregledom svakog ACE-a dok:

- **Access-Denied ACE** eksplicitno odbija tražena prava za poverenika identifikovanog u pristupnom tokenu.
- **Access-Allowed ACE-ovi** eksplicitno odobravaju sva tražena prava povereniku u pristupnom tokenu.
- Nakon pregleda svih ACE-ova, ako bilo koje traženo pravo nije eksplicitno odobreno, pristup se implicitno **odbija**.

### Redosled ACE-ova

Način na koji se **ACE-ovi** (pravila koja govore ko može ili ne može pristupiti nečemu) stavljaju u listu koja se zove **DACL** je veoma važan. Ovo je zato što kada sistem dodeljuje ili odbija pristup na osnovu ovih pravila, prestaje da gleda ostatak.

Postoji najbolji način da se organizuju ovi ACE-ovi, a zove se **"kanonski redosled"**. Ovaj metod pomaže da se obezbedi da sve funkcioniše glatko i pravično. Evo kako to ide za sisteme kao što su **Windows 2000** i **Windows Server 2003**:

- Prvo, stavite sva pravila koja su napravljena **specifično za ovu stavku** pre onih koji dolaze iz drugog izvora, poput roditeljskog foldera.
- U tim specifičnim pravilima, stavite ona koja kažu **"ne" (odbijeno)** pre onih koji kažu **"da"
### Primer GUI-a

**[Primer sa ovog linka](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)**

Ovo je klasična sigurnosna kartica foldera koja prikazuje ACL, DACL i ACE:

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../.gitbook/assets/classicsectab.jpg)

Ako kliknemo na **Advanced dugme**, dobićemo više opcija kao što je nasleđivanje:

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../.gitbook/assets/aceinheritance.jpg)

Ako dodamo ili izmenimo Sigurnosnog principala:

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../.gitbook/assets/editseprincipalpointers1.jpg)

Na kraju imamo SACL u kartici Auditing:

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../.gitbook/assets/audit-tab.jpg)

### Pojašnjavanje kontrole pristupa na jednostavan način

Kada upravljamo pristupom resursima, poput foldera, koristimo liste i pravila poznata kao Access Control Lists (ACLs) i Access Control Entries (ACEs). Oni definišu ko može ili ne može pristupiti određenim podacima.

#### Odbijanje pristupa određenoj grupi

Zamislite da imate folder nazvan Cost i želite da svi imaju pristup osim tima za marketing. Pravilnim podešavanjem pravila, možemo osigurati da timu za marketing bude eksplicitno zabranjen pristup pre nego što se dozvoli svima ostalima. To se postiže postavljanjem pravila za zabranu pristupa timu za marketing pre pravila koje dozvoljava pristup svima.

#### Dozvola pristupa određenom članu odbijene grupe

Recimo da Bob, direktor marketinga, treba pristup folderu Cost, iako tim za marketing generalno ne bi trebao imati pristup. Možemo dodati posebno pravilo (ACE) za Boba koje mu daje pristup i postaviti ga pre pravila koje zabranjuje pristup timu za marketing. Na taj način, Bob dobija pristup uprkos opštem ograničenju za njegov tim.

#### Razumevanje Access Control Entries

ACE su pojedinačna pravila u ACL-u. Oni identifikuju korisnike ili grupe, određuju koje pristupe su dozvoljeni ili zabranjeni i određuju kako se ta pravila primenjuju na pod-stavke (nasleđivanje). Postoje dve glavne vrste ACE-a:

- **Generic ACEs**: Ovi se primenjuju široko, utičući ili na sve vrste objekata ili razlikujući samo između kontejnera (poput foldera) i ne-kontejnera (poput datoteka). Na primer, pravilo koje korisnicima omogućava da vide sadržaj foldera, ali ne i pristup datotekama unutar njega.

- **Object-Specific ACEs**: Ovi pružaju precizniju kontrolu, omogućavajući postavljanje pravila za određene vrste objekata ili čak pojedinačna svojstva unutar objekta. Na primer, u direktorijumu korisnika, pravilo može dozvoliti korisniku da ažurira svoj broj telefona, ali ne i svoje radno vreme.

Svaki ACE sadrži važne informacije poput toga na koga se pravilo odnosi (koristeći Security Identifier ili SID), šta pravilo dozvoljava ili zabranjuje (koristeći masku pristupa) i kako se nasleđuje od drugih objekata.

#### Ključne razlike između vrsta ACE-a

- **Generic ACEs** su pogodni za jednostavne scenarije kontrole pristupa, gde isto pravilo važi za sve aspekte objekta ili za sve objekte unutar kontejnera.

- **Object-Specific ACEs** se koriste za složenije scenarije, posebno u okruženjima poput Active Directory-ja, gde možda trebate kontrolisati pristup određenim svojstvima objekta na drugačiji način.

Ukratko, ACL-i i ACE-i pomažu u definisanju preciznih kontrola pristupa, osiguravajući da samo odgovarajuće osobe ili grupe imaju pristup osetljivim informacijama ili resursima, sa mogućnošću prilagođavanja prava pristupa do nivoa pojedinačnih svojstava ili vrsta objekata.

### Izgled Access Control Entry-a

| Polje ACE-a | Opis                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Tip         | Zastavica koja označava vrstu ACE-a. Windows 2000 i Windows Server 2003 podržavaju šest vrsta ACE-a: Tri generičke vrste ACE-a koje su povezane sa svim objektima koji se mogu obezbediti. Tri vrste ACE-a specifične za objekte koja se mogu pojaviti za objekte Active Directory-ja.                                                                                                                                                                                                                                                            |
| Zastave     | Skup bitnih zastavica koje kontrolišu nasleđivanje i nadzor.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Veličina    | Broj bajtova memorije koji je alociran za ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Pristupna maska | 32-bitna vrednost čiji bitovi odgovaraju pravima pristupa za objekat. Bitovi mogu biti postavljeni na uključeno ili isključeno, ali značenje postavke zavisi od vrste ACE-a. Na primer, ako je uključen bit koji odgovara pravu za čitanje dozvola, a vrsta ACE-a je Deny, ACE odbija pravo za čitanje dozvola objekta. Ako je isti bit postavljen, ali je vrsta ACE-a Allow, ACE dodeljuje pravo za čitanje dozvola objekta. Detaljnije informacije o pristupnoj maski nalaze se u sledećoj tabeli. |
| SID         | Identifikuje korisnika ili grupu čiji pristup je kontrolisan ili nadgledan ovim ACE-om.                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Izgled pristupne maske

| Bit (Opseg) | Značenje                            | Opis/Primer                       |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | Specifična prava pristupa objektu      | Čitanje podataka, Izvršavanje, Dodavanje podataka           |
| 16 - 22     | Standardna prava pristupa             | Brisanje, Pisanje ACL-a, Pisanje vlasnika            |
| 23          | Može pristupiti sigurnosnom ACL-u            |                                           |
| 24 - 27     | Rezervisano                           |                                           |
| 28          | Generičko SVE (Čitanje, Pisanje, Izvršavanje) | Sve ispod                          |
| 29          | Generičko Izvršavanje                    | Sve što je potrebno za izvršavanje programa |
| 30          | Generičko Pisanje                      | Sve što je potrebno za pisanje u datoteku   |
| 31          | Generičko Čitanje                       | Sve što je potrebno za čitanje datoteke       |

## Reference

* [https://www.ntfs.com/ntfs-permissions-acl-use.htm](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
* [https://secureidentity.se/acl-dacl-sacl-and-the-ace/](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)
* [https://www.coopware.in2.info/_ntfsacl_ht.htm](https://www.coopware.in2.info/_ntfsacl_ht.htm)

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju oglašenu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu**
