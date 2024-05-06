# ACLs - DACLs/SACLs/ACEs

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Koristite [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=acls-dacls-sacls-aces) da biste lako izgradili i **automatizovali radne tokove** pokretane najnaprednijim alatima zajednice na svetu.\
Pristupite danas:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=acls-dacls-sacls-aces" %}

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRETPLATU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## **Lista Kontrole Pristupa (ACL)**

Lista Kontrole Pristupa (ACL) sastoji se od uređenog skupa Unosa Kontrole Pristupa (ACE) koji određuju zaštitu objekta i njegovih svojstava. U osnovi, ACL definiše koje radnje od strane kojih sigurnosnih principala (korisnika ili grupa) su dozvoljene ili zabranjene na datom objektu.

Postoje dva tipa ACL-ova:

* **Diskreciona Lista Kontrole Pristupa (DACL):** Specificira koje korisnici i grupe imaju ili nemaju pristup objektu.
* **Sistematska Lista Kontrole Pristupa (SACL):** Upravlja nadzorom pokušaja pristupa objektu.

Proces pristupa datoteci uključuje sistem koji proverava sigurnosni deskriptor objekta protiv korisničkog pristupnog tokena kako bi odredio da li treba odobriti pristup i obim tog pristupa, na osnovu ACE-ova.

### **Ključni Komponenti**

* **DACL:** Sadrži ACE-ove koji dodeljuju ili odbijaju dozvole pristupa korisnicima i grupama za objekat. To je suštinski glavni ACL koji određuje prava pristupa.
* **SACL:** Koristi se za nadzor pristupa objektima, gde ACE-ovi definišu vrste pristupa koji će biti zabeleženi u Sigurnosnom Dnevniku Događaja. Ovo može biti neprocenjivo za otkrivanje neovlašćenih pokušaja pristupa ili rešavanje problema pristupa.

### **Sistematska Interakcija sa ACL-ovima**

Svaka korisnička sesija je povezana sa pristupnim tokenom koji sadrži sigurnosne informacije relevantne za tu sesiju, uključujući korisnika, identitete grupa i privilegije. Ovaj token takođe uključuje SID prijavljivanja koji jedinstveno identifikuje sesiju.

Lokalna Služba za Sigurnost (LSASS) obrađuje zahteve za pristup objektima pregledanjem DACL-a za ACE-ove koji se podudaraju sa sigurnosnim principalom koji pokušava pristupiti. Pristup se odmah odobrava ako nisu pronađeni relevantni ACE-ovi. U suprotnom, LSASS upoređuje ACE-ove sa SID-om sigurnosnog principala u pristupnom tokenu kako bi odredio pravo pristupa.

### **Sumirani Proces**

* **ACL-ovi:** Definišu dozvole pristupa putem DACL-ova i pravila nadzora putem SACL-ova.
* **Pristupni Token:** Sadrži informacije o korisniku, grupi i privilegijama za sesiju.
* **Odluka o Pristupu:** Donosi se upoređivanjem DACL ACE-ova sa pristupnim tokenom; SACL-ovi se koriste za nadzor.

### ACE-ovi

Postoje **tri glavna tipa Unosa Kontrole Pristupa (ACE)**:

* **ACE za Odbijanje Pristupa**: Ovaj ACE eksplicitno odbija pristup objektu određenim korisnicima ili grupama (u DACL-u).
* **ACE za Dozvolu Pristupa**: Ovaj ACE eksplicitno dodeljuje pristup objektu određenim korisnicima ili grupama (u DACL-u).
* **Sistemski Revizorski ACE**: Pozicioniran unutar Sistematske Liste Kontrole Pristupa (SACL), ovaj ACE je odgovoran za generisanje revizijskih zapisa prilikom pokušaja pristupa objektu od strane korisnika ili grupa. Dokumentuje da li je pristup dozvoljen ili odbijen i prirodu pristupa.

Svaki ACE ima **četiri ključne komponente**:

1. **Sigurnosni Identifikator (SID)** korisnika ili grupe (ili njihovo ime principala u grafičkom prikazu).
2. **Zastava** koja identifikuje tip ACE-a (odbijanje pristupa, dozvola pristupa ili sistemski revizor).
3. **Zastave nasleđivanja** koje određuju da li deca objekata mogu naslediti ACE od svojih roditelja.
4. [**Maska pristupa**](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN), 32-bitna vrednost koja specificira prava odobrena objektu.

Odluka o pristupu se sprovodi sekvencijalnim pregledanjem svakog ACE-a dok:

* **ACE za Odbijanje Pristupa** eksplicitno odbija tražena prava trustee-a identifikovanog u pristupnom tokenu.
* **ACE za Dozvolu Pristupa** eksplicitno dodeljuje sva tražena prava trustee-u u pristupnom tokenu.
* Nakon pregledanja svih ACE-ova, ako bilo koje traženo pravo nije eksplicitno dozvoljeno, pristup se implicitno **odbija**.

### Redosled ACE-ova

Način na koji se **ACE-ovi** (pravila koja kažu ko može ili ne može pristupiti nečemu) stavljaju u listu nazvanu **DACL** je veoma važan. To je zato što kada sistem dodeljuje ili odbija pristup na osnovu ovih pravila, prestaje da gleda ostatak.

Postoji najbolji način organizovanja ovih ACE-ova, nazvan **"kanonski redosled."** Ovaj metod pomaže da se osigura da sve funkcioniše glatko i pravedno. Evo kako to ide za sisteme poput **Windows 2000** i **Windows Server 2003**:

* Prvo, stavite sva pravila koja su napravljena **specifično za ovu stavku** pre onih koji dolaze iz drugog izvora, poput roditeljske fascikle.
* U tim specifičnim pravilima, stavite one koji kažu **"ne" (odbij)** pre onih koji kažu **"da" (dozvoli)**.
* Za pravila koja dolaze iz drugog izvora, počnite sa onima iz **najbližeg izvora**, poput roditelja, i onda idite unazad odande. Ponovo, stavite **"ne"** pre **"da"**.

Ova postavka pomaže na dva velika načina:

* Osigurava da ako postoji specifično **"ne,"** to se poštuje, bez obzira na to koja druga pravila **"da"** postoje.
* Omogućava vlasniku stavke da ima **poslednju reč** o tome ko može ući, pre nego što pravila iz roditeljskih fascikli ili dalje unazad stupe na snagu.

Radeći na ovaj način, vlasnik datoteke ili fascikle može biti veoma precizan u vezi sa tim ko dobija pristup, osiguravajući da prave osobe mogu ući, a pogrešne ne mogu.

![](https://www.ntfs.com/images/screenshots/ACEs.gif)

Dakle, ovaj **"kanonski redosled"** je sve o tome da se osigura da su pravila pristupa jasna i dobro funkcionišu, stavljajući specifična pravila prvo i organizujući sve na pametan način.

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Koristite [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) da biste lako izgradili i **automatizovali radne tokove** pokretane najnaprednijim alatima zajednice na svetu.\
Pristupite danas:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
### Primer GUI

[**Primer sa ovog linka**](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)

Ovo je klasična sigurnosna kartica fascikle koja prikazuje ACL, DACL i ACE-ove:

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../.gitbook/assets/classicsectab.jpg)

Ako kliknemo na **Dugme Napredno**, dobićemo više opcija poput nasleđivanja:

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../.gitbook/assets/aceinheritance.jpg)

A ako dodate ili izmenite Sigurnosnog Principala:

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../.gitbook/assets/editseprincipalpointers1.jpg)

I na kraju imamo SACL u kartici Revizija:

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../.gitbook/assets/audit-tab.jpg)

### Objasniti kontrolu pristupa na pojednostavljen način

Prilikom upravljanja pristupom resursima, poput fascikle, koristimo liste i pravila poznata kao Liste Kontrole Pristupa (ACL) i Unosi Kontrole Pristupa (ACE). Oni definišu ko može ili ne može pristupiti određenim podacima.

#### Odbijanje pristupa određenoj grupi

Zamislite da imate fasciklu nazvanu Troškovi i želite da svi pristupe osim tima za marketing. Postavljanjem pravila na odgovarajući način, možemo osigurati da tim za marketing eksplicitno bude odbijen pristup pre nego što se dozvoli svima ostalima. To se postiže postavljanjem pravila za odbijanje pristupa timu za marketing pre pravila koje dozvoljava pristup svima.

#### Dozvola pristupa određenom članu odbijene grupe

Recimo da Bob, direktor marketinga, treba pristup fascikli Troškovi, iako tim za marketing generalno ne bi trebao imati pristup. Možemo dodati specifično pravilo (ACE) za Boba koje mu daje pristup i postaviti ga pre pravila koje odbija pristup timu za marketing. Na taj način, Bob dobija pristup uprkos opštem ograničenju za njegov tim.

#### Razumevanje Unosa Kontrole Pristupa

ACE-ovi su pojedinačna pravila u ACL-u. Oni identifikuju korisnike ili grupe, specificiraju koje pristupe su dozvoljeni ili odbijeni, i određuju kako se ova pravila primenjuju na pod-stavke (nasleđivanje). Postoje dva glavna tipa ACE-ova:

* **Generički ACE-ovi**: Oni se primenjuju široko, utičući ili na sve vrste objekata ili razlikujući samo između kontejnera (kao što su fascikle) i ne-kontejnera (kao što su fajlovi). Na primer, pravilo koje dozvoljava korisnicima da vide sadržaj fascikle ali ne i da pristupe fajlovima unutar nje.
* **Objekat-Specifični ACE-ovi**: Oni pružaju precizniju kontrolu, omogućavajući postavljanje pravila za specifične vrste objekata ili čak pojedinačna svojstva unutar objekta. Na primer, u direktorijumu korisnika, pravilo može dozvoliti korisniku da ažurira svoj broj telefona ali ne i svoje radno vreme.

Svaki ACE sadrži važne informacije poput na koga se pravilo odnosi (koristeći Identifikator Bezbednosti ili SID), šta pravilo dozvoljava ili odbija (koristeći masku pristupa) i kako se nasleđuje od drugih objekata.

#### Ključne Razlike Između Tipova ACE-ova

* **Generički ACE-ovi** su pogodni za jednostavne scenarije kontrole pristupa, gde isto pravilo važi za sve aspekte objekta ili za sve objekte unutar kontejnera.
* **Objekat-Specifični ACE-ovi** se koriste za kompleksnije scenarije, posebno u okruženjima poput Active Directory-ja, gde možda treba kontrolisati pristup specifičnim svojstvima objekta na drugačiji način.

U suštini, ACL-i i ACE-ovi pomažu u definisanju preciznih kontrola pristupa, osiguravajući da samo odgovarajući pojedinci ili grupe imaju pristup osetljivim informacijama ili resursima, sa mogućnošću prilagođavanja prava pristupa do nivoa pojedinačnih svojstava ili tipova objekata.

### Izgled Unosa Kontrole Pristupa

| Polje ACE-a | Opis                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Tip         | Zastava koja označava tip ACE-a. Windows 2000 i Windows Server 2003 podržavaju šest tipova ACE-a: Tri generička tipa ACE-a koja su povezana sa svim objektima koji se mogu obezbediti. Tri objekat-specifična tipa ACE-a koja se mogu pojaviti za objekte Active Directory-ja.                                                                                                                                                                                            |
| Zastave     | Skup bitnih zastava koje kontrolišu nasleđivanje i reviziju.                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| Veličina    | Broj bajtova memorije koji su alocirani za ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| Maska pristupa | 32-bitna vrednost čiji bitovi odgovaraju pravima pristupa za objekat. Bitovi mogu biti postavljeni ili isključeni, ali značenje postavke zavisi od tipa ACE-a. Na primer, ako je bit koji odgovara pravu za čitanje dozvola uključen, a tip ACE-a je Odbijanje, ACE odbija pravo čitanja dozvola objekta. Ako je isti bit postavljen ali je tip ACE-a Dozvola, ACE dodeljuje pravo čitanja dozvola objekta. Više detalja o Maski pristupa pojavljuju se u sledećoj tabeli. |
| SID         | Identifikuje korisnika ili grupu čiji pristup kontroliše ili nadgleda ovaj ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Izgled Maske Pristupa

| Bit (Opseg) | Značenje                            | Opis/Primer                       |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | Specifična Prava Pristupa Objektu      | Čitanje podataka, Izvršavanje, Dodavanje podataka           |
| 16 - 22     | Standardna Prava Pristupa             | Brisanje, Pisanje ACL-a, Pisanje Vlasnika            |
| 23          | Može pristupiti sigurnosnom ACL-u            |                                           |
| 24 - 27     | Rezervisano                           |                                           |
| 28          | Generički SVE (Čitanje, Pisanje, Izvršavanje) | Sve ispod                          |
| 29          | Generičko Izvršavanje                    | Sve što je potrebno za izvršavanje programa |
| 30          | Generičko Pisanje                      | Sve što je potrebno za pisanje u fajl   |
| 31          | Generičko Čitanje                       | Sve što je potrebno za čitanje fajla       |

## Reference

* [https://www.ntfs.com/ntfs-permissions-acl-use.htm](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
* [https://secureidentity.se/acl-dacl-sacl-and-the-ace/](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)
* [https://www.coopware.in2.info/\_ntfsacl\_ht.htm](https://www.coopware.in2.info/\_ntfsacl\_ht.htm)

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF-u** Proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Koristite [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=acls-dacls-sacls-aces) da lako izgradite i **automatizujete tokove rada** pokretane najnaprednijim alatima zajednice na svetu.\
Dobijte Pristup Danas:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=acls-dacls-sacls-aces" %}
