# ACLs - DACLs/SACLs/ACEs

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Koristite [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=acls-dacls-sacls-aces) za lako kreiranje i **automatizaciju radnih tokova** pokretanih najnaprednijim alatima zajednice na svetu.\
Pribavite pristup danas:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=acls-dacls-sacls-aces" %}

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podrška HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}

## **Lista Kontrole Pristupa (ACL)**

Lista Kontrole Pristupa (ACL) se sastoji od uređenog skupa Unosa Kontrole Pristupa (ACE) koji određuju zaštitu za objekat i njegove osobine. U suštini, ACL definiše koje akcije od strane kojih sigurnosnih principa (korisnika ili grupa) su dozvoljene ili odbijene na datom objektu.

Postoje dve vrste ACL:

* **Diskreciona Lista Kontrole Pristupa (DACL):** Specifikuje koji korisnici i grupe imaju ili nemaju pristup objektu.
* **Sistematska Lista Kontrole Pristupa (SACL):** Upravlja revizijom pokušaja pristupa objektu.

Proces pristupanja datoteci uključuje sistem koji proverava sigurnosni opis objekta u odnosu na pristupni token korisnika kako bi odredio da li pristup treba biti odobren i u kojoj meri, na osnovu ACE.

### **Ključne Komponente**

* **DACL:** Sadrži ACE koji dodeljuju ili odbijaju dozvole pristupa korisnicima i grupama za objekat. To je suštinski glavna ACL koja diktira prava pristupa.
* **SACL:** Koristi se za reviziju pristupa objektima, gde ACE definišu tipove pristupa koji se beleže u Bezbednosnom Dnevniku Događaja. Ovo može biti neprocenjivo za otkrivanje neovlašćenih pokušaja pristupa ili rešavanje problema sa pristupom.

### **Interakcija Sistema sa ACL**

Svaka korisnička sesija je povezana sa pristupnim tokenom koji sadrži sigurnosne informacije relevantne za tu sesiju, uključujući identitete korisnika, grupa i privilegije. Ovaj token takođe uključuje SID za prijavu koji jedinstveno identifikuje sesiju.

Lokalna Bezbednosna Autoritet (LSASS) obrađuje zahteve za pristup objektima ispitujući DACL za ACE koji odgovaraju sigurnosnom principu koji pokušava pristup. Pristup se odmah odobrava ako se ne pronađu relevantni ACE. U suprotnom, LSASS upoređuje ACE sa SID-om sigurnosnog principa u pristupnom tokenu kako bi odredio podobnost za pristup.

### **Sažeti Proces**

* **ACL:** Definišu dozvole pristupa kroz DACL i pravila revizije kroz SACL.
* **Pristupni Token:** Sadrži informacije o korisniku, grupi i privilegijama za sesiju.
* **Odluka o Pristupu:** Donosi se upoređivanjem DACL ACE sa pristupnim tokenom; SACL se koristi za reviziju.

### ACEs

Postoje **tri glavne vrste Unosa Kontrole Pristupa (ACE)**:

* **ACE Odbijen Pristup**: Ovaj ACE izričito odbija pristup objektu za određene korisnike ili grupe (u DACL).
* **ACE Dozvoljen Pristup**: Ovaj ACE izričito odobrava pristup objektu za određene korisnike ili grupe (u DACL).
* **Sistematski Revizorski ACE**: Postavljen unutar Sistematske Liste Kontrole Pristupa (SACL), ovaj ACE je odgovoran za generisanje revizorskih dnevnika prilikom pokušaja pristupa objektu od strane korisnika ili grupa. Beleži da li je pristup bio odobren ili odbijen i prirodu pristupa.

Svaki ACE ima **četiri ključne komponente**:

1. **Identifikator Sigurnosti (SID)** korisnika ili grupe (ili njihovo ime principa u grafičkoj reprezentaciji).
2. **Zastavica** koja identifikuje tip ACE (pristup odbijen, dozvoljen ili sistematska revizija).
3. **Zastavice nasleđivanja** koje određuju da li deca objekti mogu nasleđivati ACE od svog roditelja.
4. [**Maska pristupa**](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN), 32-bitna vrednost koja specificira prava dodeljena objektu.

Određivanje pristupa se vrši sekvencijalnim ispitivanjem svakog ACE dok:

* **ACE Odbijen Pristup** izričito odbija tražena prava poveriocu identifikovanom u pristupnom tokenu.
* **ACE Dozvoljen Pristup** izričito odobrava sva tražena prava poveriocu u pristupnom tokenu.
* Nakon provere svih ACE, ako bilo koje traženo pravo **nije izričito odobreno**, pristup je implicitno **odbijen**.

### Redosled ACE

Način na koji su **ACE** (pravila koja kažu ko može ili ne može pristupiti nečemu) postavljeni u listu nazvanu **DACL** je veoma važan. To je zato što, kada sistem dodeli ili odbije pristup na osnovu ovih pravila, prestaje da gleda ostatak.

Postoji najbolji način za organizovanje ovih ACE, a to se zove **"kanonski red."** Ova metoda pomaže da se osigura da sve funkcioniše glatko i pravedno. Evo kako to ide za sisteme poput **Windows 2000** i **Windows Server 2003**:

* Prvo, stavite sva pravila koja su napravljena **specifično za ovu stavku** pre onih koja dolaze od nekuda drugde, poput roditeljskog foldera.
* U tim specifičnim pravilima, stavite ona koja kažu **"ne" (odbiti)** pre onih koja kažu **"da" (dozvoliti)**.
* Za pravila koja dolaze od nekuda drugde, počnite sa onima iz **najbližeg izvora**, poput roditelja, a zatim se vraćajte odatle. Ponovo, stavite **"ne"** pre **"da."**

Ova postavka pomaže na dva velika načina:

* Osigurava da, ako postoji specifično **"ne,"** to bude poštovano, bez obzira na to koja druga **"da"** pravila postoje.
* Omogućava vlasniku stavke da ima **konačnu reč** o tome ko može da uđe, pre nego što se primene bilo koja pravila iz roditeljskih foldera ili dalje.

Na ovaj način, vlasnik datoteke ili foldera može biti veoma precizan u vezi sa tim ko dobija pristup, osiguravajući da prave osobe mogu da uđu, a pogrešne ne mogu.

![](https://www.ntfs.com/images/screenshots/ACEs.gif)

Dakle, ovaj **"kanonski red"** se odnosi na osiguranje da su pravila pristupa jasna i da dobro funkcionišu, stavljajući specifična pravila na prvo mesto i organizujući sve na pametan način.

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Koristite [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) za lako kreiranje i **automatizaciju radnih tokova** pokretanih najnaprednijim alatima zajednice na svetu.\
Pribavite pristup danas:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### GUI Primer

[**Primer odavde**](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)

Ovo je klasična sigurnosna kartica foldera koja prikazuje ACL, DACL i ACE:

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../.gitbook/assets/classicsectab.jpg)

Ako kliknemo na **Napredni dugme**, dobićemo više opcija kao što je nasleđivanje:

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../.gitbook/assets/aceinheritance.jpg)

I ako dodate ili izmenite Sigurnosni Princip:

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../.gitbook/assets/editseprincipalpointers1.jpg)

I na kraju imamo SACL u kartici Revizija:

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../.gitbook/assets/audit-tab.jpg)

### Objašnjenje Kontrole Pristupa na Pojednostavljen Način

Kada upravljamo pristupom resursima, poput foldera, koristimo liste i pravila poznata kao Liste Kontrole Pristupa (ACL) i Unosi Kontrole Pristupa (ACE). Ova pravila definišu ko može ili ne može pristupiti određenim podacima.

#### Odbijanje Pristupa Specifičnoj Grupi

Zamislite da imate folder nazvan Troškovi, i želite da svi imaju pristup osim marketinške ekipe. Postavljanjem pravila na pravi način, možemo osigurati da marketinška ekipa bude izričito odbijena pristup pre nego što se dozvoli svima ostalima. To se postiže postavljanjem pravila za odbijanje pristupa marketinškoj ekipi pre pravila koje dozvoljava pristup svima.

#### Dozvoljavanje Pristupa Specifičnom Članu Odbijene Grupe

Recimo da Bob, direktor marketinga, treba pristup folderu Troškovi, iako marketinška ekipa generalno ne bi trebala imati pristup. Možemo dodati specifično pravilo (ACE) za Boba koje mu dodeljuje pristup, i postaviti ga pre pravila koje odbija pristup marketinškoj ekipi. Na ovaj način, Bob dobija pristup uprkos opštem ograničenju na njegov tim.

#### Razumevanje Unosa Kontrole Pristupa

ACE su pojedinačna pravila u ACL. Ona identifikuju korisnike ili grupe, specificiraju koji pristup je dozvoljen ili odbijen, i određuju kako se ova pravila primenjuju na podstavke (nasleđivanje). Postoje dve glavne vrste ACE:

* **Generički ACE:** Ovi se primenjuju široko, utičući ili na sve tipove objekata ili razlikujući samo između kontejnera (poput foldera) i nekontejnera (poput datoteka). Na primer, pravilo koje dozvoljava korisnicima da vide sadržaj foldera, ali ne i da pristupe datotekama unutar njega.
* **Specifični ACE:** Ovi pružaju precizniju kontrolu, omogućavajući postavljanje pravila za specifične tipove objekata ili čak pojedinačne osobine unutar objekta. Na primer, u direktorijumu korisnika, pravilo može dozvoliti korisniku da ažurira svoj broj telefona, ali ne i svoje radno vreme.

Svaki ACE sadrži važne informacije kao što su ko se pravilo primenjuje (koristeći Identifikator Sigurnosti ili SID), šta pravilo dozvoljava ili odbija (koristeći masku pristupa), i kako se nasleđuje od drugih objekata.

#### Ključne Razlike Između Tipova ACE

* **Generički ACE** su pogodna za jednostavne scenarije kontrole pristupa, gde se isto pravilo primenjuje na sve aspekte objekta ili na sve objekte unutar kontejnera.
* **Specifični ACE** se koriste za složenije scenarije, posebno u okruženjima poput Active Directory, gde možda treba kontrolisati pristup specifičnim osobinama objekta na drugačiji način.

U sažetku, ACL i ACE pomažu u definisanju preciznih kontrola pristupa, osiguravajući da samo prave osobe ili grupe imaju pristup osetljivim informacijama ili resursima, sa mogućnošću prilagođavanja prava pristupa do nivoa pojedinačnih osobina ili tipova objekata.

### Raspored Unosa Kontrole Pristupa

| ACE Polje   | Opis                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Tip         | Zastavica koja označava tip ACE. Windows 2000 i Windows Server 2003 podržavaju šest tipova ACE: Tri generička tipa ACE koja su prikačena svim objektima koji se mogu obezbediti. Tri specifična tipa ACE koja se mogu pojaviti za Active Directory objekte.                                                                                                                                                                                                                                                            |
| Zastavice   | Skup bit zastavica koje kontrolišu nasleđivanje i reviziju.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Veličina    | Broj bajtova memorije koji su dodeljeni za ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Maska pristupa | 32-bitna vrednost čiji bitovi odgovaraju pravima pristupa za objekat. Bitovi se mogu postaviti ili uključiti ili isključiti, ali značenje postavke zavisi od tipa ACE. Na primer, ako je bit koji odgovara pravu na čitanje dozvola uključen, a tip ACE je Odbij, ACE odbija pravo na čitanje dozvola objekta. Ako je isti bit uključen, ali je tip ACE Dozvoli, ACE odobrava pravo na čitanje dozvola objekta. Više detalja o maski pristupa pojavljuje se u sledećoj tabeli. |
| SID         | Identifikuje korisnika ili grupu čiji je pristup kontrolisan ili nadgledan ovim ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Raspored Maske Pristupa

| Bit (Opseg) | Značenje                            | Opis/Primer                       |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | Specifična Prava Pristupa      | Čitaj podatke, Izvrši, Dodaj podatke           |
| 16 - 22     | Standardna Prava Pristupa             | Obriši, Piši ACL, Piši Vlasnika            |
| 23          | Može pristupiti sigurnosnom ACL            |                                           |
| 24 - 27     | Rezervisano                           |                                           |
| 28          | Generički SVI (Čitaj, Piši, Izvrši) | Sve ispod                          |
| 29          | Generički Izvrši                    | Sve što je potrebno za izvršavanje programa |
| 30          | Generički Piši                      | Sve što je potrebno za pisanje u datoteku   |
| 31          | Generički Čitaj                       | Sve što je potrebno za čitanje datoteke       |

## Reference

* [https://www.ntfs.com/ntfs-permissions-acl-use.htm](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
* [https://secureidentity.se/acl-dacl-sacl-and-the-ace/](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)
* [https://www.coopware.in2.info/_ntfsacl_ht.htm](https://www.coopware.in2.info/_ntfsacl_ht.htm)

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podrška HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Koristite [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=acls-dacls-sacls-aces) za lako kreiranje i **automatizaciju radnih tokova** pokretanih najnaprednijim alatima zajednice na svetu.\
Pribavite pristup danas:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=acls-dacls-sacls-aces" %}
