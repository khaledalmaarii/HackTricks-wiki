{% hint style="success" %}
Učite i vežbajte hakovanje AWS-a: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte hakovanje GCP-a: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Delite hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}


<a rel="license" href="https://creativecommons.org/licenses/by-nc/4.0/"><img alt="Creative Commons License" style="border-width:0" src="https://licensebuttons.net/l/by-nc/4.0/88x31.png" /></a><br>Autorsko pravo © Carlos Polop 2021. Osim ako nije drugačije navedeno (spoljni podaci kopirani u knjigu pripadaju originalnim autorima), tekst na <a href="https://github.com/carlospolop/hacktricks">HACK TRICKS</a> od Carlos Polopa je licenciran pod <a href="https://creativecommons.org/licenses/by-nc/4.0/">Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)</a>.

Licenca: Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)<br>Čitljiva licenca: https://creativecommons.org/licenses/by-nc/4.0/<br>Kompletni pravni uslovi: https://creativecommons.org/licenses/by-nc/4.0/legalcode<br>Formatiranje: https://github.com/jmatsushita/Creative-Commons-4.0-Markdown/blob/master/licenses/by-nc.markdown<br>

# creative commons

# Attribution-NonCommercial 4.0 International

Korporacija Creative Commons ("Creative Commons") nije advokatska firma i ne pruža pravne usluge ili pravne savete. Distribucija javnih licenci Creative Commons ne stvara odnos advokat-klijent ili bilo koji drugi odnos. Creative Commons svoje licence i povezane informacije stavlja na raspolaganje "kakve jesu". Creative Commons ne daje nikakve garancije u vezi sa svojim licencama, materijalom licenciranim pod njihovim uslovima i uslovima ili bilo kojim povezanim informacijama. Creative Commons odbacuje svu odgovornost za štetu proizašlu iz njihove upotrebe u najvećoj mogućoj meri.

## Korišćenje javnih licenci Creative Commons

Javne licence Creative Commons pružaju standardni skup uslova koje kreatori i drugi nosioci prava mogu koristiti za deljenje originalnih autorskih dela i drugog materijala podložnog autorskim pravima i određenim drugim pravima navedenim u javnoj licenci ispod. Sledeće razmatranja su samo informativne prirode, nisu iscrpna i ne čine deo naših licenci.

* __Razmatranja za davaoce licenci:__ Naše javne licence namenjene su za korišćenje od strane onih koji su ovlašćeni da javnosti daju dozvolu za korišćenje materijala na načine koji su inače ograničeni autorskim pravima i određenim drugim pravima. Naše licence su neopozive. Davaoci licenci treba da pročitaju i razumeju uslove licence koju izaberu pre nego što je primene. Davaoci licenci takođe treba da obezbede sva potrebna prava pre primene naših licenci kako bi javnost mogla ponovo koristiti materijal kako se očekuje. Davaoci licenci treba jasno označe sav materijal koji nije predmet licence. To uključuje drugi materijal sa CC licencom ili materijal korišćen pod izuzetkom ili ograničenjem autorskih prava. [Više razmatranja za davaoce licenci](http://wiki.creativecommons.org/Considerations_for_licensors_and_licensees#Considerations_for_licensors).

* __Razmatranja za javnost:__ Korišćenjem jedne od naših javnih licenci, davalac licence daje javnosti dozvolu za korišćenje licenciranog materijala pod određenim uslovima. Ako dozvola davaoca licence nije potrebna iz bilo kog razloga - na primer, zbog bilo kog primenljivog izuzetka ili ograničenja autorskih prava - tada to korišćenje nije regulisano licencom. Naše licence daju samo dozvole u okviru autorskih prava i određenih drugih prava za koje davalac licence ima ovlašćenje da ih dodeli. Korišćenje licenciranog materijala može biti ograničeno iz drugih razloga, uključujući zato što drugi imaju autorska prava ili druga prava na materijal. Davalac licence može postaviti posebne zahteve, kao što je traženje da se sve promene označe ili opišu. Iako to nije obavezno prema našim licencama, ohrabrujemo vas da poštujete te zahteve gde je to razumno. [Više razmatranja za javnost](http://wiki.creativecommons.org/Considerations_for_licensors_and_licensees#Considerations_for_licensees).

# Creative Commons Attribution-NonCommercial 4.0 International Public License

Vršeći Licencirana Prava (definisana u nastavku), Vi prihvatate i saglasni ste da budete obavezani uslovima i odredbama ove Creative Commons Attribution-NonCommercial 4.0 International Public License ("Javna Licenca"). U meri u kojoj se ova Javna Licenca može tumačiti kao ugovor, Vi dobijate Licencirana Prava u obziru na Vaše prihvatanje ovih uslova i odredbi, a Davaoc licenci Vam dodeljuje takva prava u obziru na koristi koje Davaoc licenci dobija pravljenjem Licenciranog Materijala dostupnog pod ovim uslovima i odredbama.

## Sekcija 1 - Definicije.

a. __Prilagođeni Materijal__ znači materijal podložan autorskim pravima i sličnim pravima koji je izveden iz ili zasnovan na Licenciranom Materijalu i u kojem je Licencirani Materijal preveden, izmenjen, aranžiran, transformisan ili na drugi način modifikovan na način koji zahteva dozvolu prema autorskim pravima i sličnim pravima koje ima Davaoc licenci. U svrhe ove Javne Licence, gde je Licencirani Materijal muzičko delo, izvođenje ili tonski zapis, Prilagođeni Materijal uvek nastaje kada je Licencirani Materijal sinhronizovan u vremenskom odnosu sa pokretnom slikom.

b. __Licenca Prilagoditelja__ znači licencu koju primenjujete na Vaša autorska prava i slična prava u Vašim doprinosima Prilagođenom Materijalu u skladu sa uslovima ove Javne Licence.

c. __Autorska prava i slična prava__ znače autorska prava i/ili slična prava blisko povezana sa autorskim pravima, uključujući, bez ograničenja, izvođenje, emitovanje, tonski zapis i Sui Generis Database Rights, bez obzira na to kako su prava označena ili kategorizovana. U svrhe ove Javne Licence, prava navedena u Odeljku 2(b)(1)-(2) nisu Autorska prava i slična prava.

d. __Efektivne Tehnološke Mere__ znače mere koje, u odsustvu odgovarajuće ovlašćenosti, ne mogu biti zaobiđene u skladu sa zakonima koji ispunjavaju obaveze prema članu 11 Ugovora o autorskim pravima WIPO-a usvojenog 20. decembra 1996. godine, i/ili sličnim međunarodnim sporazumima.

e. __Izuzeci i Ograničenja__ znače pravičnu upotrebu, fer korišćenje i/ili bilo koji drugi izuzetak ili ograničenje autorskih prava i sličnih prava koje se odnose na Vašu upotrebu Licenciranog Materijala.

f. __Licencirani Materijal__ znači umetničko ili književno delo, bazu podataka ili drugi materijal na koji je Davaoc licenci primenio ovu Javnu Licencu.

g. __Licencirana Prava__ znače prava koja su Vam dodeljena pod uslovima ove Javne Licence, koja su ograničena na sva autorska prava i slična prava koja se odnose na Vašu upotrebu Licenciranog Materijala i koja Davaoc licenci ima ovlašćenje da licencira.

h. __Davaoc licenci__ znači fizičko ili pravno lice koje dodeljuje prava pod ovom Javnom Licencom.

i. __NonCommercial__ znači da nije pretežno namenjen ili usmeren ka komercijalnoj koristi ili novčanoj nadoknadi. U svrhe ove Javne Licence, razmena Licenciranog Materijala za drugi materijal podložan autorskim pravima i sličnim pravima putem deljenja digitalnih fajlova ili sličnih sredstava je NonCommercial pod uslovom da nema plaćanja novčane nadoknade u vezi sa razmenom.

j. __Deljenje__ znači pružanje materijala javnosti putem bilo kog sredstva ili procesa koji zahteva dozvolu pod Licenciranim Pravima, kao što su reprodukcija, javni prikaz, javno izvođenje, distribucija, širenje, komunikacija ili uvoz, i činjenje materijala dostupnim javnosti na načine na koje članovi javnosti mogu pristupiti materijalu sa mesta i u vreme koje su sami izabrali.

k. __Sui Generis Database Rights__ znače prava koja nisu autorska prava proizašla iz Direktive 96/9/EC Evropskog parlamenta i Saveta od 11. marta 1996. godine o pravnoj zaštiti baza podataka, kako je izmenjena i/ili nasledila, kao i druga suštinski ekvivalentna prava bilo gde u svetu.

l. __Vi__ znači fizičko ili pravno lice koje vrši Licencirana Prava pod ovom Javnom Licencom. Vaš ima odgovarajuće značenje.
## Sekcija 2 – Obuhvat.

a. ___Dodela licence.___

1. Pod uslovima ove Javne licence, Davaoc licence ovim putem dodeljuje Vama širom sveta, besplatnu, ne sublicenciranu, neekskluzivnu, neopozivu licencu za vršenje Licenciranih prava na Licenciranom materijalu radi:

A. reprodukcije i Deljenja Licenciranog materijala, u celini ili delimično, isključivo u nekomercijalne svrhe; i

B. proizvodnje, reprodukcije i Deljenja Prilagođenog materijala isključivo u nekomercijalne svrhe.

2. __Izuzeci i ograničenja.__ Radi izbegavanja nedoumica, gde Izuzeci i ograničenja važe za Vašu upotrebu, ova Javna licenca se ne primenjuje, i nije Vam potrebno da se pridržavate njenih uslova.

3. __Rok.__ Rok važenja ove Javne licence je naveden u Sekciji 6(a).

4. __Mediji i formati; dozvoljene tehničke modifikacije.__ Davaoc licence Vam ovlašćuje da vršite Licencirana prava u svim medijima i formatima, bilo da su trenutno poznati ili stvoreni u budućnosti, i da vršite tehničke modifikacije neophodne za to. Davaoc licence odriče se i/ili se slaže da neće tvrditi bilo koje pravo ili ovlašćenje da Vam zabrani da vršite tehničke modifikacije neophodne za vršenje Licenciranih prava, uključujući tehničke modifikacije neophodne za zaobilaženje Efikasnih tehnoloških mera. U svrhe ove Javne licence, jednostavno vršenje modifikacija ovlašćenih ovom Sekcijom 2(a)(4) nikada ne proizvodi Prilagođeni materijal.

5. __Krajnji korisnici.__

A. __Ponuda od Davaoca licence – Licencirani materijal.__ Svaki primalac Licenciranog materijala automatski prima ponudu od Davaoca licence da vrši Licencirana prava pod uslovima ove Javne licence.

B. __Bez ograničenja prema nizvodno.__ Ne smete ponuditi ili nametnuti bilo kakve dodatne ili različite uslove ili primeniti bilo koje Efikasne tehnološke mere na Licencirani materijal ako to ograničava vršenje Licenciranih prava od strane bilo kog primaoca Licenciranog materijala.

6. __Bez preporuke.__ Ništa u ovoj Javnoj licenci ne predstavlja ili se ne može tumačiti kao dozvola da tvrdite ili implicirate da ste Vi, ili da je Vaša upotreba Licenciranog materijala, povezana sa, ili sponzorisana, podržana ili dodeljen zvanični status od strane Davaoca licence ili drugih ovlašćenih da prime atribuciju kako je predviđeno u Sekciji 3(a)(1)(A)(i).

b. ___Druga prava.___

1. Moralna prava, kao što je pravo na integritet, nisu licencirana ovom Javnom licencom, niti javnost, privatnost i/ili druga slična prava ličnosti; međutim, u meri u kojoj je moguće, Davaoc licence odriče se i/ili se slaže da ne tvrdi bilo kakva takva prava koja poseduje Davaoc licence u ograničenoj meri neophodnoj da Vam omogući vršenje Licenciranih prava, ali ne i drugačije.

2. Patentna i zaštitna prava nisu licencirana ovom Javnom licencom.

3. U meri u kojoj je moguće, Davaoc licence odriče se prava da naplati naknadu od Vas za vršenje Licenciranih prava, bilo direktno ili putem udruženja za naplatu naknada u okviru bilo kog dobrovoljnog ili obaveznog sistema licenciranja. U svim ostalim slučajevima, Davaoc licence izričito zadržava pravo da naplati takve naknade, uključujući kada se Licencirani materijal koristi za nekomercijalne svrhe.

## Sekcija 3 – Uslovi licence.

Vaše vršenje Licenciranih prava izričito je podložno sledećim uslovima.

a. ___Atribucija.___

1. Ako Delite Licencirani materijal (uključujući u modifikovanom obliku), morate:

A. zadržati sledeće ako je dostavljeno od strane Davaoca licence uz Licencirani materijal:

i. identifikaciju autora Licenciranog materijala i svih drugih ovlašćenih da prime atribuciju, na bilo koji razuman način koji zatraži Davaoc licence (uključujući pod pseudonimom ako je određeno);

ii. obaveštenje o autorskim pravima;

iii. obaveštenje koje se odnosi na ovu Javnu licencu;

iv. obaveštenje koje se odnosi na odricanje od garancija;

v. URI ili hiperlink do Licenciranog materijala koliko je razumno izvodljivo;

B. naznačiti da li ste modifikovali Licencirani materijal i zadržati naznaku bilo kakvih prethodnih modifikacija; i

C. naznačiti da je Licencirani materijal licenciran pod ovom Javnom licencom, i uključiti tekst, ili URI ili hiperlink do, ove Javne licence.

2. Možete ispuniti uslove u Sekciji 3(a)(1) na bilo koji razuman način zasnovan na mediju, sredstvima i kontekstu u kojem Delite Licencirani materijal. Na primer, može biti razumno ispuniti uslove pružanjem URI-ja ili hiperlinka do resursa koji sadrži potrebne informacije.

3. Ako zatraženo od strane Davaoca licence, morate ukloniti bilo koje od informacija potrebnih prema Sekciji 3(a)(1)(A) koliko je razumno izvodljivo.

4. Ako Delite Prilagođeni materijal koji proizvedete, Licenca Adaptera koju primenjujete ne sme sprečiti primaoca Prilagođenog materijala da se pridržava ove Javne licence.

## Sekcija 4 – Sui Generis prava baze podataka.

Gde Licencirana prava uključuju Sui Generis prava baze podataka koja se odnose na Vašu upotrebu Licenciranog materijala:

a. radi izbegavanja nedoumica, Sekcija 2(a)(1) Vam dodeljuje pravo da izvučete, ponovo koristite, reprodukujete i Delite sve ili značajan deo sadržaja baze podataka isključivo u nekomercijalne svrhe;

b. ako uključite sve ili značajan deo sadržaja baze podataka u bazu podataka u kojoj imate Sui Generis prava baze podataka, tada je baza podataka u kojoj imate Sui Generis prava baze podataka (ali ne njeni pojedinačni sadržaji) Prilagođeni materijal; i

c. Morate se pridržavati uslova u Sekciji 3(a) ako Delite sve ili značajan deo sadržaja baze podataka.

Radi izbegavanja nedoumica, ova Sekcija 4 dopunjuje, a ne zamenjuje Vaše obaveze prema ovoj Javnoj licenci gde Licencirana prava uključuju druga autorska i srodna prava.

## Sekcija 5 – Odricanje od garancija i ograničenje odgovornosti.

a. __Osim ako Davaoc licence posebno preuzme, u meri u kojoj je moguće, Davaoc licence nudi Licencirani materijal u stanju u kojem se nalazi i dostupan je, i ne daje nikakve izjave ili garancije bilo koje vrste u vezi sa Licenciranim materijalom, bilo da su eksplicitne, implicitne, zakonske ili druge. To uključuje, bez ograničenja, garancije naslova, trgovinske sposobnosti, odgovarajućnosti za određenu svrhu, nekršenja, odsustva skrivenih ili drugih grešaka, tačnosti, ili prisustva ili odsustva grešaka, bilo da su poznate ili otkrivene. Gde odricanja od garancija nisu dozvoljena u celini ili delimično, ovo odricanje se možda neće primenjivati na Vas.__

b. __U meri u kojoj je moguće, u nijednom slučaju Davaoc licence neće biti odgovoran prema Vama po bilo kojoj pravnoj teoriji (uključujući, bez ograničenja, nemar) ili na drugi način za bilo kakve direktni, posebne, indirektne, slučajne, posledične, kaznene, primerne ili druge gubitke, troškove, rashode ili štetu proizašlu iz ove Javne licence ili upotrebe Licenciranog materijala, čak i ako je Davaoc licence obavešten o mogućnosti takvih gubitaka, troškova, rashoda ili štete. Gde ograničenje odgovornosti nije dozvoljeno u celini ili delimično, ovo ograničenje se možda neće primenjivati na Vas.__

c. Odricanje od garancija i ograničenje odgovornosti navedeno gore će se tumačiti na način koji, u meri u kojoj je moguće, najbliže odgovara apsolutnom odricanju i odricanju od svake odgovornosti.

## Sekcija 6 – Rok i raskid.

a. Ova Javna licenca važi za trajanje autorskih i srodnih prava ovde licenciranih. Međutim, ako ne ispunite ovu Javnu licencu, tada Vaša prava prema ovoj Javnoj licenci automatski prestaju.

b. Gde je Vaše pravo da koristite Licencirani materijal prestalo prema Sekciji 6(a), ono se ponovo uspostavlja:

1. automatski od datuma kada se prekršaj otkloni, pod uslovom da je otklonjen u roku od 30 dana od Vašeg otkrića prekršaja; ili

2. na izričit zahtev Davaoca licence.

Radi izbegavanja nedoumica, ova Sekcija 6(b) ne utiče na bilo koje pravo koje Davaoc licence može imati da traži pravna sredstva za Vaše kršenje ove Javne licence.

c. Radi izbegavanja nedoumica, Davaoc licence takođe može ponuditi Licencirani materijal pod posebnim uslovima ili prekinuti distribuciju Licenciranog materijala u bilo koje vreme; međutim, to neće okončati ovu Javnu licencu.

d. Sekcije 1, 5, 6, 7 i 8 opstaju nakon prestanka ove Javne licence.
## Sekcija 7 - Ostali Uslovi i Odredbe.

a. Davaoc licence neće biti obavezan bilo kojim dodatnim ili različitim uslovima ili odredbama koje ste Vi saopštili, osim ako nije izričito dogovoreno.

b. Sve aranžmane, razumevanja ili sporazume u vezi sa Licenciranim materijalom koji nisu navedeni ovde smatraju se odvojenim i nezavisnim od uslova ove Javne licence.

## Sekcija 8 - Tumačenje.

a. Radi izbegavanja nedoumica, ova Javna licenca ne smanjuje, ne ograničava, ne restriktuje niti ne nameće uslove na bilo koju upotrebu Licenciranog materijala koja bi se zakonito mogla obaviti bez dozvole prema ovoj Javnoj licenci.

b. U meri u kojoj je moguće, ako se odredba ove Javne licence smatra neizvršnom, automatski će biti reformisana do minimalne mere potrebne da bi postala izvršna. Ako odredba ne može biti reformisana, biće odvojena od ove Javne licence bez uticaja na izvršnost preostalih uslova i odredbi.

c. Nijedan uslov ove Javne licence neće biti odstupljen i nijedno nepoštovanje neće biti odobreno osim ako nije izričito dogovoreno od strane Davaoca licence.

d. Ništa u ovoj Javnoj licenci ne predstavlja niti se može tumačiti kao ograničenje ili odricanje od bilo kakvih privilegija i imuniteta koji se odnose na Davaoca licence ili Vas, uključujući pravne postupke bilo koje nadležnosti ili vlasti.
```
Creative Commons is not a party to its public licenses. Notwithstanding, Creative Commons may elect to apply one of its public licenses to material it publishes and in those instances will be considered the “Licensor.” Except for the limited purpose of indicating that material is shared under a Creative Commons public license or as otherwise permitted by the Creative Commons policies published at [creativecommons.org/policies](http://creativecommons.org/policies), Creative Commons does not authorize the use of the trademark “Creative Commons” or any other trademark or logo of Creative Commons without its prior written consent including, without limitation, in connection with any unauthorized modifications to any of its public licenses or any other arrangements, understandings, or agreements concerning use of licensed material. For the avoidance of doubt, this paragraph does not form part of the public licenses.

Creative Commons may be contacted at [creativecommons.org](http://creativecommons.org/).
```
{% hint style="success" %}
Učite i vežbajte hakovanje AWS-a: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte hakovanje GCP-a: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
