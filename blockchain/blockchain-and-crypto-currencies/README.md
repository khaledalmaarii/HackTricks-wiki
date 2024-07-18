{% hint style="success" %}
Učite i vežbajte hakovanje AWS-a:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Obuka AWS Crveni Tim Stručnjak (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte hakovanje GCP-a: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Obuka GCP Crveni Tim Stručnjak (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}


## Osnovni Koncepti

- **Pametni Ugovori** su programi koji se izvršavaju na blockchain-u kada se ispune određeni uslovi, automatizujući izvršenje sporazuma bez posrednika.
- **Decentralizovane Aplikacije (dApps)** se grade na pametnim ugovorima, sa korisnički prijateljskim front-endom i transparentnim, revizibilnim back-endom.
- **Tokeni & Kovanice** se razlikuju gde kovanice služe kao digitalni novac, dok tokeni predstavljaju vrednost ili vlasništvo u specifičnim kontekstima.
- **Tokeni za Upotrebu** omogućavaju pristup uslugama, a **Tokeni za Bezbednost** označavaju vlasništvo nad imovinom.
- **DeFi** označava Decentralizovanu Finansiju, nudeći finansijske usluge bez centralnih autoriteta.
- **DEX** i **DAOs** se odnose na Decentralizovane Platforme za Razmenu i Decentralizovane Autonomne Organizacije, redom.

## Mehanizmi Konsenzusa

Mehanizmi konsenzusa osiguravaju sigurnu i dogovorenu validaciju transakcija na blockchain-u:
- **Dokaz o Radu (PoW)** se oslanja na računarsku snagu za verifikaciju transakcija.
- **Dokaz o Deonici (PoS)** zahteva od validatara da drže određenu količinu tokena, smanjujući potrošnju energije u poređenju sa PoW-om.

## Bitcoin Osnove

### Transakcije

Bitcoin transakcije uključuju prenos sredstava između adresa. Transakcije se validiraju putem digitalnih potpisa, osiguravajući da samo vlasnik privatnog ključa može pokrenuti transfere.

#### Ključni Elementi:

- **Transakcije sa Više Potpisa** zahtevaju više potpisa za autorizaciju transakcije.
- Transakcije se sastoje od **ulaza** (izvor sredstava), **izlaza** (odredište), **naknada** (plaćene rudarima) i **skripti** (pravila transakcije).

### Mreža Munje

Cilj je unaprediti skalabilnost Bitcoina omogućavajući višestruke transakcije unutar kanala, emitujući samo konačno stanje na blockchain.

## Bitcoin Problemi Privatnosti

Napadi na privatnost, poput **Zajedničkog Vlasništva Ulaza** i **Detekcije Adrese Promene UTXO**, iskorišćavaju obrasce transakcija. Strategije poput **Miksera** i **CoinJoin-a** poboljšavaju anonimnost zamagljujući veze transakcija između korisnika.

## Anonimno Sticanje Bitcoina

Metode uključuju trgovinu gotovinom, rudarenje i korišćenje miksera. **CoinJoin** meša više transakcija kako bi otežao praćenje, dok **PayJoin** prikriva CoinJoin-ove kao redovne transakcije za veću privatnost.


# Napadi na Privatnost Bitcoina

# Rezime Napada na Privatnost Bitcoina

U svetu Bitcoina, privatnost transakcija i anonimnost korisnika često su predmeti zabrinutosti. Evo pojednostavljenog pregleda nekoliko uobičajenih metoda putem kojih napadači mogu ugroziti privatnost Bitcoina.

## **Pretpostavka o Zajedničkom Vlasništvu Ulaza**

Općenito je retko da ulazi od različitih korisnika budu kombinovani u jednoj transakciji zbog uključene složenosti. Stoga, **dva ulazna adresa u istoj transakciji često se pretpostavljaju da pripadaju istom vlasniku**.

## **Detekcija Adrese Promene UTXO**

UTXO, ili **Neiskorišćeni Izlaz Transakcije**, mora biti u potpunosti potrošen u transakciji. Ako se samo deo njega pošalje na drugu adresu, preostali deo ide na novu adresu promene. Posmatrači mogu pretpostaviti da nova adresa pripada pošiljaocu, ugrožavajući privatnost.

### Primer
Da bi se to izbeglo, usluge mešanja ili korišćenje više adresa mogu pomoći u zamagljivanju vlasništva.

## **Izloženost na Društvenim Mrežama i Forumima**

Korisnici ponekad dele svoje Bitcoin adrese na mreži, čime postaje **lako povezati adresu sa njenim vlasnikom**.

## **Analiza Grafa Transakcija**

Transakcije se mogu vizualizovati kao grafovi, otkrivajući potencijalne veze između korisnika na osnovu toka sredstava.

## **Heuristika Nepotrebnog Ulaza (Optimalna Heuristika Promene)**

Ova heuristika se zasniva na analizi transakcija sa više ulaza i izlaza kako bi se pretpostavilo koji izlaz je promena koja se vraća pošiljaocu.

### Primer
```bash
2 btc --> 4 btc
3 btc     1 btc
```
## **Prinuda Ponovne Upotrebe Adrese**

Napadači mogu poslati male iznose na prethodno korišćene adrese, nadajući se da će primalac te iznose kombinovati sa drugim ulazima u budućim transakcijama, čime se povezuju adrese.

### Ispravno Ponašanje Novčanika
Novčanici treba da izbegavaju korišćenje novčića primljenih na već korišćenim, praznim adresama kako bi sprečili ovaj curenje privatnosti.

## **Druge Tehnike Analize Blokčejna**

- **Tačni Iznosi Plaćanja:** Transakcije bez kusura verovatno su između dve adrese koje pripadaju istom korisniku.
- **Zaokruženi Brojevi:** Zaokružen broj u transakciji sugeriše da je to plaćanje, pri čemu je izlaz koji nije zaokružen verovatno kusur.
- **Identifikacija Novčanika:** Različiti novčanici imaju jedinstvene obrasce kreiranja transakcija, što analitičarima omogućava da identifikuju korišćeni softver i potencijalno adresu kusura.
- **Korelacije Iznosa i Vremena:** Otkrivanje vremena ili iznosa transakcije može učiniti transakcije pratljivim.

## **Analiza Saobraćaja**

Prateći mrežni saobraćaj, napadači mogu potencijalno povezati transakcije ili blokove sa IP adresama, ugrožavajući privatnost korisnika. Ovo je posebno tačno ako entitet upravlja mnogo Bitcoin čvorova, poboljšavajući njihovu sposobnost praćenja transakcija.

## Više
Za sveobuhvatan spisak napada na privatnost i odbrane, posetite [Privatnost Bitkoina na Bitkoin Wiki](https://en.bitcoin.it/wiki/Privacy).


# Anonimne Bitkoin Transakcije

## Načini za Anonimno Dobijanje Bitkoina

- **Gotovinske Transakcije**: Dobijanje bitkoina putem gotovine.
- **Alternativne Gotovinske Opcije**: Kupovina poklon kartica i razmena istih za bitkoin online.
- **Rudarenje**: Najprivatniji način za zaradu bitkoina je putem rudarenja, posebno kada se radi samostalno jer rudarski bazeni mogu znati IP adresu rudara. [Informacije o Rudarskim Bazenima](https://en.bitcoin.it/wiki/Pooled_mining)
- **Krađa**: Teorijski, krađa bitkoina mogla bi biti još jedan način za anonimno sticanje istih, iako je ilegalna i nije preporučljiva.

## Usluge Mešanja

Korišćenjem usluge mešanja, korisnik može **poslati bitkoine** i dobiti **različite bitkoine zauzvrat**, što otežava praćenje originalnog vlasnika. Ipak, ovo zahteva poverenje u uslugu da ne čuva logove i da zapravo vrati bitkoine. Alternativne opcije mešanja uključuju Bitkoin kazina.

## CoinJoin

**CoinJoin** spaja više transakcija različitih korisnika u jednu, komplikujući proces za svakoga ko pokušava da upari ulaze sa izlazima. Uprkos njegovoj efikasnosti, transakcije sa jedinstvenim veličinama ulaza i izlaza i dalje mogu potencijalno biti praćene.

Primeri transakcija koje su možda koristile CoinJoin uključuju `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` i `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Za više informacija, posetite [CoinJoin](https://coinjoin.io/en). Za sličnu uslugu na Ethereumu, pogledajte [Tornado Cash](https://tornado.cash), koji anonimizira transakcije sa sredstvima od rudara.

## PayJoin

Varijanta CoinJoin-a, **PayJoin** (ili P2EP), prikriva transakciju između dve strane (npr. kupca i trgovca) kao redovnu transakciju, bez karakterističnih jednakih izlaza karakterističnih za CoinJoin. Ovo ga čini izuzetno teškim za otkrivanje i moglo bi poništiti heuristiku zajedničkog vlasništva ulaza koju koriste entiteti za nadzor transakcija.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transakcije poput one iznad mogu biti PayJoin, poboljšavajući privatnost dok ostaju neodvojive od standardnih bitkoin transakcija.

**Korišćenje PayJoin-a može značajno poremetiti tradicionalne metode nadzora**, čineći ga obećavajućim razvojem u potrazi za transakcionom privatnošću.


# Najbolje prakse za privatnost u kriptovalutama

## **Tehnike sinhronizacije novčanika**

Za održavanje privatnosti i sigurnosti, sinhronizacija novčanika sa blokčejnom je ključna. Ističu se dva metoda:

- **Puni čvor**: Preuzimanjem celog blokčejna, puni čvor obezbeđuje maksimalnu privatnost. Sve transakcije ikada napravljene se čuvaju lokalno, čineći nemogućim da protivnici identifikuju koje transakcije ili adrese korisniku interesuju.
- **Filtriranje blokova na strani klijenta**: Ovaj metod uključuje kreiranje filtera za svaki blok u blokčejnu, omogućavajući novčanicima da identifikuju relevantne transakcije bez otkrivanja specifičnih interesa mrežnim posmatračima. Lagani novčanici preuzimaju ove filtere, samo preuzimajući pune blokove kada se pronađe podudaranje sa adresama korisnika.

## **Korišćenje Tora za anonimnost**

S obzirom da Bitkoin funkcioniše na peer-to-peer mreži, preporučuje se korišćenje Tora kako bi se sakrila vaša IP adresa, poboljšavajući privatnost prilikom interakcije sa mrežom.

## **Prevencija ponovne upotrebe adresa**

Da bi se sačuvala privatnost, važno je koristiti novu adresu za svaku transakciju. Ponovna upotreba adresa može ugroziti privatnost povezivanjem transakcija sa istim entitetom. Moderni novčanici odvraćaju od ponovne upotrebe adresa svojim dizajnom.

## **Strategije za privatnost transakcija**

- **Višestruke transakcije**: Deljenje plaćanja na nekoliko transakcija može zamagliti iznos transakcije, ometajući napade na privatnost.
- **Izbegavanje kusura**: Odabir transakcija koje ne zahtevaju izlaz za kusur poboljšava privatnost ometanjem metoda detekcije kusura.
- **Višestruki izlazi za kusur**: Ako izbegavanje kusura nije izvodljivo, generisanje više izlaza za kusur i dalje može poboljšati privatnost.

# **Monero: Znak anonimnosti**

Monero adresira potrebu za apsolutnom anonimnošću u digitalnim transakcijama, postavljajući visok standard za privatnost.

# **Ethereum: Gas i Transakcije**

## **Razumevanje Gasa**

Gas meri računarski napor potreban za izvršavanje operacija na Ethereumu, cenjen u **gwei**-ima. Na primer, transakcija koja košta 2.310.000 gwei (ili 0,00231 ETH) uključuje limit gasa, osnovnu naknadu i napojnicu za podsticanje rudara. Korisnici mogu postaviti maksimalnu naknadu kako bi se osigurali da ne preplate, sa vraćanjem viška.

## **Izvršavanje transakcija**

Transakcije na Ethereumu uključuju pošiljaoca i primaoca, koji mogu biti adrese korisnika ili pametnih ugovora. Zahtevaju naknadu i moraju biti rudarene. Bitne informacije u transakciji uključuju primaoca, potpis pošiljaoca, vrednost, opcioni podaci, limit gasa i naknade. Važno je napomenuti da se adresa pošiljaoca dedukuje iz potpisa, eliminišući potrebu za njom u podacima transakcije.

Ove prakse i mehanizmi su osnovni za svakoga ko želi da se bavi kriptovalutama uz prioritizaciju privatnosti i sigurnosti.


## Reference

* [https://en.wikipedia.org/wiki/Proof\_of\_stake](https://en.wikipedia.org/wiki/Proof\_of\_stake)
* [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
* [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
* [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
* [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
* [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced\_address\_reuse)
