# Otkrivanje Phishinga

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** Proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## Uvod

Da biste otkrili pokušaj phishinga, važno je **razumeti tehnike phishinga koje se danas koriste**. Na roditeljskoj stranici ovog posta, možete pronaći te informacije, pa ako niste upoznati sa tehnikama koje se danas koriste, preporučujem vam da odete na roditeljsku stranicu i pročitate barem tu sekciju.

Ovaj post se zasniva na ideji da će **napadači pokušati na neki način da oponašaju ili koriste ime domena žrtve**. Ako je vaš domen nazvan `primer.com` i ako ste prevareni korišćenjem potpuno drugačijeg imena domena iz nekog razloga kao što je `osvojiliste.com`, ove tehnike to neće otkriti.

## Varijacije imena domena

Prilično je **jednostavno** otkriti te **pokušaje phishinga** koji će koristiti **slično ime domena** unutar e-pošte.\
Dovoljno je **generisati listu najverovatnijih imena za phishing** koje bi napadač mogao koristiti i **proveriti** da li je **registrovan** ili jednostavno proveriti da li postoji neka **IP adresa** koja ga koristi.

### Pronalaženje sumnjivih domena

Za tu svrhu, možete koristiti bilo koji od sledećih alata. Imajte na umu da će ovi alati automatski izvršiti DNS zahteve kako bi proverili da li je domen dodeljen nekoj IP adresi:

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

### Bitflipping

**Možete pronaći kratko objašnjenje ove tehnike na roditeljskoj stranici. Ili pročitajte originalno istraživanje na** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

Na primer, modifikacija od 1 bit u domenu microsoft.com može ga pretvoriti u _windnws.com._\
**Napadači mogu registrovati što više bit-flipping domena moguće povezanih sa žrtvom kako bi preusmerili legitimne korisnike na svoju infrastrukturu**.

**Svi mogući bit-flipping imena domena takođe bi trebalo da se prate.**

### Osnovne provere

Kada imate listu potencijalno sumnjivih imena domena, trebalo bi da ih **proverite** (pretežno portove HTTP i HTTPS) da biste **videli da li koriste neki obrazac za prijavljivanje sličan** nekom od domena žrtve.\
Takođe možete proveriti port 3333 da vidite da li je otvoren i pokreće instancu `gophish`.\
Takođe je interesantno znati **koliko je star svaki otkriven sumnjivi domen**, što je mlađi, to je rizičniji.\
Možete takođe dobiti **slike ekrana** sumnjive veb stranice HTTP i/ili HTTPS da biste videli da li je sumnjiva i u tom slučaju **pristupiti joj da biste detaljnije pogledali**.

### Napredne provere

Ako želite da odete korak dalje, preporučio bih vam da **pratite te sumnjive domene i povremeno tražite više** (svaki dan? to traje samo nekoliko sekundi/minuta). Takođe biste trebali **proveriti** otvorene **portove** povezanih IP adresa i **tražiti instance `gophish` ili slične alate** (da, i napadači prave greške) i **pratiti HTTP i HTTPS veb stranice sumnjivih domena i poddomena** da biste videli da li su kopirali neki obrazac za prijavljivanje sa veb stranica žrtve.\
Da biste **automatizovali ovo**, preporučio bih da imate listu obrazaca za prijavljivanje domena žrtve, pretražite sumnjive veb stranice i uporedite svaki pronađeni obrazac za prijavljivanje unutar sumnjivih domena sa svakim obrazcem za prijavljivanje domena žrtve koristeći nešto poput `ssdeep`.\
Ako ste locirali obrasce za prijavljivanje sumnjivih domena, možete pokušati da **pošaljete lažne podatke za prijavljivanje** i **proverite da li vas preusmerava na domen žrtve**.

## Imena domena sa ključnim rečima

Roditeljska stranica takođe pominje tehniku varijacije imena domena koja se sastoji od stavljanja **imenja domena žrtve unutar većeg domena** (npr. paypal-financial.com za paypal.com).

### Transparentnost sertifikata

Nije moguće primeniti prethodni "Brute-Force" pristup, ali je zapravo **moguće otkriti takve pokušaje phishinga** zahvaljujući transparentnosti sertifikata. Svaki put kada sertifikat izda CA, detalji postaju javni. To znači da čitanjem transparentnosti sertifikata ili čak praćenjem istog, moguće je **pronaći domene koji koriste ključnu reč unutar svog imena** Na primer, ako napadač generiše sertifikat za [https://paypal-financial.com](https://paypal-financial.com), čitanjem sertifikata moguće je pronaći ključnu reč "paypal" i znati da se koristi sumnjiva e-pošta.

Post [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) sugeriše da možete koristiti Censys za pretragu sertifikata koji utiču na određenu ključnu reč i filtrirati po datumu (samo "novi" sertifikati) i po izdavaču CA "Let's Encrypt":

![https://0xpatrik.com/content/images/2018/07/cert\_listing.png](<../../.gitbook/assets/image (1112).png>)

Međutim, možete "isto" uraditi koristeći besplatan veb [**crt.sh**](https://crt.sh). Možete **pretraživati po ključnoj reči** i **filtrirati** rezultate **po datumu i CA** ako želite.

![](<../../.gitbook/assets/image (516).png>)

Koristeći ovu poslednju opciju, čak možete koristiti polje Matching Identities da biste videli da li se bilo koja identifikacija sa pravog domena poklapa sa bilo kojim od sumnjivih domena (imajte na umu da sumnjiv domen može biti lažni pozitiv).

**Još jedna alternativa** je fantastični projekat nazvan [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067). CertStream pruža stvarni tok novo generisanih sertifikata koje možete koristiti da biste otkrili određene ključne reči u (skoro) realnom vremenu. Zapravo, postoji projekat nazvan [**phishing\_catcher**](https://github.com/x0rz/phishing\_catcher) koji upravo to radi.
### **Novi domeni**

**Još jedna alternativa** je prikupljanje liste **nedavno registrovanih domena** za neke TLD-ove ([Whoxy](https://www.whoxy.com/newly-registered-domains/) pruža takvu uslugu) i **provera ključnih reči u tim domenima**. Međutim, dugi domeni obično koriste jedan ili više poddomena, stoga ključna reč neće se pojaviti unutar FLD-a i nećete moći pronaći phishing poddomen.
