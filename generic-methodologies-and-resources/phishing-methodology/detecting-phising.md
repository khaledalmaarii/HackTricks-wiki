# Otkrivanje Phishing-a

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **nas pratite na** **Twitter-u** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}

## Uvod

Da biste otkrili pokušaj phishing-a, važno je **razumeti phishing tehnike koje se danas koriste**. Na roditeljskoj stranici ovog posta možete pronaći te informacije, pa ako niste upoznati sa tehnikama koje se danas koriste, preporučujem da odete na roditeljsku stranicu i pročitate barem taj deo.

Ovaj post se zasniva na ideji da će **napadači pokušati na neki način da imituju ili koriste ime domena žrtve**. Ako je vaš domen nazvan `example.com` i vi ste phishing-ovani koristeći potpuno drugačije ime domena, kao što je `youwonthelottery.com`, ove tehnike neće otkriti to.

## Varijacije imena domena

Relativno je **lako** da se **otkriju** ti **phishing** pokušaji koji će koristiti **sličan naziv domena** unutar email-a.\
Dovoljno je **generisati listu najverovatnijih phishing imena** koje napadač može koristiti i **proveriti** da li je **registrovano** ili samo proveriti da li postoji neki **IP** koji ga koristi.

### Pronalaženje sumnjivih domena

Za ovu svrhu možete koristiti bilo koji od sledećih alata. Imajte na umu da će ovi alati takođe automatski izvršiti DNS zahteve da provere da li domen ima dodeljen IP:

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

### Bitflipping

**Možete pronaći kratko objašnjenje ove tehnike na roditeljskoj stranici. Ili pročitajte originalno istraživanje na** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

Na primer, 1-bitna modifikacija u domenu microsoft.com može ga transformisati u _windnws.com._\
**Napadači mogu registrovati koliko god je moguće domena sa bit-flipping vezanim za žrtvu kako bi preusmerili legitimne korisnike na svoju infrastrukturu**.

**Svi mogući nazivi domena sa bit-flipping-om takođe bi trebali biti praćeni.**

### Osnovne provere

Kada imate listu potencijalno sumnjivih imena domena, trebali biste **proveriti** ih (pretežno portove HTTP i HTTPS) da **vidite da li koriste neki obrazac za prijavu sličan** onome sa domena žrtve.\
Takođe možete proveriti port 3333 da vidite da li je otvoren i da li pokreće instancu `gophish`.\
Takođe je zanimljivo znati **koliko je stara svaka otkrivena sumnjiva domena**, što je mlađa, to je rizičnija.\
Možete takođe dobiti **screenshot-ove** sumnjive web stranice HTTP i/ili HTTPS da vidite da li je sumnjiva i u tom slučaju **pristupiti joj da biste detaljnije pogledali**.

### Napredne provere

Ako želite da idete korak dalje, preporučujem da **pratite te sumnjive domene i povremeno tražite više** (svakog dana? to traje samo nekoliko sekundi/minuta). Takođe biste trebali **proveriti** otvorene **portove** povezanih IP-ova i **tražiti instance `gophish` ili sličnih alata** (da, napadači takođe prave greške) i **pratiti HTTP i HTTPS web stranice sumnjivih domena i poddomena** da vidite da li su kopirali neki obrazac za prijavu sa web stranica žrtve.\
Da biste **automatizovali ovo**, preporučujem da imate listu obrazaca za prijavu domena žrtve, da pretražujete sumnjive web stranice i upoređujete svaki obrazac za prijavu pronađen unutar sumnjivih domena sa svakim obrascem za prijavu domena žrtve koristeći nešto poput `ssdeep`.\
Ako ste locirali obrasce za prijavu sumnjivih domena, možete pokušati da **pošaljete lažne kredencijale** i **proverite da li vas preusmerava na domen žrtve**.

## Imena domena koristeći ključne reči

Roditeljska stranica takođe pominje tehniku varijacije imena domena koja se sastoji od stavljanja **imena domena žrtve unutar većeg domena** (npr. paypal-financial.com za paypal.com).

### Transparentnost sertifikata

Nije moguće primeniti prethodni "Brute-Force" pristup, ali je zapravo **moguće otkriti takve phishing pokušaje** takođe zahvaljujući transparentnosti sertifikata. Svaki put kada sertifikat izda CA, detalji se objavljuju. To znači da čitanjem transparentnosti sertifikata ili čak njenim praćenjem, **može se pronaći domene koje koriste ključnu reč unutar svog imena**. Na primer, ako napadač generiše sertifikat za [https://paypal-financial.com](https://paypal-financial.com), gledajući sertifikat moguće je pronaći ključnu reč "paypal" i znati da se koristi sumnjivi email.

Post [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) sugeriše da možete koristiti Censys da tražite sertifikate koji utiču na određenu ključnu reč i filtrirate po datumu (samo "novi" sertifikati) i po CA izdavaču "Let's Encrypt":

![https://0xpatrik.com/content/images/2018/07/cert\_listing.png](<../../.gitbook/assets/image (1115).png>)

Međutim, možete učiniti "isto" koristeći besplatni web [**crt.sh**](https://crt.sh). Možete **tražiti ključnu reč** i **filtrirati** rezultate **po datumu i CA** ako želite.

![](<../../.gitbook/assets/image (519).png>)

Korišćenjem ove poslednje opcije možete čak koristiti polje Matching Identities da vidite da li se neka identitet iz pravog domena poklapa sa bilo kojim od sumnjivih domena (napomena: sumnjivi domen može biti lažno pozitivan).

**Još jedna alternativa** je fantastičan projekat pod nazivom [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067). CertStream pruža real-time tok novoregistrovanih sertifikata koje možete koristiti za otkrivanje određenih ključnih reči u (neposrednom) realnom vremenu. U stvari, postoji projekat pod nazivom [**phishing\_catcher**](https://github.com/x0rz/phishing\_catcher) koji to upravo radi.

### **Novi domeni**

**Jedna poslednja alternativa** je da prikupite listu **novoregistrovanih domena** za neke TLD-ove ([Whoxy](https://www.whoxy.com/newly-registered-domains/) pruža takvu uslugu) i **proverite ključne reči u tim domenima**. Međutim, dugi domeni obično koriste jedan ili više poddomena, stoga ključna reč neće biti prisutna unutar FLD-a i nećete moći pronaći phishing poddomen.

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **nas pratite na** **Twitter-u** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
