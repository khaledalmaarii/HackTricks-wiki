# Sub-GHz RF

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Garage Doors

Otvarači garažnih vrata obično rade na frekvencijama u opsegu od 300-190 MHz, pri čemu su najčešće frekvencije 300 MHz, 310 MHz, 315 MHz i 390 MHz. Ovaj opseg frekvencija se često koristi za otvarače garažnih vrata jer je manje zagušen od drugih frekvencijskih opsega i manje je verovatno da će doći do smetnji od drugih uređaja.

## Car Doors

Većina daljinskih ključeva za automobile radi na **315 MHz ili 433 MHz**. Ove frekvencije su radio frekvencije i koriste se u raznim aplikacijama. Glavna razlika između dve frekvencije je ta što 433 MHz ima duži domet od 315 MHz. To znači da je 433 MHz bolji za aplikacije koje zahtevaju duži domet, kao što je daljinsko otključavanje.\
U Evropi se obično koristi 433.92MHz, dok se u SAD-u i Japanu koristi 315MHz.

## **Brute-force Attack**

<figure><img src="../../.gitbook/assets/image (1084).png" alt=""><figcaption></figcaption></figure>

Ako umesto slanja svakog koda 5 puta (poslato na ovaj način da bi se osiguralo da prijemnik to primi) pošaljete samo jednom, vreme se smanjuje na 6 minuta:

<figure><img src="../../.gitbook/assets/image (622).png" alt=""><figcaption></figcaption></figure>

i ako **uklonite 2 ms čekanje** između signala, možete **smanjiti vreme na 3 minuta.**

Štaviše, korišćenjem De Bruijn sekvence (način za smanjenje broja bitova potrebnih za slanje svih potencijalnih binarnih brojeva za brute-force) ovo **vreme se smanjuje na samo 8 sekundi**:

<figure><img src="../../.gitbook/assets/image (583).png" alt=""><figcaption></figcaption></figure>

Primer ove napade implementiran je u [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)

Zahtevajući **preambulu će izbeći optimizaciju De Bruijn sekvence** i **rolni kodovi će sprečiti ovu napad** (pod pretpostavkom da je kod dovoljno dug da ne može biti brute-forcovan).

## Sub-GHz Attack

Da biste napali ove signale sa Flipper Zero, proverite:

{% content-ref url="flipper-zero/fz-sub-ghz.md" %}
[fz-sub-ghz.md](flipper-zero/fz-sub-ghz.md)
{% endcontent-ref %}

## Rolling Codes Protection

Automatski otvarači garažnih vrata obično koriste bežični daljinski upravljač za otvaranje i zatvaranje garažnih vrata. Daljinski upravljač **šalje radio frekvencijski (RF) signal** otvaraču garažnih vrata, koji aktivira motor za otvaranje ili zatvaranje vrata.

Moguće je da neko koristi uređaj poznat kao "code grabber" da presretne RF signal i snimi ga za kasniju upotrebu. Ovo se naziva **replay attack**. Da bi se sprečio ovaj tip napada, mnogi moderni otvarači garažnih vrata koriste sigurniju metodu enkripcije poznatu kao **rolling code** sistem.

**RF signal se obično prenosi koristeći rolling code**, što znači da se kod menja sa svakom upotrebom. To otežava nekome da **presretne** signal i **iskoristi** ga za sticanje **neovlašćenog** pristupa garaži.

U sistemu rolling code, daljinski upravljač i otvarač garažnih vrata imaju **zajednički algoritam** koji **generiše novi kod** svaki put kada se daljinski upravljač koristi. Otvarač garažnih vrata će reagovati samo na **ispravan kod**, što znatno otežava nekome da dobije neovlašćen pristup garaži samo hvatanjem koda.

### **Missing Link Attack**

U suštini, slušate dugme i **hvata signal dok je daljinski upravljač van dometa** uređaja (recimo automobila ili garaže). Zatim se pomerate do uređaja i **koristite uhvaćeni kod da ga otvorite**.

### Full Link Jamming Attack

Napadač bi mogao **omesti signal blizu vozila ili prijemnika** tako da **prijemnik zapravo ne može ‘čuti’ kod**, i kada se to dogodi, možete jednostavno **uhvatiti i ponovo poslati** kod kada prestanete sa ometanjem.

Žrtva će u nekom trenutku koristiti **ključeve da zaključa automobil**, ali će napadač **snimiti dovoljno "zatvori vrata" kodova** koji se nadaju da će moći da se ponovo pošalju da otvore vrata (možda će biti potrebna **promena frekvencije** jer postoje automobili koji koriste iste kodove za otvaranje i zatvaranje, ali slušaju obe komande na različitim frekvencijama).

{% hint style="warning" %}
**Ometanje funkcioniše**, ali je primetno jer ako **osoba koja zaključava automobil jednostavno testira vrata** da bi se uverila da su zaključana, primetiće da je automobil otključan. Pored toga, ako su bili svesni takvih napada, mogli bi čak i da čuju da vrata nikada nisu napravila **zvuk** zaključavanja ili da svetla automobila nikada nisu trepnula kada su pritisnuli dugme ‘zaključaj’.
{% endhint %}

### **Code Grabbing Attack ( aka ‘RollJam’ )**

Ovo je više **prikrivena tehnika ometanja**. Napadač će ometati signal, tako da kada žrtva pokuša da zaključa vrata, to neće raditi, ali će napadač **snimiti ovaj kod**. Zatim će žrtva **ponovo pokušati da zaključa automobil** pritiskom na dugme i automobil će **snimiti ovaj drugi kod**.\
Odmah nakon toga, **napadač može poslati prvi kod** i **automobil će se zaključati** (žrtva će misliti da je drugi pritisak zatvorio). Tada će napadač moći da **pošalje drugi ukradeni kod da otvori** automobil (pod pretpostavkom da se **"zatvori automobil" kod može takođe koristiti za otvaranje**). Možda će biti potrebna promena frekvencije (jer postoje automobili koji koriste iste kodove za otvaranje i zatvaranje, ali slušaju obe komande na različitim frekvencijama).

Napadač može **ometati prijemnik automobila, a ne svoj prijemnik** jer ako prijemnik automobila sluša, na primer, na 1MHz širokom opsegu, napadač neće **ometati** tačnu frekvenciju koju koristi daljinski upravljač, već **blisku u tom spektru**, dok će **prijemnik napadača slušati u manjem opsegu** gde može slušati signal daljinskog upravljača **bez ometanja**.

{% hint style="warning" %}
Druge implementacije viđene u specifikacijama pokazuju da je **rolling code deo** ukupnog koda koji se šalje. Naime, kod koji se šalje je **24-bitni ključ** gde je prvih **12 rolling code**, **drugih 8 je komanda** (kao što je zaključavanje ili otključavanje), a poslednja 4 je **kontrolna suma**. Vozila koja implementiraju ovu vrstu su takođe prirodno podložna jer napadač jednostavno treba da zameni segment rolling code da bi mogao da **koristi bilo koji rolling code na obe frekvencije**.
{% endhint %}

{% hint style="danger" %}
Napomena: ako žrtva pošalje treći kod dok napadač šalje prvi, prvi i drugi kod će biti nevažeći.
{% endhint %}

### Alarm Sounding Jamming Attack

Testirajući protiv aftermarket rolling code sistema instaliranog na automobilu, **slanje istog koda dva puta** odmah **aktivira alarm** i imobilizator, pružajući jedinstvenu **uslugu odbijanja**. Ironično, sredstvo za **onemogućavanje alarma** i imobilizatora bilo je **pritiskanje** **daljinskog**, pružajući napadaču mogućnost da **neprekidno izvodi DoS napad**. Ili kombinujte ovaj napad sa **prethodnim da dobijete više kodova** jer bi žrtva želela da što pre zaustavi napad.

## References

* [https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
* [https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
* [https://samy.pl/defcon2015/](https://samy.pl/defcon2015/)
* [https://hackaday.io/project/164566-how-to-hack-a-car/details](https://hackaday.io/project/164566-how-to-hack-a-car/details)

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
