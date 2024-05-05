# Sub-GHz RF

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** Proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## Garažna Vrata

Otvorivači garažnih vrata obično rade na frekvencijama u opsegu od 300-190 MHz, pri čemu su najčešće frekvencije 300 MHz, 310 MHz, 315 MHz i 390 MHz. Ovaj frekvencijski opseg se često koristi za otvarače garažnih vrata jer je manje zagušen od drugih frekvencijskih opsega i manje je verovatno da će doživeti smetnje od drugih uređaja.

## Vrata Automobila

Većina daljinskih upravljača za automobile radi na frekvencijama od **315 MHz ili 433 MHz**. Ovo su oba radio frekvencije i koriste se u različitim aplikacijama. Glavna razlika između ove dve frekvencije je što 433 MHz ima veći domet od 315 MHz. To znači da je 433 MHz bolji za aplikacije koje zahtevaju veći domet, poput daljinskog otključavanja vrata.\
U Evropi se često koristi 433.92 MHz, a u SAD-u i Japanu je to 315 MHz.

## **Brute-force Napad**

<figure><img src="../../.gitbook/assets/image (1084).png" alt=""><figcaption></figcaption></figure>

Ako umesto slanja svakog koda 5 puta (poslato na ovaj način da bi se osiguralo da prijemnik dobije) pošaljete samo jednom, vreme se smanjuje na 6 minuta:

<figure><img src="../../.gitbook/assets/image (622).png" alt=""><figcaption></figcaption></figure>

i ako **uklonite period čekanja od 2 ms** između signala, možete **smanjiti vreme na 3 minuta**.

Osim toga, korišćenjem De Bruijn sekvence (način za smanjenje broja bitova potrebnih za slanje svih potencijalnih binarnih brojeva za brute force) ovo **vreme se smanjuje na samo 8 sekundi**:

<figure><img src="../../.gitbook/assets/image (583).png" alt=""><figcaption></figcaption></figure>

Primer ovog napada je implementiran na [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)

Zahtevanje **preambule će izbeći De Bruijn sekvencu** optimizaciju i **rolling kodovi će sprečiti ovaj napad** (pretpostavljajući da je kod dovoljno dug da ne može biti brute force-an).

## Napad na Sub-GHz

Za napad na ove signale pomoću Flipper Zero proverite:

{% content-ref url="flipper-zero/fz-sub-ghz.md" %}
[fz-sub-ghz.md](flipper-zero/fz-sub-ghz.md)
{% endcontent-ref %}

## Zaštita Rolling Kodova

Automatski otvarači garažnih vrata obično koriste bežični daljinski upravljač za otvaranje i zatvaranje garažnih vrata. Daljinski upravljač **šalje radio frekvencijski (RF) signal** otvaraču garažnih vrata, koji aktivira motor za otvaranje ili zatvaranje vrata.

Moguće je da neko koristi uređaj poznat kao grabilica koda da presretne RF signal i snimi ga za kasniju upotrebu. Ovo je poznato kao **napad ponovnog slanja**. Da bi se sprečio ovaj tip napada, mnogi moderni otvarači garažnih vrata koriste sigurniju enkripciju poznatu kao **rolling kod** sistem.

**RF signal se obično prenosi korišćenjem rolling koda**, što znači da se kod menja pri svakom korišćenju. Ovo čini **teškim** za nekoga da **presretne** signal i **koristi** ga za dobijanje **neovlašćenog** pristupa garaži.

U sistemu rolling koda, daljinski upravljač i otvarač garažnih vrata imaju **deljeni algoritam** koji **generiše novi kod** svaki put kada se daljinski upravljač koristi. Otvarač garažnih vrata će odgovoriti samo na **ispravan kod**, čineći mnogo teže nekome da dobije neovlašćen pristup garaži samo snimanjem koda.

### **Napad na Nedostajuću Poveznicu**

U osnovi, slušate dugme i **snimite signal dok je daljinski van dometa** uređaja (recimo automobila ili garaže). Zatim pređete do uređaja i **koristite snimljeni kod da ga otvorite**.

### Napad Potpunog Povezivanja Jamminga

Napadač bi mogao **blokirati signal blizu vozila ili prijemnika** tako da **prijemnik zapravo ne može 'čuti' kod**, i kada se to dogodi, jednostavno možete **snimiti i reprodukovati** kod kada prestanete sa blokiranjem.

Žrtva će u nekom trenutku koristiti **ključeve da zaključa automobil**, ali će napad **snimiti dovoljno "zatvori vrata" kodova** koji se nadaju da bi mogli biti ponovo poslati da otvore vrata (možda će biti potrebna **promena frekvencije** jer postoje automobili koji koriste iste kodove za otvaranje i zatvaranje ali slušaju oba komanda na različitim frekvencijama).

{% hint style="warning" %}
**Blokiranje radi**, ali je primetno jer ako **osoba zaključava automobil jednostavno proverava vrata** da bi se uverila da su zaključana primetiće da je automobil otključan. Dodatno, ako su svesni takvih napada, čak bi mogli čuti da vrata nikada nisu napravila zvuk zaključavanja ili da svetla na automobilu nikada nisu trepnula kada su pritisnuli dugme za 'zaključavanje'.
{% endhint %}

### **Napad na Grabljenje Koda (poznat kao ‘RollJam’ )**

Ovo je sofisticiranija tehnika blokiranja. Napadač će blokirati signal, tako da kada žrtva pokuša da zaključa vrata to neće uspeti, ali će napadač **snimiti ovaj kod**. Zatim, žrtva će **ponovo pokušati da zaključa automobil** pritiskom na dugme i automobil će **snimiti ovaj drugi kod**.\
Odmah nakon toga, **napadač može poslati prvi kod** i **automobil će se zaključati** (žrtva će misliti da je drugo pritiskanje zatvorilo). Zatim, napadač će moći da **pošalje drugi ukradeni kod da otvori** automobil (pretpostavljajući da se **"zatvori automobil" kod takođe može koristiti za otvaranje**). Možda će biti potrebna promena frekvencije (jer postoje automobili koji koriste iste kodove za otvaranje i zatvaranje ali slušaju oba komanda na različitim frekvencijama).

Napadač može **blokirati prijemnik automobila, a ne svoj prijemnik** jer ako prijemnik automobila sluša na primer širokopojasnu frekvenciju od 1MHz, napadač neće **blokirati tačnu frekvenciju koju koristi daljinski već** jednu blizu u tom spektru dok će **prijemnik napadača slušati u manjem opsegu** gde može čuti signal daljinskog **bez blokiranja**.

{% hint style="warning" %}
Druge implementacije viđene u specifikacijama pokazuju da je **rolling kod deo** ukupnog poslatog koda. Na primer, kod koji se šalje je **24-bitni ključ** gde su prva **12 rolling kodovi**, drugih 8 su **komanda** (kao što je zaključavanje ili otključavanje) i poslednjih 4 je **checksum**. Vozila koja implementiraju ovaj tip su takođe prirodno podložna jer napadač jednostavno treba da zameni segment rolling koda kako bi mogao **koristiti bilo koji rolling kod na oba frekvencije**.
{% endhint %}

{% hint style="danger" %}
Imajte na umu da ako žrtva pošalje treći kod dok napadač šalje prvi, prvi i drugi kod će biti poništeni.
{% endhint %}
### Napad na isključivanje alarma zvučnog signala

Testiranje protiv sistema sa kodom koji se menja nakon-market sistema instaliranog na automobilu, **slanje istog koda dva puta** odmah **aktivira alarm** i imobilizator pružajući jedinstvenu **mogućnost odbijanja usluge**. Ironično, sredstvo za **isključivanje alarma** i imobilizatora bilo je **pritisnuti** **daljinski**, pružajući napadaču mogućnost da **kontinuirano izvodi DoS napad**. Ili kombinujte ovaj napad sa **prethodnim** kako biste dobili više kodova, pošto bi žrtva želela da zaustavi napad što je pre moguće.

## Reference

* [https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
* [https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
* [https://samy.pl/defcon2015/](https://samy.pl/defcon2015/)
* [https://hackaday.io/project/164566-how-to-hack-a-car/details](https://hackaday.io/project/164566-how-to-hack-a-car/details)

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** Proverite [**PLANOVE ZA PRETPLATU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
