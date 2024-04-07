# Kako radi infracrveni signal <a href="#kako-radi-infracrveni-port" id="kako-radi-infracrveni-port"></a>

**Infracrvena svetlost je nevidljiva ljudima**. IR talasna dužina je od **0,7 do 1000 mikrona**. Kućni daljinski koriste IR signal za prenos podataka i rade u opsegu talasne dužine od 0,75 do 1,4 mikrona. Mikrokontroler u daljinskom uređaju čini da infracrveni LED trepće sa određenom frekvencijom, pretvarajući digitalni signal u IR signal.

Za primanje IR signala koristi se **fotoprijemnik**. On **pretvara IR svetlost u naponske impulse**, koji su već **digitalni signali**. Obično postoji **filter tamne svetlosti unutar prijemnika**, koji propušta **samo željenu talasnu dužinu** i eliminiše šum.

### Različiti IR protokoli <a href="#različiti-ir-protokoli" id="različiti-ir-protokoli"></a>

IR protokoli se razlikuju u 3 faktora:

* kodiranje bitova
* struktura podataka
* nosna frekvencija - često u opsegu 36 do 38 kHz

#### Načini kodiranja bitova <a href="#načini-kodiranja-bitova" id="načini-kodiranja-bitova"></a>

**1. Kodiranje razdaljine impulsa**

Bitovi se kodiraju modulacijom trajanja prostora između impulsa. Širina samog impulsa je konstantna.

<figure><img src="../../.gitbook/assets/image (292).png" alt=""><figcaption></figcaption></figure>

**2. Kodiranje širine impulsa**

Bitovi se kodiraju modulacijom širine impulsa. Širina prostora nakon impulsa je konstantna.

<figure><img src="../../.gitbook/assets/image (279).png" alt=""><figcaption></figcaption></figure>

**3. Kodiranje faze**

Takođe je poznato kao Mančester kodiranje. Logička vrednost je definisana polaritetom tranzicije između impulsa i prostora. "Prostor do impulsa" označava logiku "0", "impuls do prostora" označava logiku "1".

<figure><img src="../../.gitbook/assets/image (631).png" alt=""><figcaption></figcaption></figure>

**4. Kombinacija prethodnih i drugih egzotičnih**

{% hint style="info" %}
Postoje IR protokoli koji **pokušavaju postati univerzalni** za nekoliko vrsta uređaja. Najpoznatiji su RC5 i NEC. Nažalost, najpoznatiji **ne znači najčešći**. U mom okruženju, sreo sam samo dva NEC daljinska upravljača i nijedan RC5.

Proizvođači vole koristiti svoje jedinstvene IR protokole, čak i unutar istog opsega uređaja (na primer, TV kutije). Stoga, daljinski upravljači različitih kompanija i ponekad različitih modela iste kompanije, nisu u mogućnosti raditi sa drugim uređajima iste vrste.
{% endhint %}

### Istraživanje IR signala

Najpouzdaniji način da vidite kako izgleda IR signal daljinskog upravljača je korišćenje osciloskopa. On ne demoduliše ili invertuje primljeni signal, već ga prikazuje "kakav jeste". Ovo je korisno za testiranje i debagovanje. Pokazaću očekivani signal na primeru NEC IR protokola.

<figure><img src="../../.gitbook/assets/image (232).png" alt=""><figcaption></figcaption></figure>

Obično postoji preambula na početku kodiranog paketa. To omogućava prijemniku da odredi nivo pojačanja i pozadine. Postoje i protokoli bez preambule, na primer, Sharp.

Zatim se prenose podaci. Struktura, preambula i način kodiranja bitova određeni su specifičnim protokolom.

**NEC IR protokol** sadrži kratku komandu i kod ponavljanja, koja se šalje dok je dugme pritisnuto. I komanda i kod ponavljanja imaju istu preambulu na početku.

NEC **komanda**, pored preambule, sastoji se od bajta adrese i bajta broja komande, pomoću kojih uređaj razume šta treba da se izvrši. Bajtovi adrese i broja komande su duplicirani sa inverznim vrednostima, radi provere celovitosti prenosa. Na kraju komande postoji dodatni stop bit.

**Kod ponavljanja** ima "1" nakon preambule, što je stop bit.

Za **logiku "0" i "1"** NEC koristi Kodiranje razdaljine impulsa: prvo se prenosi impulzni niz, nakon čega sledi pauza, čija dužina određuje vrednost bita.

### Klima uređaji

Za razliku od drugih daljinskih upravljača, **klima uređaji ne prenose samo kod pritisnutog dugmeta**. Takođe **prenose sve informacije** kada se dugme pritisne kako bi se osiguralo da su **klima uređaj i daljinski sinhronizovani**.\
Ovo će sprečiti da se mašina podešena na 20ºC poveća na 21ºC sa jednim daljinskim upravljačem, a zatim kada se drugi daljinski upravljač, koji još uvek ima temperaturu od 20ºC, koristi za dalje povećanje temperature, "poveća" je na 21ºC (a ne na 22ºC misleći da je već na 21ºC).

### Napadi

Možete napasti infracrveni signal pomoću Flipper Zero uređaja:

{% content-ref url="flipper-zero/fz-infrared.md" %}
[fz-infrared.md](flipper-zero/fz-infrared.md)
{% endcontent-ref %}

## Reference

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)
