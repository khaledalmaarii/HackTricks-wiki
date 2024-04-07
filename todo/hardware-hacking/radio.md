# Radio

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** Proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## SigDigger

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)je besplatan digitalni analizator signala za GNU/Linux i macOS, dizajniran za izvlačenje informacija o nepoznatim radio signalima. Podržava različite SDR uređaje putem SoapySDR-a, omogućava podešavanje demodulacije FSK, PSK i ASK signala, dekodiranje analognog videa, analizu signalnih impulsa i slušanje analognih glasovnih kanala (sve u realnom vremenu).

### Osnovna konfiguracija

Nakon instalacije, postoji nekoliko stvari koje biste mogli razmotriti za konfigurisanje.\
U podešavanjima (drugi tab dugme) možete odabrati **SDR uređaj** ili **odabrati datoteku** za čitanje, frekvenciju za sintonizaciju i Stopu uzorkovanja (preporučuje se do 2.56Msps ako vaš računar podržava)\\

![](<../../.gitbook/assets/image (242).png>)

U ponašanju GUI-a preporučuje se omogućiti nekoliko stvari ako vaš računar podržava:

![](<../../.gitbook/assets/image (469).png>)

{% hint style="info" %}
Ako primetite da vaš računar ne hvata stvari, pokušajte da onemogućite OpenGL i smanjite stopu uzorkovanja.
{% endhint %}

### Upotrebe

* Samo da **uhvatite neko vreme signala i analizirate ga** samo držite dugme "Pritisni za snimanje" koliko god vam je potrebno.

![](<../../.gitbook/assets/image (957).png>)

* **Tjuner** u SigDigger-u pomaže da **uhvatite bolje signale** (ali ih može i degradirati). Idealno je početi sa 0 i nastaviti **povećavati dok** ne pronađete da je **šum** koji se uvodi **veći** od **poboljšanja signala** koje vam je potrebno).

![](<../../.gitbook/assets/image (1096).png>)

### Sinhronizacija sa radio kanalom

Sa [**SigDigger** ](https://github.com/BatchDrake/SigDigger)sinhronizujte se sa kanalom koji želite da čujete, konfigurišite opciju "Pregled zvuka osnovnog pojasa", konfigurišite širinu pojasa da biste dobili sve informacije koje se šalju, a zatim postavite Tjuner na nivo pre nego što šum počne značajno da se povećava:

![](<../../.gitbook/assets/image (582).png>)

## Interesantni trikovi

* Kada uređaj šalje niz informacija, obično će **prvi deo biti preambula** tako da se **ne morate** brinuti ako **ne pronađete informacije** tamo **ili ako postoje greške**.
* U okvirima informacija obično biste trebali **pronaći različite okvire dobro poravnate međusobno**:

![](<../../.gitbook/assets/image (1073).png>)

![](<../../.gitbook/assets/image (594).png>)

* **Nakon što povratite bitove, možda ćete morati da ih obradite na neki način**. Na primer, u Mančesterskoj kodifikaciji, gore+dole će biti 1 ili 0, a dole+gore će biti drugi. Dakle, parovi 1-ica i 0-ova (gore i dole) će biti prava 1 ili prava 0.
* Čak i ako signal koristi Mančestersku kodifikaciju (nemoguće je pronaći više od dve 0 ili 1 uzastopno), možete **pronaći nekoliko 1-ica ili 0-ova zajedno u preambuli**!

### Otkrivanje tipa modulacije pomoću IQ

Postoje 3 načina za skladištenje informacija u signalima: Modulacija **amplitudom**, **frekvencijom** ili **fazom**.\
Ako proveravate signal, postoje različiti načini da pokušate da saznate koji se način koristi za skladištenje informacija (pronađite više načina ispod), ali dobar način je da proverite IQ grafikon.

![](<../../.gitbook/assets/image (785).png>)

* **Otkrivanje AM-a**: Ako se na IQ grafikonu pojave na primer **2 kruga** (verovatno jedan u 0 i drugi u različitoj amplitudi), to bi moglo značiti da je ovo AM signal. To je zato što je na IQ grafikonu udaljenost između 0 i kruga amplituda signala, pa je lako vizualizovati različite amplitude koje se koriste.
* **Otkrivanje PM-a**: Kao na prethodnoj slici, ako pronađete male krugove koji nisu povezani međusobno, verovatno znači da se koristi fazna modulacija. To je zato što je na IQ grafikonu ugao između tačke i 0,0 faza signala, što znači da se koristi 4 različite faze.
* Imajte na umu da ako je informacija sakrivena u činjenici da se menja faza, a ne u samoj fazi, nećete jasno videti različite faze.
* **Otkrivanje FM-a**: IQ nema polje za identifikaciju frekvencija (udaljenost od centra je amplituda, a ugao je faza).\
Stoga, da biste identifikovali FM, trebali biste **videti uglavnom samo krug** na ovom grafikonu.\
Osim toga, različita frekvencija je "predstavljena" na IQ grafikonu ubrzanjem brzine preko kruga (tako da u SysDigger-u odabirom signala IQ grafikon se popunjava, ako pronađete ubrzanje ili promenu pravca u stvorenom krugu, to bi moglo značiti da je ovo FM):

## Primer AM-a

{% file src="../../.gitbook/assets/sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw" %}

### Otkrivanje AM-a

#### Provera omotača

Proveravajući AM informacije sa [**SigDigger** ](https://github.com/BatchDrake/SigDigger)i samo gledajući **omotač** možete videti različite jasne nivoe amplitude. Korišćeni signal šalje impulse sa informacijama u AM, ovako izgleda jedan impuls:

![](<../../.gitbook/assets/image (587).png>)

A ovako izgleda deo simbola sa talasom:

![](<../../.gitbook/assets/image (731).png>)

#### Provera histograma

Možete **odabrati ceo signal** gde se nalaze informacije, odabrati režim **Amplituda** i **Selekciju** i kliknuti na **Histogram**. Možete primetiti da se nalaze samo 2 jasna nivoa

![](<../../.gitbook/assets/image (261).png>)

Na primer, ako umesto Amplitude odaberete Frekvenciju u ovom AM signalu, pronaći ćete samo 1 frekvenciju (nema načina da se informacije modulišu u frekvenciji koristeći samo 1 frekvenciju).

![](<../../.gitbook/assets/image (729).png>)

Ako pronađete puno frekvencija, potencijalno ovo neće biti FM, verovatno je frekvencija signala samo izmenjena zbog kanala.
#### Sa IQ

U ovom primeru možete videti kako postoji **veliki krug** ali i **mnogo tačaka u centru.**

![](<../../.gitbook/assets/image (219).png>)

### Dobijanje Brzine Simbola

#### Sa jednim simbolom

Izaberite najmanji simbol koji možete pronaći (da budete sigurni da je samo 1) i proverite "Selection freq". U ovom slučaju to bi bilo 1.013kHz (tj. 1kHz).

![](<../../.gitbook/assets/image (75).png>)

#### Sa grupom simbola

Možete takođe naznačiti broj simbola koje ćete izabrati i SigDigger će izračunati frekvenciju 1 simbola (što je verovatno bolje što više simbola izaberete). U ovom scenariju sam izabrao 10 simbola i "Selection freq" je 1.004 Khz:

![](<../../.gitbook/assets/image (1005).png>)

### Dobijanje Bitova

Nakon što ste otkrili da je ovo **AM modulisani** signal i **brzinu simbola** (i znajući da u ovom slučaju nešto gore znači 1, a nešto dole znači 0), veoma je lako **dobiti bitove** kodirane u signalu. Dakle, izaberite signal sa informacijama, konfigurišite uzorkovanje i odlučivanje i pritisnite uzorak (proverite da li je izabrana **Amplituda**, konfigurisana otkrivena **Brzina simbola** i izabrano je **Gadner otkrivanje takta**):

![](<../../.gitbook/assets/image (962).png>)

* **Sync to selection intervals** znači da ako ste prethodno izabrali intervale da biste pronašli brzinu simbola, ta brzina simbola će biti korišćena.
* **Manual** znači da će se koristiti naznačena brzina simbola
* U **Fixed interval selection** naznačavate broj intervala koji treba da budu izabrani i izračunava se brzina simbola iz toga
* **Gadner otkrivanje takta** obično je najbolja opcija, ali ipak morate naznačiti neku približnu brzinu simbola.

Pritiskom na uzorak pojaviće se ovo:

![](<../../.gitbook/assets/image (641).png>)

Sada, da biste omogućili SigDiggeru da razume **gde je opseg** nivoa koji prenose informacije, morate kliknuti na **niži nivo** i držati kliknuto dok ne dođete do najvećeg nivoa:

![](<../../.gitbook/assets/image (436).png>)

Ako bi na primer postojala **4 različita nivoa amplitude**, morali biste konfigurisati **Bitove po simbolu na 2** i izabrati od najmanjeg do najvećeg.

Na kraju, **povećavajući** **Zum** i **menjajući veličinu reda** možete videti bitove (i možete sve izabrati i kopirati da biste dobili sve bitove):

![](<../../.gitbook/assets/image (273).png>)

Ako signal ima više od 1 bita po simbolu (na primer 2), SigDigger **nema načina da zna koji simbol je** 00, 01, 10, 11, pa će koristiti različite **sive skale** da predstavi svaki (i ako kopirate bitove, koristiće **brojeve od 0 do 3**, moraćete ih obraditi).

Takođe, koristite **kodifikacije** poput **Manchester**, i **gore+dole** može biti **1 ili 0** i dole+gore može biti 1 ili 0. U tim slučajevima morate **obraditi dobijene gore (1) i dole (0)** da biste zamenili parove 01 ili 10 kao 0 ili 1.

## FM Primer

{% file src="../../.gitbook/assets/sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw" %}

### Otkrivanje FM

#### Provera frekvencija i oblika talasa

Primer signala koji šalje informacije modulisane u FM:

![](<../../.gitbook/assets/image (722).png>)

Na prethodnoj slici možete videti prilično dobro da se koriste **2 frekvencije**, ali ako **posmatrate** **oblik talasa** možda **nećete moći tačno identifikovati 2 različite frekvencije**:

![](<../../.gitbook/assets/image (714).png>)

To je zato što sam uhvatio signal na obe frekvencije, stoga je jedna otprilike negativna u odnosu na drugu:

![](<../../.gitbook/assets/image (939).png>)

Ako je sinhronizovana frekvencija **bliža jednoj frekvenciji nego drugoj**, lako možete videti 2 različite frekvencije:

![](<../../.gitbook/assets/image (419).png>)

![](<../../.gitbook/assets/image (485).png>)

#### Provera histograma

Proverom frekvencijskog histograma signala sa informacijama lako možete videti 2 različita signala:

![](<../../.gitbook/assets/image (868).png>)

U ovom slučaju, ako proverite **Amplitudni histogram** pronaći ćete **samo jednu amplitudu**, tako da **ne može biti AM** (ako pronađete mnogo amplituda, možda je zato što je signal gubio snagu duž kanala):

![](<../../.gitbook/assets/image (814).png>)

A ovo bi bio histogram faze (što jasno pokazuje da signal nije modulisan u fazi):

![](<../../.gitbook/assets/image (993).png>)

#### Sa IQ

IQ nema polje za identifikaciju frekvencija (udaljenost od centra je amplituda, a ugao je faza).\
Stoga, da biste identifikovali FM, trebalo bi da vidite **samo osnovno krug** na ovom grafikonu.\
Osim toga, drugačija frekvencija je "predstavljena" na IQ grafikonu **ubrzanjem brzine preko kruga** (tako da u SysDiggeru izborom signala IQ grafikon se popunjava, ako pronađete ubrzanje ili promenu pravca u stvorenom krugu, to bi moglo značiti da je ovo FM):

![](<../../.gitbook/assets/image (78).png>)

### Dobijanje Brzine Simbola

Možete koristiti **istu tehniku kao u AM primeru** da biste dobili brzinu simbola kada pronađete frekvencije koje prenose simbole.

### Dobijanje Bitova

Možete koristiti **istu tehniku kao u AM primeru** da biste dobili bitove kada otkrijete da je signal modulisan u frekvenciji i brzini simbola.
