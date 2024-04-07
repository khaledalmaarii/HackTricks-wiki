# Kriptografski/Kompresioni Algoritmi

## Kriptografski/Kompresioni Algoritmi

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## Identifikacija Algoritama

Ako naiđete na kod **koji koristi pomeranja u desno i levo, ekskluzivno ili više aritmetičkih operacija**, veoma je verovatno da je implementacija **kriptografskog algoritma**. Ovde će biti prikazano nekoliko načina za **identifikaciju korišćenog algoritma bez potrebe za reverzom svakog koraka**.

### API funkcije

**CryptDeriveKey**

Ako se koristi ova funkcija, možete saznati koji **algoritam se koristi** proverom vrednosti drugog parametra:

![](<../../.gitbook/assets/image (153).png>)

Pogledajte ovde tabelu mogućih algoritama i njihove dodeljene vrednosti: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Kompresuje i dekompresuje dati blok podataka.

**CryptAcquireContext**

Iz [dokumenata](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta): Funkcija **CryptAcquireContext** se koristi za dobijanje ručke ka određenom kontejneru ključeva unutar određenog provajdera kriptografskih usluga (CSP). **Ova vraćena ručka se koristi u pozivima funkcija CryptoAPI** koje koriste izabrani CSP.

**CryptCreateHash**

Pokreće heširanje toka podataka. Ako se koristi ova funkcija, možete saznati koji **algoritam se koristi** proverom vrednosti drugog parametra:

![](<../../.gitbook/assets/image (546).png>)

Pogledajte ovde tabelu mogućih algoritama i njihove dodeljene vrednosti: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Konstante koda

Ponekad je zaista lako identifikovati algoritam zahvaljujući činjenici da mora koristiti posebnu i jedinstvenu vrednost.

![](<../../.gitbook/assets/image (830).png>)

Ako pretražite prvu konstantu na Google-u, dobićete sledeće:

![](<../../.gitbook/assets/image (526).png>)

Stoga, možete pretpostaviti da je dekompilirana funkcija **kalkulator sha256**.\
Možete pretražiti bilo koju od drugih konstanti i verovatno ćete dobiti isti rezultat.

### Informacije o podacima

Ako kod nema značajne konstante, možda **učitava informacije iz .data sekcije**.\
Možete pristupiti tim podacima, **grupisati prvi dvojni reč** i pretražiti ih na Google-u kao što smo uradili u prethodnom odeljku:

![](<../../.gitbook/assets/image (528).png>)

U ovom slučaju, ako potražite **0xA56363C6** možete saznati da je povezano sa **tabelama algoritma AES**.

## RC4 **(Simetrična Kriptografija)**

### Karakteristike

Sastoji se od 3 glavna dela:

* **Faza inicijalizacije/**: Kreira **tabelu vrednosti od 0x00 do 0xFF** (ukupno 256 bajtova, 0x100). Ova tabela se obično naziva **Substitution Box** (ili SBox).
* **Faza mešanja**: Proći će **kroz prethodno kreiranu tabelu** (petlja od 0x100 iteracija, ponovo) modifikujući svaku vrednost sa **polu-slučajnim** bajtovima. Da bi se kreirali ovi polu-slučajni bajtovi, koristi se RC4 **ključ**. RC4 **ključevi** mogu biti **između 1 i 256 bajtova u dužini**, međutim obično se preporučuje da bude iznad 5 bajtova. Obično, RC4 ključevi su dužine 16 bajtova.
* **XOR faza**: Na kraju, plain-text ili šifrat je **XOR-ovan sa vrednostima kreiranim ranije**. Funkcija za šifrovanje i dešifrovanje je ista. Za to će se izvršiti **petlja kroz kreiranih 256 bajtova** koliko god puta je potrebno. Ovo se obično prepoznaje u dekompiliranom kodu sa **%256 (mod 256)**.

{% hint style="info" %}
**Da biste identifikovali RC4 u disasembliranom/dekompiliranom kodu, možete proveriti 2 petlje veličine 0x100 (sa korišćenjem ključa) i zatim XOR ulaznih podataka sa 256 vrednosti kreiranih ranije u 2 petlje, verovatno koristeći %256 (mod 256)**
{% endhint %}

### **Faza inicijalizacije/Substitution Box:** (Obratite pažnju na broj 256 korišćen kao brojač i kako je 0 upisan na svako mesto od 256 karaktera)

![](<../../.gitbook/assets/image (581).png>)

### **Faza mešanja:**

![](<../../.gitbook/assets/image (832).png>)

### **XOR faza:**

![](<../../.gitbook/assets/image (901).png>)

## **AES (Simetrična Kriptografija)**

### **Karakteristike**

* Korišćenje **substitution box-ova i lookup tabela**
* Moguće je **razlikovati AES zahvaljujući korišćenju specifičnih vrednosti lookup tabela** (konstanti). _Imajte na umu da se **konstanta** može **skladištiti** u binarnom obliku **ili kreirati**_ _**dinamički**._
* **Ključ za šifrovanje** mora biti **deljiv** sa **16** (obično 32B) i obično se koristi IV od 16B.

### Konstante SBox-a

![](<../../.gitbook/assets/image (205).png>)

## Serpent **(Simetrična Kriptografija)**

### Karakteristike

* Retko je pronaći malver koji ga koristi, ali postoje primeri (Ursnif)
* Jednostavno je odrediti da li je algoritam Serpent ili ne na osnovu njegove dužine (izuzetno duga funkcija)

### Identifikacija

U sledećoj slici primetite kako se koristi konstanta **0x9E3779B9** (imajte na umu da se ova konstanta takođe koristi i u drugim kripto algoritmima poput **TEA** -Tiny Encryption Algorithm).\
Takođe obratite pažnju na **veličinu petlje** (**132**) i **broj XOR operacija** u instrukcijama **disasemblera** i u **primeru koda**:

![](<../../.gitbook/assets/image (544).png>)

Kao što je pomenuto ranije, ovaj kod može biti vizualizovan unutar bilo kog dekompajlera kao **vrlo duga funkcija** jer unutar nje **nema skokova**. Dekompilirani kod može izgledati ovako:

![](<../../.gitbook/assets/image (510).png>)

Stoga je moguće identifikovati ovaj algoritam proverom **magičnog broja** i **početnih XOR-ova**, videći **vrlo dugu funkciju** i **upoređujući** neke **instrukcije** iz duge funkcije **sa implementacijom** (kao što je pomeranje u levo za 7 i rotacija u levo za 22).
## RSA **(Asimetrična kriptografija)**

### Karakteristike

* Složenija od simetričnih algoritama
* Nema konstanti! (prilagođene implementacije su teške za određivanje)
* KANAL (kripto analizator) ne pokazuje naznake za RSA jer se oslanja na konstante.

### Identifikacija pomoću poređenja

![](<../../.gitbook/assets/image (1110).png>)

* U liniji 11 (levo) postoji `+7) >> 3` što je isto kao u liniji 35 (desno): `+7) / 8`
* Linija 12 (levo) proverava da li je `modulus_len < 0x040` i u liniji 36 (desno) proverava da li je `inputLen+11 > modulusLen`

## MD5 & SHA (heš)

### Karakteristike

* 3 funkcije: Init, Update, Final
* Slične inicijalizacijske funkcije

### Identifikacija

**Init**

Možete ih identifikovati proverom konstanti. Imajte na umu da sha\_init ima 1 konstantu koju MD5 nema:

![](<../../.gitbook/assets/image (403).png>)

**MD5 Transform**

Primetite korišćenje više konstanti

![](<../../.gitbook/assets/image (253) (1) (1).png>)

## CRC (heš)

* Manji i efikasniji jer je njegova funkcija da pronađe slučajne promene u podacima
* Koristi tabele za pretragu (tako da možete identifikovati konstante)

### Identifikacija

Proverite **konstante u tabeli za pretragu**:

![](<../../.gitbook/assets/image (505).png>)

Algoritam za CRC heš izgleda ovako:

![](<../../.gitbook/assets/image (387).png>)

## APLib (Kompresija)

### Karakteristike

* Nerecognoscibilne konstante
* Možete pokušati da napišete algoritam u Pythonu i tražite slične stvari na mreži

### Identifikacija

Grafikon je prilično velik:

![](<../../.gitbook/assets/image (207) (2) (1).png>)

Proverite **3 poređenja da biste ga prepoznali**:

![](<../../.gitbook/assets/image (427).png>)
