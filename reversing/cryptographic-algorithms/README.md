# Kriptografski/Kompresioni Algoritmi

## Kriptografski/Kompresioni Algoritmi

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}

## Identifikacija Algoritama

Ako završite u kodu **koristeći pomeranje udesno i ulevo, xore i nekoliko aritmetičkih operacija** veoma je verovatno da je to implementacija **kriptografskog algoritma**. Ovde će biti prikazani neki načini da se **identifikuje algoritam koji se koristi bez potrebe da se obrne svaki korak**.

### API funkcije

**CryptDeriveKey**

Ako se ova funkcija koristi, možete pronaći koji **algoritam se koristi** proveravajući vrednost drugog parametra:

![](<../../.gitbook/assets/image (375) (1) (1) (1) (1).png>)

Proverite ovde tabelu mogućih algoritama i njihovih dodeljenih vrednosti: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Kompresuje i dekompresuje dati bafer podataka.

**CryptAcquireContext**

Iz [dokumentacije](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta): Funkcija **CryptAcquireContext** se koristi za sticanje rukohvata do određenog kontejnera ključeva unutar određenog pružatelja kriptografskih usluga (CSP). **Ovaj vraćeni rukohvat se koristi u pozivima funkcija CryptoAPI** koje koriste odabrani CSP.

**CryptCreateHash**

Inicira heširanje toka podataka. Ako se ova funkcija koristi, možete pronaći koji **algoritam se koristi** proveravajući vrednost drugog parametra:

![](<../../.gitbook/assets/image (376).png>)

\
Proverite ovde tabelu mogućih algoritama i njihovih dodeljenih vrednosti: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Konstantne vrednosti koda

Ponekad je veoma lako identifikovati algoritam zahvaljujući činjenici da mora koristiti posebnu i jedinstvenu vrednost.

![](<../../.gitbook/assets/image (370).png>)

Ako pretražujete prvu konstantu na Google-u, ovo je ono što dobijate:

![](<../../.gitbook/assets/image (371).png>)

Stoga, možete pretpostaviti da je dekompilovana funkcija **sha256 kalkulator.**\
Možete pretražiti bilo koju od drugih konstanti i dobićete (verovatno) isti rezultat.

### informacija o podacima

Ako kod nema nijednu značajnu konstantu, može biti **učitavanje informacija iz .data sekcije**.\
Možete pristupiti tim podacima, **grupisati prvi dword** i pretražiti ga na Google-u kao što smo uradili u prethodnoj sekciji:

![](<../../.gitbook/assets/image (372).png>)

U ovom slučaju, ako tražite **0xA56363C6** možete pronaći da je povezan sa **tabelama AES algoritma**.

## RC4 **(Simetrična Kriptografija)**

### Karakteristike

Sastoji se od 3 glavna dela:

* **Faza inicijalizacije/**: Kreira **tabelu vrednosti od 0x00 do 0xFF** (ukupno 256 bajtova, 0x100). Ova tabela se obično naziva **Substituciona Kutija** (ili SBox).
* **Faza premeštanja**: **Prolazi kroz tabelu** kreiranu pre (petlja od 0x100 iteracija, ponovo) modifikujući svaku vrednost sa **polu-nasumičnim** bajtovima. Da bi se kreirali ovi polu-nasumični bajtovi, koristi se RC4 **ključ**. RC4 **ključevi** mogu biti **između 1 i 256 bajtova dužine**, međutim obično se preporučuje da budu iznad 5 bajtova. Obično, RC4 ključevi su 16 bajtova dužine.
* **XOR faza**: Na kraju, običan tekst ili šifrovani tekst se **XOR-uje sa vrednostima kreiranim pre**. Funkcija za enkripciju i dekripciju je ista. Za ovo, **proći će se kroz kreiranih 256 bajtova** onoliko puta koliko je potrebno. Ovo se obično prepoznaje u dekompilovanom kodu sa **%256 (mod 256)**.

{% hint style="info" %}
**Da biste identifikovali RC4 u disasembleru/dekompilovanom kodu, možete proveriti 2 petlje veličine 0x100 (uz korišćenje ključa) i zatim XOR ulaznih podataka sa 256 vrednosti kreiranih pre u 2 petlje verovatno koristeći %256 (mod 256)**
{% endhint %}

### **Faza inicijalizacije/Substituciona Kutija:** (Obratite pažnju na broj 256 korišćen kao brojač i kako se 0 piše na svakom mestu od 256 karaktera)

![](<../../.gitbook/assets/image (377).png>)

### **Faza premeštanja:**

![](<../../.gitbook/assets/image (378).png>)

### **XOR Faza:**

![](<../../.gitbook/assets/image (379).png>)

## **AES (Simetrična Kriptografija)**

### **Karakteristike**

* Korišćenje **substitucionih kutija i tabela za pretragu**
* Moguće je **razlikovati AES zahvaljujući korišćenju specifičnih vrednosti tabela za pretragu** (konstanti). _Napomena da se **konstant** može **čuvati** u binarnom **ili kreirati** _**dinamički**._
* **Ključ za enkripciju** mora biti **deljiv** sa **16** (obično 32B) i obično se koristi **IV** od 16B.

### SBox konstante

![](<../../.gitbook/assets/image (380).png>)

## Serpent **(Simetrična Kriptografija)**

### Karakteristike

* Retko se nalazi neki malware koji ga koristi, ali postoje primeri (Ursnif)
* Lako je odrediti da li je algoritam Serpent ili ne na osnovu njegove dužine (ekstremno duga funkcija)

### Identifikacija

Na sledećoj slici obratite pažnju na to kako se konstanta **0x9E3779B9** koristi (napomena da se ova konstanta takođe koristi od drugih kripto algoritama kao što je **TEA** -Tiny Encryption Algorithm).\
Takođe obratite pažnju na **veličinu petlje** (**132**) i **broj XOR operacija** u **disasembleru** i u **primeru koda**:

![](<../../.gitbook/assets/image (381).png>)

Kao što je pomenuto ranije, ovaj kod može biti vizualizovan unutar bilo kog dekompilatora kao **veoma duga funkcija** jer **nema skakanja** unutar nje. Dekomplovani kod može izgledati ovako:

![](<../../.gitbook/assets/image (382).png>)

Stoga, moguće je identifikovati ovaj algoritam proveravajući **magični broj** i **početne XOR-ove**, videći **veoma dugu funkciju** i **upoređujući** neke **instrukcije** duge funkcije **sa implementacijom** (kao što je pomeranje ulevo za 7 i rotacija ulevo za 22).

## RSA **(Asimetrična Kriptografija)**

### Karakteristike

* Složenije od simetričnih algoritama
* Nema konstanti! (prilagođene implementacije su teške za određivanje)
* KANAL (analizator kriptografije) ne uspeva da pokaže naznake o RSA jer se oslanja na konstante.

### Identifikacija poređenjem

![](<../../.gitbook/assets/image (383).png>)

* U liniji 11 (levo) postoji `+7) >> 3` što je isto kao u liniji 35 (desno): `+7) / 8`
* Linija 12 (levo) proverava da li je `modulus_len < 0x040` a u liniji 36 (desno) proverava da li je `inputLen+11 > modulusLen`

## MD5 & SHA (heš)

### Karakteristike

* 3 funkcije: Init, Update, Final
* Slične inicijalizacione funkcije

### Identifikacija

**Init**

Možete identifikovati oboje proveravajući konstante. Napomena da sha\_init ima 1 konstantu koju MD5 nema:

![](<../../.gitbook/assets/image (385).png>)

**MD5 Transformacija**

Obratite pažnju na korišćenje više konstanti

![](<../../.gitbook/assets/image (253) (1) (1) (1).png>)

## CRC (heš)

* Manji i efikasniji jer je njegova funkcija da pronađe slučajne promene u podacima
* Koristi tabele za pretragu (tako da možete identifikovati konstante)

### Identifikacija

Proverite **konstante tabela za pretragu**:

![](<../../.gitbook/assets/image (387).png>)

CRC heš algoritam izgleda ovako:

![](<../../.gitbook/assets/image (386).png>)

## APLib (Kompresija)

### Karakteristike

* Nema prepoznatljivih konstanti
* Možete pokušati da napišete algoritam u python-u i pretražiti slične stvari online

### Identifikacija

Grafik je prilično veliki:

![](<../../.gitbook/assets/image (207) (2) (1).png>)

Proverite **3 poređenja da biste ga prepoznali**:

![](<../../.gitbook/assets/image (384).png>)

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
