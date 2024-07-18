{% hint style="success" %}
Učite i vežbajte hakovanje AWS-a:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte hakovanje GCP-a: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}


# CBC - Cipher Block Chaining

U CBC režimu se **prethodni šifrovani blok koristi kao IV** za XOR sa sledećim blokom:

![https://defuse.ca/images/cbc\_encryption.png](https://defuse.ca/images/cbc\_encryption.png)

Za dešifrovanje CBC-a se vrše **suprotne operacije**:

![https://defuse.ca/images/cbc\_decryption.png](https://defuse.ca/images/cbc\_decryption.png)

Primetite kako je potrebno koristiti **ključ za šifrovanje** i **IV**.

# Padding Poruke

Pošto se šifrovanje vrši u **fiksnim veličinama blokova**, **padding** je obično potreban u **poslednjem bloku** da bi se kompletirala njegova dužina.\
Obično se koristi **PKCS7**, koji generiše padding **ponavljanjem** **broja** **bajtova** **potrebnih** da se **kompletira** blok. Na primer, ako poslednjem bloku nedostaju 3 bajta, padding će biti `\x03\x03\x03`.

Pogledajmo još primera sa **2 bloka dužine 8 bajtova**:

| bajt #0 | bajt #1 | bajt #2 | bajt #3 | bajt #4 | bajt #5 | bajt #6 | bajt #7 | bajt #0  | bajt #1  | bajt #2  | bajt #3  | bajt #4  | bajt #5  | bajt #6  | bajt #7  |
| ------- | ------- | ------- | ------- | ------- | ------- | ------- | ------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | 6        | **0x02** | **0x02** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | **0x03** | **0x03** | **0x03** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | **0x05** | **0x05** | **0x05** | **0x05** | **0x05** |
| P       | A       | S       | S       | W       | O       | R       | D       | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** |

Primetite kako je u poslednjem primeru **poslednji blok bio pun pa je generisan još jedan samo sa paddingom**.

# Padding Oracle

Kada aplikacija dešifruje šifrovane podatke, prvo će dešifrovati podatke; zatim će ukloniti padding. Tokom čišćenja paddinga, ako **neispravan padding pokrene detektibilno ponašanje**, imate **ranjivost padding orakla**. Detektibilno ponašanje može biti **greška**, **nedostatak rezultata** ili **sporiji odgovor**.

Ako primetite ovo ponašanje, možete **dešifrovati šifrovane podatke** i čak **šifrovati bilo koji čisti tekst**.

## Kako iskoristiti

Možete koristiti [https://github.com/AonCyberLabs/PadBuster](https://github.com/AonCyberLabs/PadBuster) da iskoristite ovu vrstu ranjivosti ili jednostavno uraditi
```
sudo apt-get install padbuster
```
Da biste testirali da li je kolačić sajta ranjiv, možete pokušati:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
**Kodiranje 0** znači da se koristi **base64** (ali su dostupni i drugi, proverite meni pomoći).

Takođe možete **zloupotrebiti ovu ranjivost da biste šifrovali nove podatke. Na primer, zamislite da je sadržaj kolačića "**_**korisnik=MojeKorisničkoIme**_**", tada ga možete promeniti u "\_korisnik=administrator\_" i eskalirati privilegije unutar aplikacije. To takođe možete uraditi koristeći `paduster` navođenjem parametra -plaintext**:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA==" -plaintext "user=administrator"
```
Ako je sajt ranjiv, `padbuster` će automatski pokušati da pronađe kada se javlja greška u popunjavanju, ali možete i sami naznačiti poruku o grešci koristeći parametar **-error**.
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "" 8 -encoding 0 -cookies "hcon=RVJDQrwUdTRWJUVUeBKkEA==" -error "Invalid padding"
```
## Teorija

U **kratko**, možete početi dešifrovanje šifrovanih podataka pogađajući tačne vrednosti koje se mogu koristiti za kreiranje svih **različitih punjenja**. Zatim, napad padding orakl će početi dešifrovanje bajtova od kraja ka početku pogađajući koja će biti tačna vrednost koja **stvara punjenje od 1, 2, 3, itd**.

![](<../.gitbook/assets/image (629) (1) (1).png>)

Zamislite da imate neki šifrovan tekst koji zauzima **2 bloka** formirana bajtovima od **E0 do E15**.\
Da biste **dešifrovali** **poslednji** **blok** (**E8** do **E15**), ceo blok prolazi kroz "dešifrovanje blok šifre" generišući **posredne bajtove I0 do I15**.\
Na kraju, svaki posredni bajt se **XORuje** sa prethodnim šifrovanim bajtovima (E0 do E7). Dakle:

* `C15 = D(E15) ^ E7 = I15 ^ E7`
* `C14 = I14 ^ E6`
* `C13 = I13 ^ E5`
* `C12 = I12 ^ E4`
* ...

Sada je moguće **modifikovati `E7` dok `C15` ne bude `0x01`**, što će takođe biti tačno punjenje. Dakle, u ovom slučaju: `\x01 = I15 ^ E'7`

Dakle, pronalaženjem E'7, moguće je **izračunati I15**: `I15 = 0x01 ^ E'7`

Što nam omogućava da **izračunamo C15**: `C15 = E7 ^ I15 = E7 ^ \x01 ^ E'7`

Znajući **C15**, sada je moguće **izračunati C14**, ali ovog puta forsujući punjenje `\x02\x02`.

Ovaj BF je jednako složen kao i prethodni jer je moguće izračunati `E''15` čija je vrednost 0x02: `E''7 = \x02 ^ I15` tako da je potrebno samo pronaći **`E'14`** koji generiše **`C14` jednako `0x02`**.\
Zatim, uradite iste korake za dešifrovanje C14: **`C14 = E6 ^ I14 = E6 ^ \x02 ^ E''6`**

**Pratite ovaj lanac dok ne dešifrujete ceo šifrovan tekst.**

## Otkrivanje ranjivosti

Registrujte nalog i prijavite se sa tim nalogom.\
Ako se **prijavite mnogo puta** i uvek dobijete **isti kolačić**, verovatno postoji **nešto** **pogrešno** u aplikaciji. Kolačić koji se vraća trebao bi biti jedinstven svaki put kada se prijavite. Ako je kolačić **uvek** **isti**, verovatno će uvek biti validan i neće biti načina da se on poništi.

Sada, ako pokušate da **modifikujete** kolačić, videćete da dobijate **grešku** od aplikacije.\
Ali ako forsite punjenje (koristeći na primer padbuster) uspećete da dobijete drugi kolačić koji je validan za drugog korisnika. Ovaj scenario je vrlo verovatno ranjiv na padbuster.

## Reference

* [https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation](https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation)


{% hint style="success" %}
Naučite i vežbajte hakovanje AWS-a:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Naučite i vežbajte hakovanje GCP-a: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
