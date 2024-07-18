{% hint style="success" %}
Učite i vežbajte hakovanje AWS-a:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Obuka AWS Crveni Tim Stručnjak (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte hakovanje GCP-a: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Obuka GCP Crveni Tim Stručnjak (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Delite hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}


# CBC

Ako je **kolačić** **samo** **korisničko ime** (ili je prvi deo kolačića korisničko ime) i želite da se predstavite kao korisnik "**admin**". Tada možete kreirati korisničko ime **"bdmin"** i **bruteforce** prvi bajt kolačića.

# CBC-MAC

**Šifrovano vezivanje poruka za autentifikaciju blokova** (**CBC-MAC**) je metoda korišćena u kriptografiji. Radi tako što uzima poruku i šifruje je blok po blok, gde je šifrovanje svakog bloka povezano sa prethodnim. Ovaj proces stvara **lanac blokova**, osiguravajući da čak i promena jednog bita originalne poruke dovede do nepredvidive promene poslednjeg bloka šifrovanih podataka. Da bi se napravila ili poništila takva promena, potreban je ključ za šifrovanje, obezbeđujući sigurnost.

Da bi se izračunao CBC-MAC poruke m, poruka se šifruje u CBC režimu sa nulom kao inicijalizacioni vektor i čuva se poslednji blok. Sledeća slika prikazuje računanje CBC-MAC poruke koja se sastoji od blokova ![https://wikimedia.org/api/rest\_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5](https://wikimedia.org/api/rest\_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5) koristeći tajni ključ k i blok šifre E:

![https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC\_structure\_\(en\).svg/570px-CBC-MAC\_structure\_\(en\).svg.png](https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC\_structure\_\(en\).svg/570px-CBC-MAC\_structure\_\(en\).svg.png)

# Ranjivost

Sa CBC-MAC obično se koristi **IV 0**.\
To je problem jer će 2 poznate poruke (`m1` i `m2`) nezavisno generisati 2 potpisa (`s1` i `s2`). Dakle:

* `E(m1 XOR 0) = s1`
* `E(m2 XOR 0) = s2`

Zatim će poruka sastavljena od m1 i m2 konkateniranih (m3) generisati 2 potpisa (s31 i s32):

* `E(m1 XOR 0) = s31 = s1`
* `E(m2 XOR s1) = s32`

**Što je moguće izračunati bez poznavanja ključa za šifrovanje.**

Zamislite da šifrujete ime **Administrator** u blokovima od **8 bajtova**:

* `Administ`
* `rator\00\00\00`

Možete kreirati korisničko ime nazvano **Administ** (m1) i dobiti potpis (s1).\
Zatim možete kreirati korisničko ime nazvano rezultat `rator\00\00\00 XOR s1`. Ovo će generisati `E(m2 XOR s1 XOR 0)` što je s32.\
sada, možete koristiti s32 kao potpis punog imena **Administrator**.

### Rezime

1. Dobijte potpis korisničkog imena **Administ** (m1) koji je s1
2. Dobijte potpis korisničkog imena **rator\x00\x00\x00 XOR s1 XOR 0** je s32**.**
3. Postavite kolačić na s32 i biće validan kolačić za korisnika **Administrator**.

# Kontrolisanje napada IV

Ako možete kontrolisati korišćeni IV, napad bi mogao biti veoma lak.\
Ako su kolačići samo šifrovano korisničko ime, da se predstavite kao korisnik "**administrator**" možete kreirati korisnika "**Administrator**" i dobićete njegov kolačić.\
Sada, ako možete kontrolisati IV, možete promeniti prvi bajt IV-a tako da **IV\[0] XOR "A" == IV'\[0] XOR "a"** i ponovo generisati kolačić za korisnika **Administrator**. Ovaj kolačić će biti validan za **predstavljanje** korisnika **administrator** sa početnim **IV**.

## Reference

Više informacija na [https://en.wikipedia.org/wiki/CBC-MAC](https://en.wikipedia.org/wiki/CBC-MAC)


{% hint style="success" %}
Učite i vežbajte hakovanje AWS-a:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Obuka AWS Crveni Tim Stručnjak (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte hakovanje GCP-a: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Obuka GCP Crveni Tim Stručnjak (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Delite hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
