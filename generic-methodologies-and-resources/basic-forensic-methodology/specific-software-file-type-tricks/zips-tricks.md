# Trikovi sa ZIP fajlovima

{% hint style="success" %}
Naučite i vežbajte hakovanje AWS-a:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Obuka AWS Crveni Tim Stručnjak (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Naučite i vežbajte hakovanje GCP-a: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Obuka GCP Crveni Tim Stručnjak (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Pomozite HackTricks-u</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}

**Alati komandne linije** za upravljanje **zip fajlovima** su neophodni za dijagnostikovanje, popravku i probijanje zip fajlova. Evo nekih ključnih alata:

- **`unzip`**: Otkriva zašto se zip fajl možda ne može dekompresovati.
- **`zipdetails -v`**: Nudi detaljnu analizu polja formata zip fajla.
- **`zipinfo`**: Lista sadržaj zip fajla bez njihovog ekstrahovanja.
- **`zip -F input.zip --out output.zip`** i **`zip -FF input.zip --out output.zip`**: Pokušajte da popravite oštećene zip fajlove.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Alat za brute-force probijanje zip šifri, efikasan za šifre do oko 7 karaktera.

Specifikacija formata zip fajlova pruža sveobuhvatne detalje o strukturi i standardima zip fajlova.

Važno je napomenuti da zip fajlovi zaštićeni šifrom **ne šifruju imena fajlova niti veličine fajlova** unutar sebe, što je sigurnosni propust koji nije zajednički za RAR ili 7z fajlove koji šifruju ove informacije. Osim toga, zip fajlovi šifrovani starijom metodom ZipCrypto su ranjivi na **napad sa tekstom u otvorenom obliku** ako je dostupna nešifrovana kopija kompresovanog fajla. Ovaj napad koristi poznati sadržaj za probijanje šifre zip fajla, ranjivost detaljno opisana u [HackThis-ovom članku](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) i dalje objašnjena u [ovom naučnom radu](https://www.cs.auckland.ac.nz/\~mike/zipattacks.pdf). Međutim, zip fajlovi obezbeđeni **AES-256** šifrovanjem su imuni na ovaj napad sa tekstom u otvorenom obliku, što pokazuje važnost izbora sigurnih metoda šifrovanja za osetljive podatke.

## Reference
* [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/) 

{% hint style="success" %}
Naučite i vežbajte hakovanje AWS-a:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Obuka AWS Crveni Tim Stručnjak (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Naučite i vežbajte hakovanje GCP-a: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Obuka GCP Crveni Tim Stručnjak (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Pomozite HackTricks-u</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
