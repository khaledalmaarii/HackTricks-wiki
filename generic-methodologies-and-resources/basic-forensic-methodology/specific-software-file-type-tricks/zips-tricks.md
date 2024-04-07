# Trikovi sa ZIP fajlovima

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

**Alati komandne linije** za upravljanje **zip fajlovima** su esencijalni za dijagnostikovanje, popravku i probijanje zip fajlova. Evo nekih ključnih alata:

- **`unzip`**: Otkriva zašto se zip fajl možda ne može dekompresovati.
- **`zipdetails -v`**: Nudi detaljnu analizu polja formata zip fajla.
- **`zipinfo`**: Lista sadržaj zip fajla bez njihovog ekstrahovanja.
- **`zip -F input.zip --out output.zip`** i **`zip -FF input.zip --out output.zip`**: Pokušajte da popravite oštećene zip fajlove.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Alat za brute-force probijanje zip šifri, efikasan za šifre do oko 7 karaktera.

Specifikacija [Zip formata fajla](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) pruža sveobuhvatne detalje o strukturi i standardima zip fajlova.

Važno je napomenuti da zip fajlovi zaštićeni šifrom **ne šifruju imena fajlova niti veličine fajlova** unutar sebe, sigurnosni propust koji nije zajednički za RAR ili 7z fajlove koji šifruju ove informacije. Osim toga, zip fajlovi enkriptovani starijom ZipCrypto metodom su ranjivi na **napad sa tekstom u otvorenom obliku** ako je dostupna neenkriptovana kopija kompresovanog fajla. Ovaj napad koristi poznati sadržaj za probijanje šifre zip fajla, ranjivost detaljno opisana u [HackThis-ovom članku](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) i dalje objašnjena u [ovom akademskom radu](https://www.cs.auckland.ac.nz/\~mike/zipattacks.pdf). Međutim, zip fajlovi obezbeđeni **AES-256** enkripcijom su imuni na ovaj napad sa tekstom u otvorenom obliku, pokazujući važnost izbora sigurnih metoda enkripcije za osetljive podatke.

## Reference
* [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
