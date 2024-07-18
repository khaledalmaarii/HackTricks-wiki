# Ostale Web Trikove

{% hint style="success" %}
Naučite i vežbajte AWS Hakovanje:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Obuka AWS Crveni Tim Ekspert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Naučite i vežbajte GCP Hakovanje: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Obuka GCP Crveni Tim Ekspert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Pomozite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Delite hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}

### Host header

Više puta se dešava da back-end veruje **Host header-u** da izvrši neke akcije. Na primer, može koristiti njegovu vrednost kao **domen za slanje resetovanja lozinke**. Dakle, kada primite email sa linkom za resetovanje lozinke, domen koji se koristi je onaj koji ste uneli u Host header. Zatim, možete zatražiti resetovanje lozinke drugih korisnika i promeniti domen u jedan koji kontrolišete kako biste ukrali njihove kodove za resetovanje lozinke. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).

{% hint style="warning" %}
Imajte na umu da je moguće da čak ne morate čekati da korisnik klikne na link za resetovanje lozinke da biste dobili token, jer možda čak i **spam filteri ili drugi posredni uređaji/botovi će kliknuti na njega da ga analiziraju**.
{% endhint %}

### Sesija sa boolean vrednostima

Ponekad kada uspešno završite neku verifikaciju, back-end će **samo dodati boolean sa vrednošću "True" atributu vaše sesije**. Zatim, drugi endpoint će znati da li ste uspešno prošli tu proveru.\
Međutim, ako **prođete proveru** i vašoj sesiji je dodeljena vrednost "True" u atributu bezbednosti, možete pokušati da **pristupite drugim resursima** koji **zavise od istog atributa** ali na koje **ne biste trebali imati dozvole** za pristup. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).

### Funkcionalnost registracije

Pokušajte da se registrujete kao već postojeći korisnik. Pokušajte takođe koristeći ekvivalentne karaktere (tačke, mnogo razmaka i Unicode).

### Preuzimanje emailova

Registrujte email, pre potvrde promenite email, zatim, ako je nova potvrda poslata na prvi registrovani email, možete preuzeti bilo koji email. Ili ako možete omogućiti drugi email potvrđujući prvi, takođe možete preuzeti bilo koji nalog.

### Pristup internom servisnom stolu kompanija koje koriste atlassian

{% embed url="https://yourcompanyname.atlassian.net/servicedesk/customer/user/login" %}

### TRACE metoda

Programeri ponekad zaborave da onemoguće različite opcije za debagovanje u produkcionom okruženju. Na primer, HTTP `TRACE` metoda je dizajnirana za dijagnostičke svrhe. Ako je omogućena, veb server će odgovoriti na zahteve koji koriste `TRACE` metodu tako što će u odgovoru odjeknuti tačan zahtev koji je primljen. Ovo ponašanje je često bezopasno, ali ponekad dovodi do otkrivanja informacija, kao što su naziv internih autentikacionih zaglavlja koja mogu biti dodata zahtevima od strane reverznih proxy-ja.![Image for post](https://miro.medium.com/max/60/1\*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1\*wDFRADTOd9Tj63xucenvAA.png)


{% hint style="success" %}
Naučite i vežbajte AWS Hakovanje:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Obuka AWS Crveni Tim Ekspert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Naučite i vežbajte GCP Hakovanje: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Obuka GCP Crveni Tim Ekspert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Pomozite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Delite hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
