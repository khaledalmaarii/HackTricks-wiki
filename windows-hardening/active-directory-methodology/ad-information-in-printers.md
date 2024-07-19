{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}


Postoji nekoliko blogova na internetu koji **ističu opasnosti ostavljanja štampača konfiguranih sa LDAP sa podrazumevanjem/slabim** lozinkama.\
To je zato što bi napadač mogao **prevariti štampač da se autentifikuje protiv lažnog LDAP servera** (tipično je `nc -vv -l -p 444` dovoljno) i da uhvati **lozinke štampača u čistom tekstu**.

Takođe, nekoliko štampača će sadržati **logove sa korisničkim imenima** ili čak mogu biti u mogućnosti da **preuzmu sva korisnička imena** sa Kontrolera domena.

Sve ove **osetljive informacije** i uobičajeni **nedostatak sigurnosti** čine štampače veoma zanimljivim za napadače.

Neki blogovi o ovoj temi:

* [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
* [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

## Konfiguracija štampača
- **Lokacija**: Lista LDAP servera se nalazi na: `Network > LDAP Setting > Setting Up LDAP`.
- **Ponašanje**: Interfejs omogućava izmene LDAP servera bez ponovnog unosa lozinki, što je usmereno na pogodnost korisnika, ali predstavlja sigurnosne rizike.
- **Eksploatacija**: Eksploatacija uključuje preusmeravanje adrese LDAP servera na kontrolisanu mašinu i korišćenje funkcije "Test Connection" za hvatanje lozinki.

## Hvatanje lozinki

**Za detaljnije korake, pogledajte originalni [izvor](https://grimhacker.com/2018/03/09/just-a-printer/).**

### Metoda 1: Netcat Listener
Jednostavan netcat listener bi mogao biti dovoljan:
```bash
sudo nc -k -v -l -p 386
```
Međutim, uspeh ove metode varira.

### Metoda 2: Potpuni LDAP Server sa Slapd
Pouzdaniji pristup uključuje postavljanje potpunog LDAP servera jer štampač izvršava null bind nakon čega sledi upit pre nego što pokuša vezivanje kredencijala.

1. **Podešavanje LDAP Servera**: Vodič prati korake iz [ovog izvora](https://www.server-world.info/en/note?os=Fedora_26&p=openldap).
2. **Ključni Koraci**:
- Instalirajte OpenLDAP.
- Konfigurišite admin lozinku.
- Uvezite osnovne šeme.
- Postavite naziv domena na LDAP DB.
- Konfigurišite LDAP TLS.
3. **Izvršenje LDAP Usluge**: Kada je postavljen, LDAP usluga se može pokrenuti koristeći:
```bash
slapd -d 2
```
## Reference
* [https://grimhacker.com/2018/03/09/just-a-printer/](https://grimhacker.com/2018/03/09/just-a-printer/)


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
