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

**Jak złoty bilet**, diamentowy bilet to TGT, który może być użyty do **uzyskania dostępu do dowolnej usługi jako dowolny użytkownik**. Złoty bilet jest fałszowany całkowicie offline, szyfrowany hashem krbtgt tej domeny, a następnie przekazywany do sesji logowania do użycia. Ponieważ kontrolery domeny nie śledzą TGT, które (lub które) zostały legalnie wydane, chętnie zaakceptują TGT, które są szyfrowane ich własnym hashem krbtgt.

Istnieją dwie powszechne techniki wykrywania użycia złotych biletów:

* Szukaj TGS-REQ, które nie mają odpowiadającego AS-REQ.
* Szukaj TGT, które mają absurdalne wartości, takie jak domyślna 10-letnia żywotność Mimikatz.

**Diamentowy bilet** jest tworzony przez **modyfikację pól legalnego TGT, które zostało wydane przez DC**. Osiąga się to poprzez **zażądanie** **TGT**, **odszyfrowanie** go hashem krbtgt domeny, **zmodyfikowanie** pożądanych pól biletu, a następnie **ponowne zaszyfrowanie** go. To **przezwycięża dwa wcześniej wspomniane niedociągnięcia** złotego biletu, ponieważ:

* TGS-REQ będą miały poprzedzający AS-REQ.
* TGT zostało wydane przez DC, co oznacza, że będzie miało wszystkie poprawne szczegóły z polityki Kerberos domeny. Chociaż te mogą być dokładnie fałszowane w złotym bilecie, jest to bardziej skomplikowane i podatne na błędy.
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
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na githubie.

</details>
{% endhint %}
