# Bilet diamentowy

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Bilet diamentowy

**Podobnie jak złoty bilet**, bilet diamentowy to TGT, który można użyć do **uzyskania dostępu do dowolnej usługi jako dowolny użytkownik**. Złoty bilet jest całkowicie sfałszowany offline, zaszyfrowany za pomocą hasha krbtgt tego domeny, a następnie przekazywany do sesji logowania w celu użycia. Ponieważ kontrolery domeny nie śledzą TGT, które zostały wydane legalnie, chętnie akceptują TGT, które są zaszyfrowane za pomocą własnego hasha krbtgt.

Istnieją dwie powszechne techniki wykrywania użycia złotych biletów:

* Szukanie TGS-REQ, które nie mają odpowiadającego AS-REQ.
* Szukanie TGT, które mają śmieszne wartości, takie jak domyślny 10-letni okres ważności Mimikatz.

**Bilet diamentowy** jest tworzony poprzez **modyfikację pól prawidłowego TGT, które zostało wydane przez kontroler domeny**. Dokonuje się tego poprzez **żądanie** TGT, **odszyfrowanie** go za pomocą hasha krbtgt domeny, **modyfikację** żądanych pól biletu, a następnie **ponowne zaszyfrowanie** go. To **eliminuje dwie wcześniej wspomniane wady** złotego biletu, ponieważ:

* TGS-REQ będą miały poprzedzające AS-REQ.
* TGT został wydany przez kontroler domeny, co oznacza, że będzie miał wszystkie poprawne szczegóły z polityki Kerberos domeny. Chociaż można je dokładnie sfałszować w złotym bilecie, jest to bardziej skomplikowane i podatne na błędy.
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
<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
