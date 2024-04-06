# SmbExec/ScExec

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Jak to działa

**Smbexec** to narzędzie używane do zdalnego wykonywania poleceń na systemach Windows, podobne do **Psexec**, ale unika umieszczania jakichkolwiek złośliwych plików na docelowym systemie.

### Kluczowe punkty dotyczące **SMBExec**

- Działa poprzez tworzenie tymczasowej usługi (na przykład "BTOBTO") na maszynie docelowej w celu wykonania poleceń za pomocą cmd.exe (%COMSPEC%), bez zrzucania jakichkolwiek plików binarnych.
- Pomimo swojego skrytego podejścia, generuje dzienniki zdarzeń dla każdego wykonanego polecenia, oferując formę nieinteraktywnego "shell'a".
- Polecenie do połączenia za pomocą **Smbexec** wygląda następująco:
```bash
smbexec.py WORKGROUP/genericuser:genericpassword@10.10.10.10
```
### Wykonywanie poleceń bez użycia plików binarnych

- **Smbexec** umożliwia bezpośrednie wykonywanie poleceń za pomocą ścieżek binarnych usługi, eliminując potrzebę fizycznych plików binarnych na celu.
- Ta metoda jest przydatna do jednorazowego wykonywania poleceń na celu z systemem Windows. Na przykład, połączenie jej z modułem `web_delivery` w Metasploit pozwala na wykonanie odwróconego ładunku PowerShell-targeted Meterpreter.
- Tworząc zdalną usługę na maszynie atakującego z ustawioną ścieżką binarną do uruchomienia podanego polecenia za pomocą cmd.exe, można pomyślnie wykonać ładunek, osiągając wywołanie zwrotne i wykonanie ładunku z nasłuchiwaczem Metasploit, nawet jeśli wystąpią błędy odpowiedzi usługi.

### Przykład poleceń

Tworzenie i uruchamianie usługi można osiągnąć za pomocą następujących poleceń:
```bash
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
Aby uzyskać dalsze szczegóły, sprawdź [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)


## Odwołania
* [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
