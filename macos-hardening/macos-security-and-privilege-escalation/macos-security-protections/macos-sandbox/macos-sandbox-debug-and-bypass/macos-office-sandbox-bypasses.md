# Przejścia obwodów piaskownicy w macOS Office

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów GitHub.

</details>

### Słowo Bypass piaskownicy za pomocą agentów uruchomieniowych

Aplikacja korzysta z **niestandardowej piaskownicy** przy użyciu uprawnienia **`com.apple.security.temporary-exception.sbpl`**, a ta niestandardowa piaskownica pozwala na zapisywanie plików w dowolnym miejscu, o ile nazwa pliku zaczyna się od `~$`: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Dlatego ucieczka była tak łatwa jak **zapisanie pliku `plist`** LaunchAgent w `~/Library/LaunchAgents/~$escape.plist`.

Sprawdź [**oryginalny raport tutaj**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).

### Słowo Bypass piaskownicy za pomocą elementów logowania i zip

Pamiętaj, że po pierwszej ucieczce, Word może zapisywać dowolne pliki, których nazwa zaczyna się od `~$`, chociaż po poprawce poprzedniej podatności nie było możliwe zapisywanie w `/Library/Application Scripts` lub `/Library/LaunchAgents`.

Odkryto, że z piaskownicy można utworzyć **Element logowania** (aplikacje, które będą uruchamiane po zalogowaniu użytkownika). Jednak te aplikacje **nie zostaną uruchomione**, chyba że są **podpisane** i **niemożliwe jest dodanie argumentów** (więc nie można po prostu uruchomić odwróconej powłoki za pomocą **`bash`**).

Po poprzedniej ucieczce z piaskownicy, Microsoft wyłączył możliwość zapisywania plików w `~/Library/LaunchAgents`. Jednak odkryto, że jeśli umieścisz **plik zip jako Element logowania**, `Archive Utility` po prostu go **rozpakuje** w bieżącej lokalizacji. Dlatego, ponieważ domyślnie folder `LaunchAgents` z `~/Library` nie jest tworzony, można było **spakować plik plist w `LaunchAgents/~$escape.plist`** i **umieścić** plik zip w **`~/Library`**, aby po rozpakowaniu dotarł do miejsca trwałości.

Sprawdź [**oryginalny raport tutaj**](https://objective-see.org/blog/blog\_0x4B.html).

### Słowo Bypass piaskownicy za pomocą elementów logowania i .zshenv

(Pamiętaj, że po pierwszej ucieczce, Word może zapisywać dowolne pliki, których nazwa zaczyna się od `~$`).

Jednak poprzednia technika miała ograniczenie - jeśli folder **`~/Library/LaunchAgents`** istnieje, ponieważ został utworzony przez inne oprogramowanie, operacja zakończyłaby się niepowodzeniem. Dlatego odkryto inną sekwencję Elementów logowania dla tego przypadku.

Atakujący mógł utworzyć pliki **`.bash_profile`** i **`.zshenv`** z ładunkiem do wykonania, a następnie spakować je i **zapisać plik zip w folderze użytkownika ofiary**: **`~/~$escape.zip`**.

Następnie dodać plik zip do **Elementów logowania**, a następnie do aplikacji **`Terminal`**. Po ponownym zalogowaniu użytkownika plik zip zostanie rozpakowany w plikach użytkownika, nadpisując **`.bash_profile`** i **`.zshenv`**, a więc terminal wykona jeden z tych plików (w zależności od tego, czy używany jest bash czy zsh).

Sprawdź [**oryginalny raport tutaj**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).

### Słowo Bypass piaskownicy za pomocą Open i zmiennych środowiskowych

Z procesów w piaskownicy nadal można wywoływać inne procesy za pomocą narzędzia **`open`**. Ponadto, te procesy będą działać **w swojej własnej piaskownicy**.

Odkryto, że narzędzie open ma opcję **`--env`**, która pozwala uruchomić aplikację z **określonymi zmiennymi środowiskowymi**. Dlatego można było utworzyć plik **`.zshenv`** w folderze **wewnątrz** piaskownicy i użyć `open` z `--env`, ustawiając zmienną **`HOME`** na ten folder, otwierając tę aplikację **Terminal**, która wykona plik `.zshenv` (z jakiegoś powodu konieczne było również ustawienie zmiennej `__OSINSTALL_ENVIROMENT`).

Sprawdź [**oryginalny raport tutaj**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).

### Słowo Bypass piaskownicy za pomocą Open i stdin

Narzędzie **`open`** obsługiwało również parametr **`--stdin`** (a po poprzedniej ucieczce nie było już możliwe użycie `--env`).

Chodzi o to, że nawet jeśli **`python`** był podpisany przez Apple, **nie będzie wykonywał** skryptu z atrybutem **`quarantine`**. Jednak można było przekazać mu skrypt ze standardowego wejścia (stdin), więc nie sprawdzał, czy był kwarantannowany czy nie:&#x20;

1. Upuść plik **`~$exploit.py`** z dowolnymi poleceniami Pythona.
2. Uruchom _open_ **`–stdin='~$exploit.py' -a Python`**, co uruchamia aplikację Python z naszym upuszczonym plikiem jako standardowe wejście. Python z radością wykonuje nasz kod i ponieważ jest to proces potomny _launchd_, nie podlega zasadom piaskownicy Worda.

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [
