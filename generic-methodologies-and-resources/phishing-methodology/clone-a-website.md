<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>


W przypadku oceny phishingowej czasami może być przydatne całkowite **sklonowanie strony internetowej**.

Należy jednak pamiętać, że można również dodać do sklonowanej strony niektóre ładunki, takie jak hak BeEF, aby "kontrolować" kartę użytkownika.

Istnieje wiele narzędzi, które można użyć w tym celu:

## wget
```text
wget -mk -nH
```
## goclone

`goclone` jest narzędziem do klonowania stron internetowych, które umożliwia tworzenie dokładnych kopii istniejących witryn. Może być używane do przeprowadzania ataków phishingowych, w których oszuści próbują podszyć się pod prawdziwe strony internetowe w celu wyłudzenia poufnych informacji od użytkowników.

### Instalacja

Aby zainstalować `goclone`, wykonaj następujące kroki:

1. Pobierz kod źródłowy z repozytorium GitHub:

   ```
   git clone https://github.com/username/goclone.git
   ```

2. Przejdź do katalogu `goclone`:

   ```
   cd goclone
   ```

3. Zainstaluj zależności:

   ```
   go mod download
   ```

4. Skompiluj `goclone`:

   ```
   go build
   ```

### Użycie

Aby sklonować stronę internetową za pomocą `goclone`, wykonaj następujące kroki:

1. Uruchom `goclone` i podaj adres URL strony, którą chcesz sklonować:

   ```
   ./goclone clone https://www.example.com
   ```

2. `goclone` utworzy kopię strony internetowej w bieżącym katalogu. Możesz dostosować lokalizację, w której zostanie utworzona kopia, używając flagi `-o`:

   ```
   ./goclone clone -o /path/to/clone https://www.example.com
   ```

3. Po zakończeniu procesu klonowania, możesz przeglądać sklonowaną stronę internetową, otwierając plik `index.html` w przeglądarce:

   ```
   firefox index.html
   ```

### Ostrzeżenie

Należy pamiętać, że klonowanie stron internetowych bez zgody ich właścicieli jest nielegalne i narusza prawa autorskie. `goclone` powinno być używane wyłącznie w celach edukacyjnych lub w ramach legalnych testów penetracyjnych.
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## Zestaw narzędzi do inżynierii społecznej

### Klonowanie strony internetowej

Klonowanie strony internetowej jest jedną z najpopularniejszych technik wykorzystywanych w atakach phishingowych. Polega ona na stworzeniu identycznego lub bardzo podobnego wyglądem podrabianego serwisu, który ma na celu oszukanie użytkowników i wyłudzenie ich poufnych informacji, takich jak hasła czy dane logowania.

#### Klonowanie strony internetowej krok po kroku

1. Wybierz stronę do sklonowania: Wybierz stronę, którą chcesz sklonować. Może to być popularna platforma społecznościowa, bankowość elektroniczna lub jakikolwiek inny serwis, który przyciąga dużą liczbę użytkowników.

2. Pobierz zawartość strony: Skopiuj kod źródłowy strony, którą chcesz sklonować. Możesz to zrobić, korzystając z narzędzi do przeglądania kodu strony, takich jak przeglądarka internetowa lub narzędzia do analizy ruchu sieciowego.

3. Dostosuj kod źródłowy: Przeanalizuj kod źródłowy i dostosuj go do swoich potrzeb. Możesz zmienić wygląd strony, dodać fałszywe formularze logowania lub inne elementy, które pomogą w oszustwie użytkowników.

4. Skonfiguruj serwer: Skonfiguruj serwer, na którym będzie hostowana sklonowana strona. Możesz skorzystać z lokalnego serwera, takiego jak Apache, lub skorzystać z chmury, takiej jak AWS lub GCP.

5. Przetestuj sklonowaną stronę: Przetestuj sklonowaną stronę, aby upewnić się, że wygląda i działa tak, jak powinna. Sprawdź, czy fałszywe formularze logowania przechwytują dane użytkowników i czy przekierowują ich na prawdziwą stronę po zalogowaniu.

6. Przeprowadź atak phishingowy: Wykorzystaj sklonowaną stronę do przeprowadzenia ataku phishingowego. Możesz wysłać link do sklonowanej strony za pośrednictwem wiadomości e-mail, wiadomości SMS lub innych kanałów komunikacji, aby przyciągnąć uwagę potencjalnych ofiar.

7. Przechwyć dane: Po przeprowadzeniu ataku phishingowego, zbierz dane, które użytkownicy wprowadzili na sklonowanej stronie. Może to obejmować hasła, dane logowania, informacje osobiste itp.

8. Zabezpiecz się przed wykryciem: Aby uniknąć wykrycia, możesz zastosować różne techniki, takie jak ukrywanie adresu URL, wykorzystanie SSL lub przekierowanie użytkowników na prawdziwą stronę po wprowadzeniu danych.

Klonowanie strony internetowej jest potężnym narzędziem wykorzystywanym przez hakerów do przeprowadzania ataków phishingowych. Ważne jest, aby być świadomym takich zagrożeń i zachować ostrożność podczas korzystania z internetu.
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
