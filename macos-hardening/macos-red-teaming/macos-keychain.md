# macOS Keychain

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Główne Keychainy

* **Keychain użytkownika** (`~/Library/Keychains/login.keycahin-db`), który służy do przechowywania **danych uwierzytelniających specyficznych dla użytkownika**, takich jak hasła do aplikacji, hasła internetowe, certyfikaty generowane przez użytkownika, hasła sieciowe i klucze publiczne/prywatne generowane przez użytkownika.
* **Keychain systemowy** (`/Library/Keychains/System.keychain`), który przechowuje **dane uwierzytelniające na poziomie systemu**, takie jak hasła WiFi, korzeniowe certyfikaty systemowe, prywatne klucze systemowe i hasła aplikacji systemowych.

### Dostęp do Keychaina z hasłem

Te pliki, chociaż nie mają wbudowanej ochrony i mogą być **pobrane**, są szyfrowane i wymagają **odszyfrowania za pomocą hasła tekstowego użytkownika**. Narzędzie takie jak [**Chainbreaker**](https://github.com/n0fate/chainbreaker) może być użyte do odszyfrowania.

## Ochrona wpisów w Keychainie

### ACLs

Każdy wpis w keychainie jest regulowany przez **Listy Kontroli Dostępu (ACLs)**, które określają, kto może wykonywać różne czynności na wpisie keychaina, w tym:

* **ACLAuhtorizationExportClear**: Pozwala posiadaczowi uzyskać tekst jawny tajemnicy.
* **ACLAuhtorizationExportWrapped**: Pozwala posiadaczowi uzyskać tekst jawny zaszyfrowany innym podanym hasłem.
* **ACLAuhtorizationAny**: Pozwala posiadaczowi wykonywać dowolne czynności.

ACLs są dodatkowo uzupełniane przez **listę zaufanych aplikacji**, które mogą wykonywać te czynności bez pytania. Mogą to być:

* &#x20;**N`il`** (nie wymagane autoryzacji, **każdy jest zaufany**)
* Pusta **lista** (nikt nie jest zaufany)
* **Lista** konkretnych **aplikacji**.

Wpis może również zawierać klucz **`ACLAuthorizationPartitionID`,** który służy do identyfikacji **teamid, apple** i **cdhash.**

* Jeśli jest określone **teamid**, to aby **uzyskać dostęp** do wartości wpisu **bez** pytania, używana aplikacja musi mieć **ten sam teamid**.
* Jeśli jest określone **apple**, to aplikacja musi być **podpisana** przez **Apple**.
* Jeśli jest wskazane **cdhash**, to aplikacja musi mieć określony **cdhash**.

### Tworzenie wpisu w Keychainie

Podczas tworzenia **nowego** **wpisu** za pomocą **`Keychain Access.app`**, obowiązują następujące zasady:

* Wszystkie aplikacje mogą szyfrować.
* **Żadna aplikacja** nie może eksportować/odszyfrowywać (bez pytania użytkownika).
* Wszystkie aplikacje mogą zobaczyć sprawdzanie integralności.
* Żadna aplikacja nie może zmieniać ACLs.
* Identyfikator partycji jest ustawiony na **`apple`**.

Podczas gdy **aplikacja tworzy wpis w keychainie**, zasady są nieco inne:

* Wszystkie aplikacje mogą szyfrować.
* Tylko **tworząca aplikacja** (lub inne aplikacje dodane explicite) mogą eksportować/odszyfrowywać (bez pytania użytkownika).
* Wszystkie aplikacje mogą zobaczyć sprawdzanie integralności.
* Żadna aplikacja nie może zmieniać ACLs.
* Identyfikator partycji jest ustawiony na **`teamid:[teamID tutaj]`**.

## Dostęp do Keychaina

### `security`
```bash
# Dump all metadata and decrypted secrets (a lot of pop-ups)
security dump-keychain -a -d

# Find generic password for the "Slack" account and print the secrets
security find-generic-password -a "Slack" -g

# Change the specified entrys PartitionID entry
security set-generic-password-parition-list -s "test service" -a "test acount" -S
```
### Interfejsy programowania aplikacji (API)

{% hint style="success" %}
**Wyliczanie i wydobywanie** sekretów z **keychaina**, które **nie generują monitu**, można wykonać za pomocą narzędzia [**LockSmith**](https://github.com/its-a-feature/LockSmith)
{% endhint %}

Wylistuj i uzyskaj **informacje** o każdym wpisie w keychainie:

* API **`SecItemCopyMatching`** udostępnia informacje o każdym wpisie, a przy jego użyciu można ustawić kilka atrybutów:
* **`kSecReturnData`**: Jeśli jest ustawione na true, spróbuje zdekodować dane (ustaw na false, aby uniknąć ewentualnych monitów)
* **`kSecReturnRef`**: Uzyskaj również odniesienie do elementu keychaina (ustaw na true, jeśli później zauważysz, że możesz zdekodować bez monitu)
* **`kSecReturnAttributes`**: Uzyskaj metadane dotyczące wpisów
* **`kSecMatchLimit`**: Ilość wyników do zwrócenia
* **`kSecClass`**: Rodzaj wpisu w keychainie

Uzyskaj **ACL** dla każdego wpisu:

* Za pomocą API **`SecAccessCopyACLList`** można uzyskać **ACL dla elementu keychaina**, a zwróci on listę ACL (takich jak `ACLAuhtorizationExportClear` i inne wcześniej wymienione), gdzie każda lista zawiera:
* Opis
* **Lista zaufanych aplikacji**. Może to być:
* Aplikacja: /Applications/Slack.app
* Plik binarny: /usr/libexec/airportd
* Grupa: group://AirPort

Eksportuj dane:

* API **`SecKeychainItemCopyContent`** pobiera tekst jawny
* API **`SecItemExport`** eksportuje klucze i certyfikaty, ale może być konieczne ustawienie hasła w celu zaszyfrowania eksportowanych danych

A oto **wymagania**, aby móc **eksportować sekret bez monitu**:

* Jeśli jest **1 lub więcej zaufanych** aplikacji na liście:
* Wymagane są odpowiednie **autoryzacje** (**`Nil`**, lub należy być **częścią** listy dozwolonych aplikacji w autoryzacji dostępu do informacji o sekrecie)
* Wymagane jest dopasowanie sygnatury kodu do **PartitionID**
* Wymagane jest dopasowanie sygnatury kodu do jednej **zaufanej aplikacji** (lub należy być członkiem odpowiedniej grupy KeychainAccessGroup)
* Jeśli **wszystkie aplikacje są zaufane**:
* Wymagane są odpowiednie **autoryzacje**
* Wymagane jest dopasowanie sygnatury kodu do **PartitionID**
* Jeśli brak **PartitionID**, to nie jest to wymagane

{% hint style="danger" %}
Dlatego, jeśli jest **wymieniona 1 aplikacja**, musisz **wstrzyknąć kod w tę aplikację**.

Jeśli w **PartitionID** jest wskazane **apple**, można uzyskać do niego dostęp za pomocą **`osascript`**, więc wszystko, co ufa wszystkim aplikacjom z apple w PartitionID. Można również użyć **`Pythona`** do tego.
{% endhint %}

### Dwa dodatkowe atrybuty

* **Invisible**: Jest to flaga typu boolean, która służy do **ukrywania** wpisu w aplikacji **UI** Keychain
* **General**: Służy do przechowywania **metadanych** (więc NIE JEST ZASZYFROWANE)
* Microsoft przechowywał w postaci zwykłego tekstu wszystkie tokeny odświeżania do dostępu do wrażliwych punktów końcowych.

## Odwołania

* [**#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas**](https://www.youtube.com/watch?v=jKE1ZW33JpY)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) **i** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github repos.**

</details>
