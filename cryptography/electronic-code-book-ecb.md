<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>


# ECB

(ECB) Electronic Code Book - symetryczny schemat szyfrowania, który **zamienia każdy blok tekstu jawnego** na **blok tekstu zaszyfrowanego**. Jest to **najprostszy** schemat szyfrowania. Główna idea polega na **podziale** tekstu jawnego na **bloki o rozmiarze N bitów** (zależy od rozmiaru bloku danych wejściowych, algorytmu szyfrowania) a następnie zaszyfrowaniu (odszyfrowaniu) każdego bloku tekstu jawnego przy użyciu jedynego klucza.

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

Użycie ECB ma wiele implikacji dla bezpieczeństwa:

* **Bloków z zaszyfrowanej wiadomości można usunąć**
* **Bloków z zaszyfrowanej wiadomości można przemieszczać**

# Wykrywanie podatności

Wyobraź sobie, że logujesz się do aplikacji kilka razy i **zawsze otrzymujesz ten sam ciasteczko**. Wynika to z faktu, że ciasteczko aplikacji ma postać **`<nazwa użytkownika>|<hasło>`**.\
Następnie tworzysz dwóch nowych użytkowników, oboje z **tym samym długim hasłem** i **prawie** **taką samą** **nazwą użytkownika**.\
Odkrywasz, że **bloki o rozmiarze 8B**, w których **informacje o obu użytkownikach** są takie same, są **identyczne**. Wyobrażasz sobie, że może to być spowodowane użyciem ECB.

Podobnie jak w poniższym przykładzie. Zauważ, jak te **2 zdekodowane ciasteczka** mają kilka razy blok **`\x23U\xE45K\xCB\x21\xC8`**
```
\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9

\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9
```
To wynika z tego, że **nazwa użytkownika i hasło tych ciasteczek zawierały kilkakrotnie literę "a"** (na przykład). **Bloki**, które są **różne**, to bloki, które zawierały **przynajmniej 1 inny znak** (może to być znak "|", lub jakaś niezbędna różnica w nazwie użytkownika).

Teraz atakujący musi tylko odkryć, czy format to `<nazwa użytkownika><znacznik><hasło>` czy `<hasło><znacznik><nazwa użytkownika>`. Aby to zrobić, może **generować kilka nazw użytkowników** o **podobnych i długich nazwach użytkowników i hasłach**, aż znajdzie format i długość znacznika:

| Długość nazwy użytkownika: | Długość hasła: | Długość nazwa użytkownika+hasło: | Długość ciasteczka (po dekodowaniu): |
| ------------------------- | -------------- | -------------------------------- | ----------------------------------- |
| 2                         | 2              | 4                                | 8                                   |
| 3                         | 3              | 6                                | 8                                   |
| 3                         | 4              | 7                                | 8                                   |
| 4                         | 4              | 8                                | 16                                  |
| 7                         | 7              | 14                               | 16                                  |

# Wykorzystanie podatności

## Usuwanie całych bloków

Znając format ciasteczka (`<nazwa użytkownika>|<hasło>`), aby podszyć się pod nazwę użytkownika `admin`, utwórz nowego użytkownika o nazwie `aaaaaaaaadmin`, pobierz ciasteczko i zdekoduj je:
```
\x23U\xE45K\xCB\x21\xC8\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
Możemy zobaczyć wzór `\x23U\xE45K\xCB\x21\xC8` utworzony wcześniej z nazwą użytkownika zawierającą tylko `a`.\
Następnie możesz usunąć pierwszy blok 8B i otrzymasz poprawne ciasteczko dla nazwy użytkownika `admin`:
```
\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
## Przesuwanie bloków

W wielu bazach danych jest to samo, czy szukamy `WHERE username='admin';` czy `WHERE username='admin    ';` _(Zauważ dodatkowe spacje)_

Więc inny sposób na podszywanie się pod użytkownika `admin` to:

* Wygeneruj nazwę użytkownika, która spełnia warunek: `len(<username>) + len(<delimiter) % len(block)`. Przy rozmiarze bloku `8B` możesz wygenerować nazwę użytkownika o nazwie: `username       `, a z separatorem `|` fragment `<username><delimiter>` wygeneruje 2 bloki o rozmiarze 8B.
* Następnie wygeneruj hasło, które wypełni dokładną liczbę bloków zawierających nazwę użytkownika, którą chcemy podszyć się oraz spacje, na przykład: `admin   `

Cookie tego użytkownika będzie składać się z 3 bloków: pierwsze 2 bloki to bloki z nazwą użytkownika + separator, a trzeci blok to hasło (które podszywa się pod nazwę użytkownika): `username       |admin   `

**Następnie wystarczy zamienić pierwszy blok z ostatnim i będziemy podszywali się pod użytkownika `admin`: `admin          |username`**

## Odnośniki

* [http://cryptowiki.net/index.php?title=Electronic_Code_Book\_(ECB)](http://cryptowiki.net/index.php?title=Electronic_Code_Book_\(ECB\))


<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć **reklamę swojej firmy w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) **i** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **na GitHubie.**

</details>
