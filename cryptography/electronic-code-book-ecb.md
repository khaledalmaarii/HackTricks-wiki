{% hint style="success" %}
Ucz się i praktykuj Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Szkolenie AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i praktykuj Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Szkolenie GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) oraz [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na githubie.

</details>
{% endhint %}


# ECB

(ECB) Electronic Code Book - symetryczny schemat szyfrowania, który **zamienia każdy blok tekstu jawnego** na **blok tekstu zaszyfrowanego**. Jest to **najprostszy** schemat szyfrowania. Główna idea polega na **podziale** tekstu jawnego na **bloki o długości N bitów** (zależy od rozmiaru bloku danych wejściowych, algorytmu szyfrowania) a następnie zaszyfrowaniu (odszyfrowaniu) każdego bloku tekstu jawnego przy użyciu jedynie klucza.

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

Korzystanie z ECB ma wiele implikacji dla bezpieczeństwa:

* **Bloki z zaszyfrowanej wiadomości mogą być usunięte**
* **Bloki z zaszyfrowanej wiadomości mogą być przemieszczane**

# Wykrywanie podatności

Wyobraź sobie, że logujesz się do aplikacji kilka razy i **zawsze otrzymujesz ten sam ciasteczko**. Dzieje się tak, ponieważ ciasteczko aplikacji to **`<nazwa użytkownika>|<hasło>`**.\
Następnie tworzysz dwóch nowych użytkowników, obaj z **takim samym długim hasłem** i **prawie** **taką samą** **nazwą użytkownika**.\
Odkrywasz, że **bloki o długości 8B**, w których **informacje obu użytkowników** są takie same, są **równe**. Wtedy wyobrażasz sobie, że może to być spowodowane użyciem **ECB**.

Tak jak w poniższym przykładzie. Zauważ, jak te **2 zdekodowane ciasteczka** mają kilka razy blok **`\x23U\xE45K\xCB\x21\xC8`**
```
\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9

\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9
```
To wynika z tego, że **nazwa użytkownika i hasło tych ciasteczek zawierały kilkakrotnie literę "a"** (na przykład). **Bloki**, które są **różne**, to bloki, które zawierały **co najmniej 1 inny znak** (być może separator "|" lub jakaś konieczna różnica w nazwie użytkownika).

Teraz atakujący musi tylko odkryć, czy format to `<nazwa użytkownika><separator><hasło>` czy `<hasło><separator><nazwa użytkownika>`. Aby to zrobić, może po prostu **generować kilka nazw użytkowników** o **podobnych i długich nazwach użytkowników i hasłach, aż znajdzie format i długość separatora:**

| Długość nazwy użytkownika: | Długość hasła: | Długość nazwa użytkownika+hasło: | Długość ciasteczka (po dekodowaniu): |
| -------------------------- | -------------- | ------------------------------- | ----------------------------------- |
| 2                          | 2              | 4                               | 8                                   |
| 3                          | 3              | 6                               | 8                                   |
| 3                          | 4              | 7                               | 8                                   |
| 4                          | 4              | 8                               | 16                                  |
| 7                          | 7              | 14                              | 16                                  |

# Wykorzystanie podatności

## Usuwanie całych bloków

Znając format ciasteczka (`<nazwa użytkownika>|<hasło>`), aby podszyć się pod nazwę użytkownika `admin`, stwórz nowego użytkownika o nazwie `aaaaaaaaadmin` i pobierz ciasteczko, a następnie zdekoduj je:
```
\x23U\xE45K\xCB\x21\xC8\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
Możemy zobaczyć wzorzec `\x23U\xE45K\xCB\x21\xC8` utworzony wcześniej z nazwą użytkownika zawierającą tylko `a`. Następnie możesz usunąć pierwszy blok 8B i otrzymasz poprawne ciasteczko dla nazwy użytkownika `admin`:
```
\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
## Przenoszenie bloków

W wielu bazach danych to samo jest wyszukiwanie `WHERE username='admin';` lub `WHERE username='admin    ';` _(Zauważ dodatkowe spacje)_

Więc inny sposób na podszywanie się pod użytkownika `admin` byłby:

* Wygenerowanie nazwy użytkownika takiej, że: `len(<username>) + len(<delimiter) % len(block)`. Przy rozmiarze bloku `8B` można wygenerować nazwę użytkownika: `username       `, z separatorem `|` fragment `<username><delimiter>` wygeneruje 2 bloki o rozmiarze 8B.
* Następnie wygenerowanie hasła, które wypełni dokładną liczbę bloków zawierających nazwę użytkownika, którą chcemy podszyć się i spacje, na przykład: `admin   `

Ciasteczko tego użytkownika będzie składać się z 3 bloków: pierwsze 2 bloki to bloki nazwy użytkownika + separatora, a trzeci to blok hasła (który podszywa się pod nazwę użytkownika): `username       |admin   `

**Następnie wystarczy zastąpić pierwszy blok ostatnim razem i będziemy podszywać się pod użytkownika `admin`: `admin          |username`**

## Referencje

* [http://cryptowiki.net/index.php?title=Electronic_Code_Book\_(ECB)](http://cryptowiki.net/index.php?title=Electronic_Code_Book_\(ECB\))
