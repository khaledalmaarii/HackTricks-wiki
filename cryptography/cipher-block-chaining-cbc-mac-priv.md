<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>


# CBC

Jeśli **ciasteczko** to **tylko** **nazwa użytkownika** (lub pierwsza część ciasteczka to nazwa użytkownika) i chcesz podszyć się pod nazwę użytkownika "**admin**". W takim przypadku możesz utworzyć nazwę użytkownika **"bdmin"** i **przeprowadzić atak brutalnej siły** na **pierwszy bajt** ciasteczka.

# CBC-MAC

**Cipher block chaining message authentication code** (**CBC-MAC**) to metoda używana w kryptografii. Polega na szyfrowaniu wiadomości blok po bloku, gdzie szyfrowanie każdego bloku jest powiązane z poprzednim. Ten proces tworzy **łańcuch bloków**, zapewniając, że zmiana nawet jednego bitu oryginalnej wiadomości spowoduje nieprzewidywalną zmianę ostatniego bloku zaszyfrowanych danych. Aby dokonać takiej zmiany lub jej odwrócenia, wymagany jest klucz szyfrowania, co zapewnia bezpieczeństwo.

Aby obliczyć CBC-MAC wiadomości m, szyfruje się m w trybie CBC z wektorem inicjalizacji zerowego i zachowuje ostatni blok. Poniższy schemat przedstawia obliczanie CBC-MAC wiadomości składającej się z bloków![https://wikimedia.org/api/rest\_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5](https://wikimedia.org/api/rest\_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5) przy użyciu tajnego klucza k i szyfru blokowego E:

![https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC\_structure\_\(en\).svg/570px-CBC-MAC\_structure\_\(en\).svg.png](https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC\_structure\_\(en\).svg/570px-CBC-MAC\_structure\_\(en\).svg.png)

# Podatność

W przypadku CBC-MAC zazwyczaj używany jest IV o wartości 0.\
Jest to problem, ponieważ 2 znane wiadomości (`m1` i `m2`) niezależnie generują 2 podpisy (`s1` i `s2`). Więc:

* `E(m1 XOR 0) = s1`
* `E(m2 XOR 0) = s2`

Następnie wiadomość składająca się z m1 i m2 połączonych (m3) wygeneruje 2 podpisy (s31 i s32):

* `E(m1 XOR 0) = s31 = s1`
* `E(m2 XOR s1) = s32`

**Można to obliczyć bez znajomości klucza szyfrowania.**

Wyobraź sobie, że szyfrujesz nazwę **Administrator** w blokach o długości **8 bajtów**:

* `Administ`
* `rator\00\00\00`

Możesz utworzyć nazwę użytkownika o nazwie **Administ** (m1) i pobrać podpis (s1).\
Następnie możesz utworzyć nazwę użytkownika o nazwie wynikowej `rator\00\00\00 XOR s1`. Spowoduje to wygenerowanie `E(m2 XOR s1 XOR 0)`, które jest s32.\
Teraz możesz użyć s32 jako podpisu pełnej nazwy **Administrator**.

### Podsumowanie

1. Pobierz podpis nazwy użytkownika **Administ** (m1), który wynosi s1.
2. Pobierz podpis nazwy użytkownika **rator\x00\x00\x00 XOR s1 XOR 0**, który wynosi s32.
3. Ustaw ciasteczko na s32 i będzie to ważne ciasteczko dla użytkownika **Administrator**.

# Atak kontrolujący IV

Jeśli możesz kontrolować używany IV, atak może być bardzo prosty.\
Jeśli ciasteczka to tylko zaszyfrowana nazwa użytkownika, aby podszyć się pod użytkownika "**administrator**", możesz utworzyć użytkownika "**Administrator**" i otrzymasz jego ciasteczko.\
Teraz, jeśli możesz kontrolować IV, możesz zmienić pierwszy bajt IV tak, aby **IV\[0] XOR "A" == IV'\[0] XOR "a"** i ponownie wygenerować ciasteczko dla użytkownika **Administrator**. To ciasteczko będzie ważne do **podszywania się** pod użytkownika **administrator** z początkowym **IV**.

## Odwołania

Więcej informacji na stronie [https://en.wikipedia.org/wiki/CBC-MAC](https://en.wikipedia.org/wiki/CBC-MAC)


<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>
