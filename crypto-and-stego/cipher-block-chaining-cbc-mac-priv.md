<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na GitHubie.

</details>


# CBC

Jeśli **ciasteczko** to **tylko** **nazwa użytkownika** (lub pierwsza część ciasteczka to nazwa użytkownika) i chcesz podszyć się pod nazwę użytkownika "**admin**". Wtedy możesz stworzyć nazwę użytkownika **"bdmin"** i **przeprowadzić atak brutalnej siły** na **pierwszy bajt** ciasteczka.

# CBC-MAC

**Kod uwierzytelniający wiadomości z łańcuchem bloków szyfrujących** (**CBC-MAC**) to metoda stosowana w kryptografii. Polega na szyfrowaniu wiadomości blok po bloku, gdzie szyfrowanie każdego bloku jest powiązane z poprzednim. Ten proces tworzy **łańcuch bloków**, zapewniając, że zmiana nawet jednego bitu oryginalnej wiadomości spowoduje nieprzewidywalną zmianę w ostatnim bloku zaszyfrowanych danych. Aby dokonać takiej zmiany lub jej odwrócenia, wymagany jest klucz szyfrowania, co zapewnia bezpieczeństwo.

Aby obliczyć CBC-MAC wiadomości m, szyfruje się m w trybie CBC z zerowym wektorem inicjalizacji i zachowuje ostatni blok. Poniższy rysunek przedstawia obliczenia CBC-MAC wiadomości składającej się z bloków![https://wikimedia.org/api/rest\_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5](https://wikimedia.org/api/rest\_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5) przy użyciu tajnego klucza k i szyfru blokowego E:

![https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC\_structure\_\(en\).svg/570px-CBC-MAC\_structure\_\(en\).svg.png](https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC\_structure\_\(en\).svg/570px-CBC-MAC\_structure\_\(en\).svg.png)

# Podatność

Z CBC-MAC zazwyczaj używany jest **wektor inicjalizacji 0**.\
To stanowi problem, ponieważ 2 znane wiadomości (`m1` i `m2`) niezależnie generują 2 podpisy (`s1` i `s2`). Więc:

* `E(m1 XOR 0) = s1`
* `E(m2 XOR 0) = s2`

Następnie wiadomość składająca się z m1 i m2 połączonych (m3) wygeneruje 2 podpisy (s31 i s32):

* `E(m1 XOR 0) = s31 = s1`
* `E(m2 XOR s1) = s32`

**Co można obliczyć bez znajomości klucza szyfrowania.**

Wyobraź sobie, że szyfrujesz nazwę **Administrator** w blokach **8 bajtów**:

* `Administ`
* `rator\00\00\00`

Możesz stworzyć nazwę użytkownika **Administ** (m1) i odzyskać podpis (s1).\
Następnie możesz stworzyć nazwę użytkownika, która jest wynikiem `rator\00\00\00 XOR s1`. To wygeneruje `E(m2 XOR s1 XOR 0)`, czyli s32.\
teraz możesz użyć s32 jako podpisu pełnej nazwy **Administrator**.

### Podsumowanie

1. Uzyskaj podpis nazwy użytkownika **Administ** (m1), który to s1
2. Uzyskaj podpis nazwy użytkownika **rator\x00\x00\x00 XOR s1 XOR 0**, czyli s32**.**
3. Ustaw ciasteczko na s32 i będzie to ważne ciasteczko dla użytkownika **Administrator**.

# Atak Kontrolujący IV

Jeśli możesz kontrolować używany IV, atak może być bardzo prosty.\
Jeśli ciasteczko to po prostu zaszyfrowana nazwa użytkownika, aby podszyć się pod użytkownika "**administrator**", możesz stworzyć użytkownika "**Administrator**" i uzyskać jego ciasteczko.\
Teraz, jeśli możesz kontrolować IV, możesz zmienić pierwszy bajt IV, aby **IV\[0] XOR "A" == IV'\[0] XOR "a"** i odtworzyć ciasteczko dla użytkownika **Administrator**. To ciasteczko będzie ważne do **podszycia się** pod użytkownika **administratora** z początkowym **IV**.

## Referencje

Więcej informacji na [https://en.wikipedia.org/wiki/CBC-MAC](https://en.wikipedia.org/wiki/CBC-MAC)


<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na GitHubie.

</details>
