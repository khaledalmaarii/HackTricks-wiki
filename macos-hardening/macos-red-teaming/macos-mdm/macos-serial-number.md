# Numer seryjny macOS

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>


## Podstawowe informacje

Urządzenia Apple po 2010 roku mają numery seryjne składające się z **12 znaków alfanumerycznych**, gdzie każdy segment przekazuje określone informacje:

- **Pierwsze 3 znaki**: Wskazują **miejsce produkcji**.
- **Znaki 4 i 5**: Oznaczają **rok i tydzień produkcji**.
- **Znaki 6-8**: Służą jako **unikalny identyfikator** dla każdego urządzenia.
- **Ostatnie 4 znaki**: Określają **numer modelu**.

Na przykład, numer seryjny **C02L13ECF8J2** podąża za tą strukturą.

### **Miejsca produkcji (Pierwsze 3 znaki)**
Określone kody reprezentują konkretne fabryki:
- **FC, F, XA/XB/QP/G8**: Różne lokalizacje w USA.
- **RN**: Meksyk.
- **CK**: Cork, Irlandia.
- **VM**: Foxconn, Republika Czeska.
- **SG/E**: Singapur.
- **MB**: Malezja.
- **PT/CY**: Korea.
- **EE/QT/UV**: Tajwan.
- **FK/F1/F2, W8, DL/DM, DN, YM/7J, 1C/4H/WQ/F7**: Różne lokalizacje w Chinach.
- **C0, C3, C7**: Konkretne miasta w Chinach.
- **RM**: Odnowione urządzenia.

### **Rok produkcji (4. znak)**
Ten znak zmienia się od 'C' (reprezentujący pierwszą połowę 2010 roku) do 'Z' (druga połowa 2019 roku), gdzie różne litery oznaczają różne półroczne okresy.

### **Tydzień produkcji (5. znak)**
Cyfry 1-9 odpowiadają tygodniom 1-9. Litery C-Y (z wyłączeniem samogłosek i 'S') reprezentują tygodnie 10-27. Dla drugiej połowy roku do tej liczby dodawane jest 26.

### **Unikalny identyfikator (Znaki 6-8)**
Te trzy cyfry zapewniają, że każde urządzenie, nawet tego samego modelu i partii, ma odrębny numer seryjny.

### **Numer modelu (Ostatnie 4 znaki)**
Te cyfry identyfikują konkretny model urządzenia.

### Referencja

* [https://beetstech.com/blog/decode-meaning-behind-apple-serial-number](https://beetstech.com/blog/decode-meaning-behind-apple-serial-number)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
