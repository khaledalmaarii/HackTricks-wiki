# Oracle z dopełnieniem

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>

## CBC - Szyfrowanie blokowe z łańcuchem

W trybie CBC **poprzedni zaszyfrowany blok jest używany jako IV** do operacji XOR z następnym blokiem:

![https://defuse.ca/images/cbc\_encryption.png](https://defuse.ca/images/cbc\_encryption.png)

Aby odszyfrować CBC, wykonuje się **odwrotne operacje**:

![https://defuse.ca/images/cbc\_decryption.png](https://defuse.ca/images/cbc\_decryption.png)

Zauważ, że potrzebne są **klucz szyfrowania** i **IV**.

## Dopełnienie wiadomości

Ponieważ szyfrowanie jest wykonywane w **blokach o stałym rozmiarze**, zazwyczaj konieczne jest **dopełnienie** w **ostatnim bloku**, aby uzupełnić jego długość.\
Zazwyczaj używany jest **PKCS7**, który generuje dopełnienie **powtarzając** **ilość** **bajtów** **potrzebną** do **uzupełnienia** bloku. Na przykład, jeśli w ostatnim bloku brakuje 3 bajtów, dopełnienie będzie `\x03\x03\x03`.

Przyjrzyjmy się więcej przykładom z **2 blokami o długości 8 bajtów**:

| bajt #0 | bajt #1 | bajt #2 | bajt #3 | bajt #4 | bajt #5 | bajt #6 | bajt #7 | bajt #0  | bajt #1  | bajt #2  | bajt #3  | bajt #4  | bajt #5  | bajt #6  | bajt #7  |
| ------- | ------- | ------- | ------- | ------- | ------- | ------- | ------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | 6        | **0x02** | **0x02** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | **0x03** | **0x03** | **0x03** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | **0x05** | **0x05** | **0x05** | **0x05** | **0x05** |
| P       | A       | S       | S       | W       | O       | R       | D       | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** |

Zauważ, jak w ostatnim przykładzie **ostatni blok był pełny, więc wygenerowano kolejny tylko z dopełnieniem**.

## Oracle z dopełnieniem

Gdy aplikacja deszyfruje zaszyfrowane dane, najpierw odszyfrowuje dane; następnie usuwa dopełnienie. Podczas usuwania dopełnienia, jeśli **nieprawidłowe dopełnienie wywołuje wykrywalne zachowanie**, mamy **lukę w oracle z dopełnieniem**. Wykrywalne zachowanie może być **błędem**, **brakiem wyników** lub **wolniejszą odpowiedzią**.

Jeśli wykryjesz to zachowanie, możesz **odszyfrować zaszyfrowane dane** i nawet **zaszyfrować dowolny tekst jawnie**.

### Jak wykorzystać

Możesz użyć [https://github.com/AonCyberLabs/PadBuster](https://github.com/AonCyberLabs/PadBuster), aby wykorzystać ten rodzaj podatności lub po prostu zrobić
```
sudo apt-get install padbuster
```
Aby sprawdzić, czy ciasteczko witryny jest podatne, możesz spróbować:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
**Kodowanie 0** oznacza, że używane jest **base64** (ale inne są dostępne, sprawdź menu pomocy).

Możesz również **wykorzystać tę podatność do szyfrowania nowych danych. Na przykład, wyobraź sobie, że zawartość ciasteczka to "**_**user=MyUsername**_**", wtedy możesz zmienić ją na "\_user=administrator\_" i eskalować uprawnienia wewnątrz aplikacji. Możesz to również zrobić, używając `paduster` i określając parametr -plaintext:**
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA==" -plaintext "user=administrator"
```
Jeśli witryna jest podatna, `padbuster` automatycznie spróbuje znaleźć moment wystąpienia błędu w dopełnieniu, ale możesz także wskazać komunikat o błędzie, używając parametru **-error**.
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "" 8 -encoding 0 -cookies "hcon=RVJDQrwUdTRWJUVUeBKkEA==" -error "Invalid padding"
```
### Teoria

W **skrócie**, możesz zacząć deszyfrować zaszyfrowane dane przez zgadywanie poprawnych wartości, które mogą być użyte do stworzenia wszystkich **różnych dopełnień**. Następnie atak padding oracle zacznie deszyfrować bajty od końca do początku, zgadując, jaka będzie poprawna wartość, która **tworzy dopełnienie 1, 2, 3, itd**.

![](<../.gitbook/assets/image (561).png>)

Wyobraź sobie, że masz zaszyfrowany tekst zajmujący **2 bloki** utworzone przez bajty od **E0 do E15**.\
Aby **odszyfrować** **ostatni** **blok** (**E8** do **E15**), cały blok przechodzi przez "deszyfrowanie bloku szyfrującego" generując **bajty pośrednie I0 do I15**.\
W końcu, każdy bajt pośredni jest **XORowany** z poprzednimi zaszyfrowanymi bajtami (E0 do E7). Więc:

* `C15 = D(E15) ^ E7 = I15 ^ E7`
* `C14 = I14 ^ E6`
* `C13 = I13 ^ E5`
* `C12 = I12 ^ E4`
* ...

Teraz jest możliwe **zmodyfikowanie `E7` aż do momentu, gdy `C15` będzie `0x01`**, co również będzie poprawnym dopełnieniem. Więc, w tym przypadku: `\x01 = I15 ^ E'7`

Znalezienie E'7 pozwala **obliczyć I15**: `I15 = 0x01 ^ E'7`

Co pozwala nam **obliczyć C15**: `C15 = E7 ^ I15 = E7 ^ \x01 ^ E'7`

Znając **C15**, teraz jest możliwe **obliczenie C14**, ale tym razem metodą brute-force dla dopełnienia `\x02\x02`.

Ten BF jest równie skomplikowany jak poprzedni, ponieważ możliwe jest obliczenie `E''15`, którego wartość to 0x02: `E''7 = \x02 ^ I15`, więc wystarczy znaleźć **`E'14`**, który generuje **`C14` równy `0x02`**.\
Następnie wykonaj te same kroki, aby odszyfrować C14: **`C14 = E6 ^ I14 = E6 ^ \x02 ^ E''6`**

**Podążaj tą ścieżką, aż odszyfrujesz cały zaszyfrowany tekst.**

### Wykrywanie podatności

Zarejestruj konto i zaloguj się na to konto.\
Jeśli **logujesz się wiele razy** i zawsze otrzymujesz **ten sam ciasteczko**, prawdopodobnie jest **coś nie tak** z aplikacją. Ciasteczko wysłane z powrotem powinno być unikalne za każdym razem, gdy się logujesz. Jeśli ciasteczko jest **zawsze** **takie samo**, prawdopodobnie zawsze będzie ono ważne i **nie będzie możliwe jego unieważnienie**.

Teraz, jeśli spróbujesz **zmodyfikować** ciasteczko, zobaczysz, że otrzymujesz **błąd** od aplikacji.\
Ale jeśli użyjesz BF do dopełnienia (korzystając na przykład z padbuster), uda ci się uzyskać inne ciasteczko ważne dla innego użytkownika. Ten scenariusz jest bardzo prawdopodobnie podatny na padbuster.

### Referencje

* [https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation](https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
