<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>


# JTAGenum

[**JTAGenum** ](https://github.com/cyphunk/JTAGenum)to narzędzie, które można używać z Raspberry PI lub Arduino do próby znalezienia pinów JTAG z nieznanego układu.\
W **Arduino** podłącz piny od 2 do 11 do 10 pinów potencjalnie należących do JTAG. Wgraj program do Arduino, a następnie spróbuj bruteforce'ować wszystkie piny, aby znaleźć te należące do JTAG i które z nich to.\
W **Raspberry PI** można używać tylko pinów od 1 do 6 (6 pinów, więc testowanie każdego potencjalnego pinu JTAG będzie trwało dłużej).

## Arduino

W Arduino, po podłączeniu kabli (pin 2 do 11 do pinów JTAG, a GND Arduino do GND płytki bazowej), **załaduj program JTAGenum w Arduino** i w Monitorze szeregowym wyślij **`h`** (komenda dla pomocy), a powinieneś zobaczyć pomoc:

![](<../../.gitbook/assets/image (643).png>)

![](<../../.gitbook/assets/image (650).png>)

Skonfiguruj **"Brak zakończenia linii" i 115200baud**.\
Wyślij komendę s, aby rozpocząć skanowanie:

![](<../../.gitbook/assets/image (651) (1) (1) (1).png>)

Jeśli masz do czynienia z JTAG, znajdziesz jedną lub kilka **linii zaczynających się od FOUND!**, wskazujących piny JTAG.


<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>
