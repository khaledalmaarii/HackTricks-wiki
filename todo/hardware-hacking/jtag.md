# JTAG

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) albo **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>

## JTAGenum

[**JTAGenum** ](https://github.com/cyphunk/JTAGenum)to narzędzie, które można użyć z Raspberry PI lub Arduino do próby znalezienia pinów JTAG w nieznanym chipie.\
W **Arduino** podłącz **piny od 2 do 11 do 10 pinów potencjalnie należących do JTAG**. Wgraj program do Arduino, a następnie spróbuj siłowo przetestować wszystkie piny, aby sprawdzić, czy którykolwiek z nich należy do JTAG i który to pin.\
W **Raspberry PI** można użyć tylko **pinów od 1 do 6** (6 pinów, więc testowanie każdego potencjalnego pinu JTAG będzie wolniejsze).

### Arduino

W Arduino, po podłączeniu kabli (pinów 2 do 11 do pinów JTAG i GND Arduino do GND płyty głównej), **wgraj program JTAGenum do Arduino** i w Monitorze szeregowym wyślij **`h`** (polecenie pomocy), a powinieneś zobaczyć pomoc:

![](<../../.gitbook/assets/image (939).png>)

![](<../../.gitbook/assets/image (578).png>)

Skonfiguruj **"Brak zakończenia linii" i 115200baud**.\
Wyślij polecenie s, aby rozpocząć skanowanie:

![](<../../.gitbook/assets/image (774).png>)

Jeśli masz do czynienia z JTAG, znajdziesz jeden lub kilka **linii zaczynających się od ZNALEZIONO!**, wskazujących piny JTAG.
