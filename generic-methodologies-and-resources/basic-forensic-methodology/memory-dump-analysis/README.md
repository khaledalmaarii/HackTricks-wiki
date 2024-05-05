# Analiza zrzutu pamięci

<details>

<summary><strong>Zacznij naukę hakowania AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Czy pracujesz w **firmie z branży cyberbezpieczeństwa**? Chcesz zobaczyć swoją **firmę reklamowaną w HackTricks**? lub chcesz uzyskać dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakowania, przesyłając PR-y do** [**repozytorium hacktricks**](https://github.com/carlospolop/hacktricks) **i** [**repozytorium hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) to najważniejsze wydarzenie z zakresu cyberbezpieczeństwa w **Hiszpanii** i jedno z najważniejszych w **Europie**. Mając **misję promowania wiedzy technicznej**, ten kongres stanowi gorące miejsce spotkań dla profesjonalistów technologii i cyberbezpieczeństwa we wszystkich dziedzinach.

{% embed url="https://www.rootedcon.com/" %}

## Rozpocznij

Zacznij **szukać** **złośliwego oprogramowania** w pliku pcap. Użyj **narzędzi** wymienionych w [**Analizie złośliwego oprogramowania**](../malware-analysis.md).

## [Volatility](volatility-cheatsheet.md)

**Volatility to główny otwarty framework do analizy zrzutów pamięci**. To narzędzie napisane w Pythonie analizuje zrzuty zewnętrznych źródeł lub maszyn wirtualnych VMware, identyfikując dane takie jak procesy i hasła na podstawie profilu systemu operacyjnego zrzutu. Jest rozszerzalny za pomocą wtyczek, co czyni go bardzo wszechstronnym narzędziem do śledztw sądowych.

[Znajdź tutaj ściągawkę](volatility-cheatsheet.md)

## Raport z awarii mini zrzutu pamięci

Gdy zrzut jest mały (tylko kilka KB, może kilka MB), prawdopodobnie jest to raport z awarii mini zrzutu pamięci, a nie zrzut pamięci.

![](<../../../.gitbook/assets/image (532).png>)

Jeśli masz zainstalowany Visual Studio, możesz otworzyć ten plik i uzyskać podstawowe informacje, takie jak nazwa procesu, architektura, informacje o wyjątku i moduły wykonywane:

![](<../../../.gitbook/assets/image (263).png>)

Możesz także załadować wyjątek i zobaczyć zdekompilowane instrukcje

![](<../../../.gitbook/assets/image (142).png>)

![](<../../../.gitbook/assets/image (610).png>)

W każdym razie Visual Studio nie jest najlepszym narzędziem do przeprowadzenia analizy głębokości zrzutu.

Powinieneś go **otworzyć** za pomocą **IDA** lub **Radare** w celu dokładnej **inspekcji**.

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) to najważniejsze wydarzenie z zakresu cyberbezpieczeństwa w **Hiszpanii** i jedno z najważniejszych w **Europie**. Mając **misję promowania wiedzy technicznej**, ten kongres stanowi gorące miejsce spotkań dla profesjonalistów technologii i cyberbezpieczeństwa we wszystkich dziedzinach.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>Zacznij naukę hakowania AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Czy pracujesz w **firmie z branży cyberbezpieczeństwa**? Chcesz zobaczyć swoją **firmę reklamowaną w HackTricks**? lub chcesz uzyskać dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakowania, przesyłając PR-y do** [**repozytorium hacktricks**](https://github.com/carlospolop/hacktricks) **i** [**repozytorium hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
