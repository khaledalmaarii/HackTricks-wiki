# Analiza dumpu pamięci

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć swoją **firmę reklamowaną w HackTricks**? A może chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do repozytorium [hacktricks](https://github.com/carlospolop/hacktricks) i [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) to najważniejsze wydarzenie związane z cyberbezpieczeństwem w **Hiszpanii** i jedno z najważniejszych w **Europie**. Mając na celu promowanie wiedzy technicznej, ten kongres jest gorącym punktem spotkań dla profesjonalistów technologii i cyberbezpieczeństwa we wszystkich dziedzinach.

{% embed url="https://www.rootedcon.com/" %}

## Rozpoczęcie

Rozpocznij **poszukiwanie** złośliwego oprogramowania w pliku pcap. Użyj **narzędzi** wymienionych w [**Analiza złośliwego oprogramowania**](../malware-analysis.md).

## [Volatility](../../../generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md)

**Volatility to główny otwarty framework do analizy dumpów pamięci**. Narzędzie to napisane w języku Python analizuje dump z zewnętrznych źródeł lub maszyn wirtualnych VMware, identyfikując dane takie jak procesy i hasła na podstawie profilu systemu operacyjnego w dumpie. Dzięki możliwości rozszerzania za pomocą wtyczek, jest niezwykle wszechstronne w śledzeniu śladów w śledztwach kryminalistycznych.

**[Tutaj znajdziesz ściągawkę](../../../generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md)**

## Raport z mini dumpu

Jeśli dump jest mały (tylko kilka kilobajtów, może kilka megabajtów), to prawdopodobnie jest to raport z mini dumpu, a nie dump pamięci.

![](<../../../.gitbook/assets/image (216).png>)

Jeśli masz zainstalowany Visual Studio, możesz otworzyć ten plik i uzyskać podstawowe informacje, takie jak nazwa procesu, architektura, informacje o wyjątku i wykonywane moduły:

![](<../../../.gitbook/assets/image (217).png>)

Możesz również załadować wyjątek i zobaczyć zdekompilowane instrukcje

![](<../../../.gitbook/assets/image (219).png>)

![](<../../../.gitbook/assets/image (218) (1).png>)

W każdym razie, Visual Studio nie jest najlepszym narzędziem do przeprowadzania analizy głębokości dumpu.

Powinieneś go **otworzyć** za pomocą **IDA** lub **Radare**, aby dokładnie go zbadać.

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) to najważniejsze wydarzenie związane z cyberbezpieczeństwem w **Hiszpanii** i jedno z najważniejszych w **Europie**. Mając na celu promowanie wiedzy technicznej, ten kongres jest gorącym punktem spotkań dla profesjonalistów technologii i cyberbezpieczeństwa we wszystkich dziedzinach.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć swoją **firmę reklamowaną w HackTricks**? A może chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do repozytorium [hacktricks](https://github.com/carlospolop/hacktricks) i [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
