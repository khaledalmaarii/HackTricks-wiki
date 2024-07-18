# Analiza zrzutów pamięci

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) to najważniejsze wydarzenie związane z cyberbezpieczeństwem w **Hiszpanii** i jedno z najważniejszych w **Europie**. Z **misją promowania wiedzy technicznej**, ten kongres jest gorącym punktem spotkań dla profesjonalistów z technologii i cyberbezpieczeństwa w każdej dziedzinie.

{% embed url="https://www.rootedcon.com/" %}

## Początek

Zacznij **szukać** **złośliwego oprogramowania** w pcap. Użyj **narzędzi** wymienionych w [**Analiza złośliwego oprogramowania**](../malware-analysis.md).

## [Volatility](volatility-cheatsheet.md)

**Volatility to główna otwarta platforma do analizy zrzutów pamięci**. To narzędzie Python analizuje zrzuty z zewnętrznych źródeł lub maszyn wirtualnych VMware, identyfikując dane takie jak procesy i hasła na podstawie profilu systemu operacyjnego zrzutu. Jest rozszerzalne za pomocą wtyczek, co czyni je bardzo wszechstronnym w dochodzeniach kryminalistycznych.

[**Znajdź tutaj arkusz skrótów**](volatility-cheatsheet.md)

## Raport o awarii mini zrzutu

Gdy zrzut jest mały (zaledwie kilka KB, może kilka MB), to prawdopodobnie jest to raport o awarii mini zrzutu, a nie zrzut pamięci.

![](<../../../.gitbook/assets/image (532).png>)

Jeśli masz zainstalowany Visual Studio, możesz otworzyć ten plik i powiązać podstawowe informacje, takie jak nazwa procesu, architektura, informacje o wyjątkach i moduły, które są wykonywane:

![](<../../../.gitbook/assets/image (263).png>)

Możesz również załadować wyjątek i zobaczyć zdekompilowane instrukcje

![](<../../../.gitbook/assets/image (142).png>)

![](<../../../.gitbook/assets/image (610).png>)

W każdym razie, Visual Studio nie jest najlepszym narzędziem do przeprowadzenia analizy głębokości zrzutu.

Powinieneś **otworzyć** go za pomocą **IDA** lub **Radare**, aby zbadać go w **głębi**.

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) to najważniejsze wydarzenie związane z cyberbezpieczeństwem w **Hiszpanii** i jedno z najważniejszych w **Europie**. Z **misją promowania wiedzy technicznej**, ten kongres jest gorącym punktem spotkań dla profesjonalistów z technologii i cyberbezpieczeństwa w każdej dziedzinie.

{% embed url="https://www.rootedcon.com/" %}

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}
