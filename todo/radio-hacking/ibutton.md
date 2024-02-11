# iButton

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Wprowadzenie

iButton to ogólna nazwa dla elektronicznego klucza identyfikacyjnego zapakowanego w **metalowy pojemnik w kształcie monety**. Jest również nazywany pamięcią dotykową Dallas lub pamięcią kontaktową. Mimo że często błędnie nazywany jest "magnetycznym" kluczem, nie zawiera **niczego magnetycznego**. W rzeczywistości wewnątrz niego ukryty jest pełnoprawny **mikroczip** działający na cyfrowym protokole.

<figure><img src="../../.gitbook/assets/image (19).png" alt=""><figcaption></figcaption></figure>

### Czym jest iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Zazwyczaj iButton oznacza fizyczną formę klucza i czytnika - okrągłą monetę z dwoma kontaktami. Dla otaczającej go ramki istnieje wiele wariantów, od najpopularniejszego plastikowego uchwytu z otworem po pierścienie, wisiorki, itp.

<figure><img src="../../.gitbook/assets/image (23) (2).png" alt=""><figcaption></figcaption></figure>

Gdy klucz dotyka czytnika, **kontakty się stykają** i klucz jest zasilany, aby **przesłać** swoje ID. Czasami klucz **nie jest odczytywany** natychmiast, ponieważ **kontakt PSD interkomu jest większy**, niż powinien być. W takim przypadku trzeba nacisnąć klucz na jedną ze ścian czytnika.

<figure><img src="../../.gitbook/assets/image (21) (2).png" alt=""><figcaption></figcaption></figure>

### **Protokół 1-Wire** <a href="#1-wire-protocol" id="1-wire-protocol"></a>

Klucze Dallas wymieniają dane za pomocą protokołu 1-Wire. Posiadają tylko jeden kontakt do transferu danych (!!) w obu kierunkach, od mastera do slave'a i odwrotnie. Protokół 1-Wire działa według modelu Master-Slave. W tej topologii Master zawsze inicjuje komunikację, a Slave podąża za jego instrukcjami.

Gdy klucz (Slave) kontaktuje się z interkomem (Masterem), układ wewnątrz klucza zostaje włączony, zasilany przez interkom, i klucz zostaje zainicjalizowany. Następnie interkom żąda ID klucza. W kolejnym kroku przyjrzymy się temu procesowi bardziej szczegółowo.

Flipper może działać zarówno w trybie Master, jak i Slave. W trybie odczytu klucza Flipper działa jako czytnik, czyli działa jako Master. W trybie emulacji klucza, Flipper udaje klucz, działa jako Slave.

### Klucze Dallas, Cyfral i Metakom

Aby dowiedzieć się, jak działają te klucze, sprawdź stronę [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

### Ataki

iButton można zaatakować za pomocą Flipper Zero:

{% content-ref url="flipper-zero/fz-ibutton.md" %}
[fz-ibutton.md](flipper-zero/fz-ibutton.md)
{% endcontent-ref %}

## Odnośniki

* [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
