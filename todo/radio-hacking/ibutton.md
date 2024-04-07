# iButton

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na GitHubie.

</details>

## Wprowadzenie

iButton to ogólna nazwa dla elektronicznego klucza identyfikacyjnego zapakowanego w **metalowy pojemnik w kształcie monety**. Jest również nazywany **pamięcią dotykową Dallas** lub pamięcią kontaktową. Pomimo częstego błędnego określania go jako klucz „magnetyczny”, w rzeczywistości nie zawiera **nic magnetycznego**. W rzeczywistości wewnątrz znajduje się ukryty pełnoprawny **mikroczip** działający w oparciu o protokół cyfrowy.

<figure><img src="../../.gitbook/assets/image (912).png" alt=""><figcaption></figcaption></figure>

### Co to jest iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Zazwyczaj iButton oznacza fizyczną formę klucza i czytnika - okrągłą monetę z dwoma kontaktami. Dla ramki otaczającej go istnieje wiele wariantów, od najbardziej popularnego plastikowego uchwytu z otworem po pierścienie, naszyjniki itp.

<figure><img src="../../.gitbook/assets/image (1075).png" alt=""><figcaption></figcaption></figure>

Gdy klucz dotrze do czytnika, **kontakty się stykają** i klucz jest zasilany, aby **przesłać** swoje ID. Czasami klucz **nie jest odczytywany** natychmiast, ponieważ **obszar PSD kontaktu interkomu jest większy** niż powinien być. W takim przypadku trzeba nacisnąć klucz na jednej ze ścian czytnika.

<figure><img src="../../.gitbook/assets/image (287).png" alt=""><figcaption></figcaption></figure>

### **Protokół 1-Wire** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Klucze Dallas wymieniają dane za pomocą protokołu 1-Wire. Zaledwie jeden kontakt do transferu danych (!!) w obu kierunkach, od mastera do slave'a i odwrotnie. Protokół 1-Wire działa zgodnie z modelem Master-Slave. W tej topologii Master zawsze inicjuje komunikację, a Slave podąża za jego instrukcjami.

Gdy klucz (Slave) styka się z interkomem (Master), chip wewnątrz klucza się włącza, zasilany przez interkom, i klucz jest inicjowany. Następnie interkom żąda ID klucza. Następnie przyjrzymy się temu procesowi bardziej szczegółowo.

Flipper może działać zarówno w trybie Master, jak i Slave. W trybie odczytu klucza Flipper działa jako czytnik, czyli działa jako Master. W trybie emulacji klucza, Flipper udaje, że jest kluczem, działa w trybie Slave.

### Klucze Dallas, Cyfral i Metakom

Aby uzyskać informacje na temat działania tych kluczy, sprawdź stronę [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

### Ataki

Klucze iButton mogą być atakowane za pomocą Flipper Zero:

{% content-ref url="flipper-zero/fz-ibutton.md" %}
[fz-ibutton.md](flipper-zero/fz-ibutton.md)
{% endcontent-ref %}

## Referencje

* [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)
