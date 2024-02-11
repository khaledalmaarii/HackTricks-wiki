<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów GitHub.

</details>


**Oryginalny post znajduje się pod adresem** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## Podsumowanie

Znaleziono dwa klucze rejestru, które można zapisywać przez bieżącego użytkownika:

- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**

Zasugerowano sprawdzenie uprawnień usługi **RpcEptMapper** za pomocą **regedit GUI**, a konkretnie zakładki **Advanced Security Settings** w oknie **Effective Permissions**. To podejście umożliwia ocenę przyznanych uprawnień dla określonych użytkowników lub grup bez konieczności badania każdego wpisu kontroli dostępu (ACE) osobno.

Na zrzucie ekranu pokazano uprawnienia przypisane do użytkownika o niskich uprawnieniach, wśród których wyróżnia się uprawnienie **Create Subkey**. To uprawnienie, zwane również **AppendData/AddSubdirectory**, odpowiada wynikom skryptu.

Zauważono, że nie można bezpośrednio modyfikować pewnych wartości, ale można tworzyć nowe podklucze. Przykładem było próba zmiany wartości **ImagePath**, która skończyła się komunikatem o odmowie dostępu.

Mimo tych ograniczeń zidentyfikowano potencjał eskalacji uprawnień poprzez możliwość wykorzystania podklucza **Performance** w strukturze rejestru usługi **RpcEptMapper**, który nie jest domyślnie obecny. Może to umożliwić rejestrację DLL i monitorowanie wydajności.

Skonsultowano dokumentację dotyczącą podklucza **Performance** i jego wykorzystania do monitorowania wydajności, co doprowadziło do opracowania DLL w celu potwierdzenia koncepcji. Ta DLL, demonstrująca implementację funkcji **OpenPerfData**, **CollectPerfData** i **ClosePerfData**, została przetestowana za pomocą **rundll32**, potwierdzając jej działanie.

Celem było zmuszenie usługi **RPC Endpoint Mapper** do załadowania stworzonej DLL wydajnościowej. Obserwacje wykazały, że wykonanie zapytań klasy WMI dotyczących danych wydajności za pomocą PowerShella skutkuje utworzeniem pliku dziennika, umożliwiając wykonanie dowolnego kodu w kontekście **LOCAL SYSTEM** i tym samym przyznanie podwyższonych uprawnień.

Podkreślono trwałość i potencjalne konsekwencje tej podatności, zwracając uwagę na jej znaczenie dla strategii poeksploatacyjnych, ruchu bocznego i unikania systemów antywirusowych/EDR.

Mimo że podatność początkowo została niezamierzenie ujawniona przez skrypt, podkreślono, że jej wykorzystanie jest ograniczone do przestarzałych wersji systemu Windows (np. **Windows 7 / Server 2008 R2**) i wymaga dostępu lokalnego.

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów GitHub.

</details>
