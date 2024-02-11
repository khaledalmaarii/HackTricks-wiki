# Lokalne przechowywanie w chmurze

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Użyj [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), aby łatwo tworzyć i **automatyzować przepływy pracy** przy użyciu najbardziej zaawansowanych narzędzi społeczności na świecie.\
Otrzymaj dostęp już dziś:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## OneDrive

W systemie Windows folder OneDrive można znaleźć w `\Users\<nazwa_użytkownika>\AppData\Local\Microsoft\OneDrive`. Wewnątrz folderu `logs\Personal` można znaleźć plik `SyncDiagnostics.log`, który zawiera pewne interesujące dane dotyczące zsynchronizowanych plików:

* Rozmiar w bajtach
* Data utworzenia
* Data modyfikacji
* Liczba plików w chmurze
* Liczba plików w folderze
* **CID**: Unikalny identyfikator użytkownika OneDrive
* Czas generowania raportu
* Rozmiar dysku systemowego

Po znalezieniu CID zaleca się **wyszukiwanie plików zawierających ten identyfikator**. Możliwe, że znajdziesz pliki o nazwie: _**\<CID>.ini**_ i _**\<CID>.dat**_, które mogą zawierać interesujące informacje, takie jak nazwy plików zsynchronizowanych z OneDrive.

## Google Drive

W systemie Windows główny folder Google Drive można znaleźć w `\Users\<nazwa_użytkownika>\AppData\Local\Google\Drive\user_default`\
Ten folder zawiera plik o nazwie Sync\_log.log z informacjami, takimi jak adres e-mail konta, nazwy plików, znaczniki czasu, skróty MD5 plików, itp. Nawet usunięte pliki pojawiają się w tym pliku dziennika wraz z odpowiadającymi im skrótami MD5.

Plik **`Cloud_graph\Cloud_graph.db`** to baza danych sqlite, która zawiera tabelę **`cloud_graph_entry`**. W tej tabeli można znaleźć **nazwę** **zsynchronizowanych** **plików**, czas modyfikacji, rozmiar i sumę kontrolną MD5 plików.

Dane tabeli bazy danych **`Sync_config.db`** zawierają adres e-mail konta, ścieżkę do folderów udostępnionych i wersję Google Drive.

## Dropbox

Dropbox używa **baz danych SQLite** do zarządzania plikami. W tym\
Bazy danych można znaleźć w folderach:

* `\Users\<nazwa_użytkownika>\AppData\Local\Dropbox`
* `\Users\<nazwa_użytkownika>\AppData\Local\Dropbox\Instance1`
* `\Users\<nazwa_użytkownika>\AppData\Roaming\Dropbox`

A główne bazy danych to:

* Sigstore.dbx
* Filecache.dbx
* Deleted.dbx
* Config.dbx

Rozszerzenie ".dbx" oznacza, że **bazy danych** są **zaszyfrowane**. Dropbox używa **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/previous-versions/ms995355\(v=msdn.10\)?redirectedfrom=MSDN))

Aby lepiej zrozumieć szyfrowanie używane przez Dropbox, możesz przeczytać [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html).

Jednak główne informacje to:

* **Entropia**: d114a55212655f74bd772e37e64aee9b
* **Sól**: 0D638C092E8B82FC452883F95F355B8E
* **Algorytm**: PBKDF2
* **Iteracje**: 1066

Oprócz tych informacji, do odszyfrowania baz danych potrzebujesz:

* **Zaszyfrowany klucz DPAPI**: Możesz go znaleźć w rejestrze wewnątrz `NTUSER.DAT\Software\Dropbox\ks\client` (wyeksportuj te dane jako binarne)
* Gałęzie **`SYSTEM`** i **`SECURITY`**
* **Klucze główne DPAPI**: Które można znaleźć w `\Users\<nazwa_użytkownika>\AppData\Roaming\Microsoft\Protect`
* Nazwa użytkownika i hasło użytkownika systemu Windows

Następnie możesz użyć narzędzia [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi\_data\_decryptor.html)**:**

![](<../../../.gitbook/assets/image (448).png>)

Jeśli wszystko pójdzie zgodnie z oczekiwaniami, narzędzie wskaże **klucz główny**, który musisz **użyć do odzyskania oryginalnego klucza**. Aby odzyskać oryginalny klucz, użyj tego [przepisu cyber\_chef](https://gchq.github.io/CyberChef/#recipe=Derive\_PBKDF2\_key\(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D\)) umieszczając klucz główny jako "hasło" wewnątrz przepisu.

Otrzymany szesnastkowy kod jest końcowym kluczem używanym do szyfrowania baz danych, które można odszyfrować za pomocą:
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
Baza danych **`config.dbx`** zawiera:

* **Email**: Adres e-mail użytkownika
* **usernamedisplayname**: Nazwa użytkownika
* **dropbox\_path**: Ścieżka, w której znajduje się folder Dropbox
* **Host\_id: Hash**: Używany do uwierzytelniania w chmurze. Może być wycofany tylko za pośrednictwem strony internetowej.
* **Root\_ns**: Identyfikator użytkownika

Baza danych **`filecache.db`** zawiera informacje o wszystkich plikach i folderach zsynchronizowanych z Dropbox. Tabela `File_journal` zawiera najbardziej przydatne informacje:

* **Server\_path**: Ścieżka, w której znajduje się plik na serwerze (ścieżka ta poprzedzona jest `host_id` klienta).
* **local\_sjid**: Wersja pliku
* **local\_mtime**: Data modyfikacji
* **local\_ctime**: Data utworzenia

Inne tabele w tej bazie danych zawierają bardziej interesujące informacje:

* **block\_cache**: Skrót wszystkich plików i folderów Dropbox
* **block\_ref**: Powiązanie identyfikatora skrótu z tabeli `block_cache` z identyfikatorem pliku w tabeli `file_journal`
* **mount\_table**: Udostępnione foldery Dropbox
* **deleted\_fields**: Usunięte pliki Dropbox
* **date\_added**

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Użyj [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), aby łatwo tworzyć i **automatyzować zadania** przy użyciu najbardziej zaawansowanych narzędzi społecznościowych na świecie.\
Otrzymaj dostęp już dziś:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć **reklamę swojej firmy w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi trikami hakerskimi, przesyłając PR do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
