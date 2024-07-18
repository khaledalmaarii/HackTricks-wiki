# Lokalna Chmura

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Użyj [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), aby łatwo budować i **automatyzować przepływy pracy** zasilane przez **najbardziej zaawansowane** narzędzia społecznościowe na świecie.\
Uzyskaj dostęp już dziś:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## OneDrive

W systemie Windows możesz znaleźć folder OneDrive w `\Users\<username>\AppData\Local\Microsoft\OneDrive`. A wewnątrz `logs\Personal` można znaleźć plik `SyncDiagnostics.log`, który zawiera interesujące dane dotyczące zsynchronizowanych plików:

* Rozmiar w bajtach
* Data utworzenia
* Data modyfikacji
* Liczba plików w chmurze
* Liczba plików w folderze
* **CID**: Unikalny identyfikator użytkownika OneDrive
* Czas generowania raportu
* Rozmiar dysku twardego systemu operacyjnego

Gdy znajdziesz CID, zaleca się **wyszukiwanie plików zawierających ten identyfikator**. Możesz znaleźć pliki o nazwach: _**\<CID>.ini**_ i _**\<CID>.dat**_, które mogą zawierać interesujące informacje, takie jak nazwy plików zsynchronizowanych z OneDrive.

## Google Drive

W systemie Windows możesz znaleźć główny folder Google Drive w `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Ten folder zawiera plik o nazwie Sync\_log.log z informacjami takimi jak adres e-mail konta, nazwy plików, znaczniki czasu, hashe MD5 plików itp. Nawet usunięte pliki pojawiają się w tym pliku dziennika z odpowiadającym im MD5.

Plik **`Cloud_graph\Cloud_graph.db`** to baza danych sqlite, która zawiera tabelę **`cloud_graph_entry`**. W tej tabeli można znaleźć **nazwy** **zsynchronizowanych** **plików**, czas modyfikacji, rozmiar i sumę kontrolną MD5 plików.

Dane tabeli bazy danych **`Sync_config.db`** zawierają adres e-mail konta, ścieżkę do udostępnionych folderów oraz wersję Google Drive.

## Dropbox

Dropbox używa **baz danych SQLite** do zarządzania plikami. W tym\
Możesz znaleźć bazy danych w folderach:

* `\Users\<username>\AppData\Local\Dropbox`
* `\Users\<username>\AppData\Local\Dropbox\Instance1`
* `\Users\<username>\AppData\Roaming\Dropbox`

A główne bazy danych to:

* Sigstore.dbx
* Filecache.dbx
* Deleted.dbx
* Config.dbx

Rozszerzenie ".dbx" oznacza, że **bazy danych** są **szyfrowane**. Dropbox używa **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/previous-versions/ms995355\(v=msdn.10\)?redirectedfrom=MSDN))

Aby lepiej zrozumieć szyfrowanie, które używa Dropbox, możesz przeczytać [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html).

Jednak główne informacje to:

* **Entropia**: d114a55212655f74bd772e37e64aee9b
* **Sól**: 0D638C092E8B82FC452883F95F355B8E
* **Algorytm**: PBKDF2
* **Iteracje**: 1066

Oprócz tych informacji, aby odszyfrować bazy danych, potrzebujesz jeszcze:

* **szyfrowanego klucza DPAPI**: Możesz go znaleźć w rejestrze w `NTUSER.DAT\Software\Dropbox\ks\client` (wyeksportuj te dane jako binarne)
* **hive'y** **`SYSTEM`** i **`SECURITY`**
* **kluczy głównych DPAPI**: Które można znaleźć w `\Users\<username>\AppData\Roaming\Microsoft\Protect`
* **nazwa użytkownika** i **hasło** użytkownika systemu Windows

Następnie możesz użyć narzędzia [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi\_data\_decryptor.html)**:**

![](<../../../.gitbook/assets/image (448).png>)

Jeśli wszystko pójdzie zgodnie z planem, narzędzie wskaże **klucz główny**, który musisz **użyć, aby odzyskać oryginalny**. Aby odzyskać oryginalny klucz, po prostu użyj tego [przepisu cyber\_chef](https://gchq.github.io/CyberChef/#recipe=Derive\_PBKDF2\_key\(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D\)), wstawiając klucz główny jako "hasło" w przepisie.

Ostateczny hex to klucz użyty do szyfrowania baz danych, który można odszyfrować za pomocą:
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
The **`config.dbx`** baza danych zawiera:

* **Email**: Email użytkownika
* **usernamedisplayname**: Nazwa użytkownika
* **dropbox\_path**: Ścieżka, w której znajduje się folder dropbox
* **Host\_id: Hash** używany do uwierzytelniania w chmurze. Może być odwołany tylko z poziomu sieci.
* **Root\_ns**: Identyfikator użytkownika

The **`filecache.db`** baza danych zawiera informacje o wszystkich plikach i folderach synchronizowanych z Dropbox. Tabela `File_journal` zawiera najwięcej przydatnych informacji:

* **Server\_path**: Ścieżka, w której plik znajduje się na serwerze (ta ścieżka jest poprzedzona `host_id` klienta).
* **local\_sjid**: Wersja pliku
* **local\_mtime**: Data modyfikacji
* **local\_ctime**: Data utworzenia

Inne tabele w tej bazie danych zawierają bardziej interesujące informacje:

* **block\_cache**: hash wszystkich plików i folderów Dropbox
* **block\_ref**: Powiązanie identyfikatora hash z tabeli `block_cache` z identyfikatorem pliku w tabeli `file_journal`
* **mount\_table**: Udostępnione foldery Dropbox
* **deleted\_fields**: Usunięte pliki Dropbox
* **date\_added**

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Użyj [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), aby łatwo budować i **automatyzować przepływy pracy** zasilane przez **najbardziej zaawansowane** narzędzia społecznościowe na świecie.\
Uzyskaj dostęp już dziś:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na GitHubie.

</details>
{% endhint %}
