# Volatility - CheatSheet

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/) to najważniejsze wydarzenie związane z cyberbezpieczeństwem w **Hiszpanii** i jedno z najważniejszych w **Europie**. Mając **misję promowania wiedzy technicznej**, ten kongres jest gorącym punktem spotkań dla profesjonalistów technologii i cyberbezpieczeństwa we wszystkich dziedzinach.

{% embed url="https://www.rootedcon.com/" %}

Jeśli chcesz czegoś **szybkiego i szalonego**, co uruchomi kilka wtyczek Volatility równolegle, możesz użyć: [https://github.com/carlospolop/autoVolatility](https://github.com/carlospolop/autoVolatility)

```bash
python autoVolatility.py -f MEMFILE -d OUT_DIRECTORY -e /home/user/tools/volatility/vol.py # It will use the most important plugins (could use a lot of space depending on the size of the memory)
```

## Instalacja

### volatility3

```bash
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
python3 setup.py install
python3 vol.py —h
```

#### Metoda 1: Analiza obrazu pamięci

1. Uruchomienie Volatility:

```bash
volatility -f <plik_obrazu_pamięci> imageinfo
```

2. Wybór profilu:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> <komenda>
```

3. Wyświetlanie listy procesów:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> pslist
```

4. Wyświetlanie informacji o procesie:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> psscan
```

5. Wyświetlanie listy modułów:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> modscan
```

6. Wyświetlanie listy sterowników:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> driverscan
```

7. Wyświetlanie listy połączeń sieciowych:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> connscan
```

8. Wyświetlanie listy otwartych plików:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> filescan
```

9. Wyświetlanie listy zasobów rejestru:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> hivelist
```

10. Wyświetlanie zawartości rejestru:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> printkey -K <adres_rejestru>
```

11. Wyświetlanie listy otwartych uchwytów:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> handles
```

12. Wyświetlanie listy usług:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> svcscan
```

13. Wyświetlanie listy plików w katalogu:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> filescan -D <ścieżka_do_katalogu>
```

14. Wyświetlanie listy procesów w katalogu:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> pslist -D <ścieżka_do_katalogu>
```

15. Wyświetlanie listy procesów dla danego użytkownika:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> pslist -U <nazwa_użytkownika>
```

16. Wyświetlanie listy procesów dla danego PID:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> pslist -p <PID>
```

17. Wyświetlanie listy procesów dla danego procesu rodzica:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> pstree -p <PID_procesu_rodzica>
```

18. Wyświetlanie listy procesów dla danego procesu dziecka:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> pstree -t <PID_procesu_dziecka>
```

19. Wyświetlanie listy wątków dla danego procesu:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> threads -p <PID_procesu>
```

20. Wyświetlanie listy wątków dla danego procesu rodzica:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> threads -p <PID_procesu_rodzica>
```

21. Wyświetlanie listy wątków dla danego procesu dziecka:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> threads -t <PID_procesu_dziecka>
```

22. Wyświetlanie listy wątków dla danego procesu i wątku:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> threads -p <PID_procesu> -t <TID_wątku>
```

23. Wyświetlanie listy deskryptorów dla danego procesu:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> handles -p <PID_procesu>
```

24. Wyświetlanie listy deskryptorów dla danego procesu rodzica:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> handles -p <PID_procesu_rodzica>
```

25. Wyświetlanie listy deskryptorów dla danego procesu dziecka:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> handles -t <PID_procesu_dziecka>
```

26. Wyświetlanie listy deskryptorów dla danego procesu i deskryptora:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> handles -p <PID_procesu> -t <deskryptor>
```

27. Wyświetlanie listy plików dla danego procesu:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> filescan -p <PID_procesu>
```

28. Wyświetlanie listy plików dla danego procesu rodzica:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> filescan -p <PID_procesu_rodzica>
```

29. Wyświetlanie listy plików dla danego procesu dziecka:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> filescan -t <PID_procesu_dziecka>
```

30. Wyświetlanie listy plików dla danego procesu i pliku:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> filescan -p <PID_procesu> -t <plik>
```

31. Wyświetlanie listy połączeń sieciowych dla danego procesu:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> connscan -p <PID_procesu>
```

32. Wyświetlanie listy połączeń sieciowych dla danego procesu rodzica:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> connscan -p <PID_procesu_rodzica>
```

33. Wyświetlanie listy połączeń sieciowych dla danego procesu dziecka:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> connscan -t <PID_procesu_dziecka>
```

34. Wyświetlanie listy połączeń sieciowych dla danego procesu i połączenia:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> connscan -p <PID_procesu> -t <połączenie>
```

35. Wyświetlanie listy modułów dla danego procesu:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> modscan -p <PID_procesu>
```

36. Wyświetlanie listy modułów dla danego procesu rodzica:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> modscan -p <PID_procesu_rodzica>
```

37. Wyświetlanie listy modułów dla danego procesu dziecka:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> modscan -t <PID_procesu_dziecka>
```

38. Wyświetlanie listy modułów dla danego procesu i modułu:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> modscan -p <PID_procesu> -t <moduł>
```

39. Wyświetlanie listy sterowników dla danego procesu:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> driverscan -p <PID_procesu>
```

40. Wyświetlanie listy sterowników dla danego procesu rodzica:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> driverscan -p <PID_procesu_rodzica>
```

41. Wyświetlanie listy sterowników dla danego procesu dziecka:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> driverscan -t <PID_procesu_dziecka>
```

42. Wyświetlanie listy sterowników dla danego procesu i sterownika:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> driverscan -p <PID_procesu> -t <sterownik>
```

43. Wyświetlanie listy usług dla danego procesu:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> svcscan -p <PID_procesu>
```

44. Wyświetlanie listy usług dla danego procesu rodzica:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> svcscan -p <PID_procesu_rodzica>
```

45. Wyświetlanie listy usług dla danego procesu dziecka:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> svcscan -t <PID_procesu_dziecka>
```

46. Wyświetlanie listy usług dla danego procesu i usługi:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> svcscan -p <PID_procesu> -t <usługa>
```

47. Wyświetlanie listy zasobów rejestru dla danego procesu:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> hivelist -p <PID_procesu>
```

48. Wyświetlanie listy zasobów rejestru dla danego procesu rodzica:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> hivelist -p <PID_procesu_rodzica>
```

49. Wyświetlanie listy zasobów rejestru dla danego procesu dziecka:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> hivelist -t <PID_procesu_dziecka>
```

50. Wyświetlanie listy zasobów rejestru dla danego procesu i zasobu:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> hivelist -p <PID_procesu> -t <zasób_rejestru>
```

51. Wyświetlanie zawartości rejestru dla danego procesu i zasobu rejestru:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> printkey -K <adres_rejestru> -p <PID_procesu>
```

52. Wyświetlanie zawartości rejestru dla danego procesu rodzica i zasobu rejestru:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> printkey -K <adres_rejestru> -p <PID_procesu_rodzica>
```

53. Wyświetlanie zawartości rejestru dla danego procesu dziecka i zasobu rejestru:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> printkey -K <adres_rejestru> -t <PID_procesu_dziecka>
```

54. Wyświetlanie zawartości rejestru dla danego procesu i zasobu rejestru:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> printkey -K <adres_rejestru> -p <PID_procesu> -t <zasób_rejestru>
```

55. Wyświetlanie listy otwartych uchwytów dla danego procesu:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> handles -p <PID_procesu>
```

56. Wyświetlanie listy otwartych uchwytów dla danego procesu rodzica:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> handles -p <PID_procesu_rodzica>
```

57. Wyświetlanie listy otwartych uchwytów dla danego procesu dziecka:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> handles -t <PID_procesu_dziecka>
```

58. Wyświetlanie listy otwartych uchwytów dla danego procesu i uchwytu:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> handles -p <PID_procesu> -t <uchwyt>
```

59. Wyświetlanie listy deskryptorów dla danego procesu:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> handles -p <PID_procesu>
```

60. Wyświetlanie listy deskryptorów dla danego procesu rodzica:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> handles -p <PID_procesu_rodzica>
```

61. Wyświetlanie listy deskryptorów dla danego procesu dziecka:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> handles -t <PID_procesu_dziecka>
```

62. Wyświetlanie listy deskryptorów dla danego procesu i deskryptora:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> handles -p <PID_procesu> -t <deskryptor>
```

63. Wyświetlanie listy plików dla danego procesu:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> filescan -p <PID_procesu>
```

64. Wyświetlanie listy plików dla danego procesu rodzica:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> filescan -p <PID_procesu_rodzica>
```

65. Wyświetlanie listy plików dla danego procesu dziecka:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> filescan -t <PID_procesu_dziecka>
```

66. Wyświetlanie listy plików dla danego procesu i pliku:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> filescan -p <PID_procesu> -t <plik>
```

67. Wyświetlanie listy połączeń sieciowych dla danego procesu:

```bash
volatility -f <plik_obrazu_pamięci> --profile=<profil> connscan -p <PID_procesu>
```

68. Wyświetlanie listy połąc

```
Download the executable from https://www.volatilityfoundation.org/26
```

```bash
git clone https://github.com/volatilityfoundation/volatility.git
cd volatility
python setup.py install
```

## Polecenia Volatility

Dostęp do oficjalnej dokumentacji znajduje się w [Odwołanie do poleceń Volatility](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#kdbgscan)

### Uwaga dotycząca wtyczek „list” vs. „scan”

Volatility ma dwa główne podejścia do wtyczek, które czasami odzwierciedlają się w ich nazwach. Wtyczki „list” będą próbowały nawigować przez struktury jądra systemu Windows, aby pobrać informacje, takie jak procesy (lokalizowanie i przechodzenie przez listę połączoną struktur `_EPROCESS` w pamięci), uchwyty systemowe (lokalizowanie i wyświetlanie tabeli uchwytów, dereferencjonowanie znalezionych wskaźników, itp.). Zachowują się one mniej więcej tak, jakby Windows API zostało poproszone o wylistowanie procesów.

To sprawia, że wtyczki „list” są dość szybkie, ale równie podatne na manipulację przez złośliwe oprogramowanie, jak Windows API. Na przykład, jeśli złośliwe oprogramowanie używa DKOM do odłączenia procesu od listy połączonej struktur `_EPROCESS`, nie pojawi się ono w Menedżerze zadań, ani w pslist.

Wtyczki „scan” z kolei podejdą do sprawy podobnie jak wycinanie pamięci w poszukiwaniu rzeczy, które mogą mieć sens, gdy są dereferencjonowane jako konkretne struktury. Na przykład, `psscan` odczyta pamięć i spróbuje utworzyć obiekty `_EPROCESS` z niej (używa skanowania tagów puli, które polega na wyszukiwaniu ciągów 4-bajtowych wskazujących na obecność interesującej struktury). Zaletą jest to, że może odnaleźć procesy, które zostały zakończone, i nawet jeśli złośliwe oprogramowanie manipuluje listą połączoną struktur `_EPROCESS`, wtyczka nadal znajdzie strukturę w pamięci (ponieważ musi ona nadal istnieć, aby proces mógł działać). Wada polega na tym, że wtyczki „scan” są nieco wolniejsze od wtyczek „list” i czasami mogą dawać fałszywe wyniki (proces, który został zakończony zbyt dawno temu i którego części struktury zostały nadpisane przez inne operacje).

Źródło: [http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/](http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/)

## Profile systemów operacyjnych

### Volatility3

Jak wyjaśniono w pliku readme, musisz umieścić **tabelę symboli systemu operacyjnego**, który chcesz obsługiwać, w folderze _volatility3/volatility/symbols_.\
Pakiety tabel symboli dla różnych systemów operacyjnych są dostępne do **pobrania** pod adresem:

* [https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip)
* [https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip)
* [https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip)

### Volatility2

#### Profil zewnętrzny

Możesz uzyskać listę obsługiwanych profili wykonując:

```bash
./volatility_2.6_lin64_standalone --info | grep "Profile"
```

Jeśli chcesz użyć **nowego profilu, który pobrałeś** (na przykład profilu linuxowego), musisz utworzyć strukturę folderów: _plugins/overlays/linux_ i umieścić w tym folderze plik zip zawierający profil. Następnie, uzyskaj numer profilu, używając:

```bash
./vol --plugins=/home/kali/Desktop/ctfs/final/plugins --info
Volatility Foundation Volatility Framework 2.6


Profiles
--------
LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 - A Profile for Linux CentOS7_3.10.0-123.el7.x86_64_profile x64
VistaSP0x64                                   - A Profile for Windows Vista SP0 x64
VistaSP0x86                                   - A Profile for Windows Vista SP0 x86
```

Możesz **pobrać profile Linuxa i Maca** z [https://github.com/volatilityfoundation/profiles](https://github.com/volatilityfoundation/profiles)

W poprzednim fragmencie możesz zobaczyć, że profil nazywa się `LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64`, i możesz go użyć do wykonania czegoś takiego jak:

```bash
./vol -f file.dmp --plugins=. --profile=LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 linux_netscan
```

#### Odkryj profil

```plaintext
volatility -f <memory_dump> imageinfo
```

```plaintext
volatility -f <memory_dump> kdbgscan
```

```plaintext
volatility -f <memory_dump> hivelist
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key>
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset>
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=html -D <output_directory>
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=csv -D <output_directory>
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=json -D <output_directory>
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=sqlite -D <output_directory>
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=sqlite3 -D <output_directory>
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=txt -D <output_directory>
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=txt -D <output_directory> --output-file=<output_file>
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=txt -D <output_directory> --output-file=<output_file> --output-append
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=txt -D <output_directory> --output-file=<output_file> --output-append --output-unicode
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=txt -D <output_directory> --output-file=<output_file> --output-append --output-unicode --output-raw
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=txt -D <output_directory> --output-file=<output_file> --output-append --output-unicode --output-raw --output-hex
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=txt -D <output_directory> --output-file=<output_file> --output-append --output-unicode --output-raw --output-hex --output-utf8
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=txt -D <output_directory> --output-file=<output_file> --output-append --output-unicode --output-raw --output-hex --output-utf8 --output-utf16
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=txt -D <output_directory> --output-file=<output_file> --output-append --output-unicode --output-raw --output-hex --output-utf8 --output-utf16 --output-utf16le
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=txt -D <output_directory> --output-file=<output_file> --output-append --output-unicode --output-raw --output-hex --output-utf8 --output-utf16 --output-utf16le --output-utf16be
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=txt -D <output_directory> --output-file=<output_file> --output-append --output-unicode --output-raw --output-hex --output-utf8 --output-utf16 --output-utf16le --output-utf16be --output-utf32
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=txt -D <output_directory> --output-file=<output_file> --output-append --output-unicode --output-raw --output-hex --output-utf8 --output-utf16 --output-utf16le --output-utf16be --output-utf32 --output-utf32le
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=txt -D <output_directory> --output-file=<output_file> --output-append --output-unicode --output-raw --output-hex --output-utf8 --output-utf16 --output-utf16le --output-utf16be --output-utf32 --output-utf32le --output-utf32be
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=txt -D <output_directory> --output-file=<output_file> --output-append --output-unicode --output-raw --output-hex --output-utf8 --output-utf16 --output-utf16le --output-utf16be --output-utf32 --output-utf32le --output-utf32be --output-utf7
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=txt -D <output_directory> --output-file=<output_file> --output-append --output-unicode --output-raw --output-hex --output-utf8 --output-utf16 --output-utf16le --output-utf16be --output-utf32 --output-utf32le --output-utf32be --output-utf7 --output-utf1
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=txt -D <output_directory> --output-file=<output_file> --output-append --output-unicode --output-raw --output-hex --output-utf8 --output-utf16 --output-utf16le --output-utf16be --output-utf32 --output-utf32le --output-utf32be --output-utf7 --output-utf1 --output-utf3
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=txt -D <output_directory> --output-file=<output_file> --output-append --output-unicode --output-raw --output-hex --output-utf8 --output-utf16 --output-utf16le --output-utf16be --output-utf32 --output-utf32le --output-utf32be --output-utf7 --output-utf1 --output-utf3 --output-utf5
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=txt -D <output_directory> --output-file=<output_file> --output-append --output-unicode --output-raw --output-hex --output-utf8 --output-utf16 --output-utf16le --output-utf16be --output-utf32 --output-utf32le --output-utf32be --output-utf7 --output-utf1 --output-utf3 --output-utf5 --output-utf9
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=txt -D <output_directory> --output-file=<output_file> --output-append --output-unicode --output-raw --output-hex --output-utf8 --output-utf16 --output-utf16le --output-utf16be --output-utf32 --output-utf32le --output-utf32be --output-utf7 --output-utf1 --output-utf3 --output-utf5 --output-utf9 --output-utf11
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=txt -D <output_directory> --output-file=<output_file> --output-append --output-unicode --output-raw --output-hex --output-utf8 --output-utf16 --output-utf16le --output-utf16be --output-utf32 --output-utf32le --output-utf32be --output-utf7 --output-utf1 --output-utf3 --output-utf5 --output-utf9 --output-utf11 --output-utf13
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=txt -D <output_directory> --output-file=<output_file> --output-append --output-unicode --output-raw --output-hex --output-utf8 --output-utf16 --output-utf16le --output-utf16be --output-utf32 --output-utf32le --output-utf32be --output-utf7 --output-utf1 --output-utf3 --output-utf5 --output-utf9 --output-utf11 --output-utf13 --output-utf15
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=txt -D <output_directory> --output-file=<output_file> --output-append --output-unicode --output-raw --output-hex --output-utf8 --output-utf16 --output-utf16le --output-utf16be --output-utf32 --output-utf32le --output-utf32be --output-utf7 --output-utf1 --output-utf3 --output-utf5 --output-utf9 --output-utf11 --output-utf13 --output-utf15 --output-utf17
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=txt -D <output_directory> --output-file=<output_file> --output-append --output-unicode --output-raw --output-hex --output-utf8 --output-utf16 --output-utf16le --output-utf16be --output-utf32 --output-utf32le --output-utf32be --output-utf7 --output-utf1 --output-utf3 --output-utf5 --output-utf9 --output-utf11 --output-utf13 --output-utf15 --output-utf17 --output-utf19
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=txt -D <output_directory> --output-file=<output_file> --output-append --output-unicode --output-raw --output-hex --output-utf8 --output-utf16 --output-utf16le --output-utf16be --output-utf32 --output-utf32le --output-utf32be --output-utf7 --output-utf1 --output-utf3 --output-utf5 --output-utf9 --output-utf11 --output-utf13 --output-utf15 --output-utf17 --output-utf19 --output-utf21
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=txt -D <output_directory> --output-file=<output_file> --output-append --output-unicode --output-raw --output-hex --output-utf8 --output-utf16 --output-utf16le --output-utf16be --output-utf32 --output-utf32le --output-utf32be --output-utf7 --output-utf1 --output-utf3 --output-utf5 --output-utf9 --output-utf11 --output-utf13 --output-utf15 --output-utf17 --output-utf19 --output-utf21 --output-utf23
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=txt -D <output_directory> --output-file=<output_file> --output-append --output-unicode --output-raw --output-hex --output-utf8 --output-utf16 --output-utf16le --output-utf16be --output-utf32 --output-utf32le --output-utf32be --output-utf7 --output-utf1 --output-utf3 --output-utf5 --output-utf9 --output-utf11 --output-utf13 --output-utf15 --output-utf17 --output-utf19 --output-utf21 --output-utf23 --output-utf25
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=txt -D <output_directory> --output-file=<output_file> --output-append --output-unicode --output-raw --output-hex --output-utf8 --output-utf16 --output-utf16le --output-utf16be --output-utf32 --output-utf32le --output-utf32be --output-utf7 --output-utf1 --output-utf3 --output-utf5 --output-utf9 --output-utf11 --output-utf13 --output-utf15 --output-utf17 --output-utf19 --output-utf21 --output-utf23 --output-utf25 --output-utf27
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=txt -D <output_directory> --output-file=<output_file> --output-append --output-unicode --output-raw --output-hex --output-utf8 --output-utf16 --output-utf16le --output-utf16be --output-utf32 --output-utf32le --output-utf32be --output-utf7 --output-utf1 --output-utf3 --output-utf5 --output-utf9 --output-utf11 --output-utf13 --output-utf15 --output-utf17 --output-utf19 --output-utf21 --output-utf23 --output-utf25 --output-utf27 --output-utf29
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=txt -D <output_directory> --output-file=<output_file> --output-append --output-unicode --output-raw --output-hex --output-utf8 --output-utf16 --output-utf16le --output-utf16be --output-utf32 --output-utf32le --output-utf32be --output-utf7 --output-utf1 --output-utf3 --output-utf5 --output-utf9 --output-utf11 --output-utf13 --output-utf15 --output-utf17 --output-utf19 --output-utf21 --output-utf23 --output-utf25 --output-utf27 --output-utf29 --output-utf31
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=txt -D <output_directory> --output-file=<output_file> --output-append --output-unicode --output-raw --output-hex --output-utf8 --output-utf16 --output-utf16le --output-utf16be --output-utf32 --output-utf32le --output-utf32be --output-utf7 --output-utf1 --output-utf3 --output-utf5 --output-utf9 --output-utf11 --output-utf13 --output-utf15 --output-utf17 --output-utf19 --output-utf21 --output-utf23 --output-utf25 --output-utf27 --output-utf29 --output-utf31 --output-utf33
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=txt -D <output_directory> --output-file=<output_file> --output-append --output-unicode --output-raw --output-hex --output-utf8 --output-utf16 --output-utf16le --output-utf16be --output-utf32 --output-utf32le --output-utf32be --output-utf7 --output-utf1 --output-utf3 --output-utf5 --output-utf9 --output-utf11 --output-utf13 --output-utf15 --output-utf17 --output-utf19 --output-utf21 --output-utf23 --output-utf25 --output-utf27 --output-utf29 --output-utf31 --output-utf33 --output-utf35
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=txt -D <output_directory> --output-file=<output_file> --output-append --output-unicode --output-raw --output-hex --output-utf8 --output-utf16 --output-utf16le --output-utf16be --output-utf32 --output-utf32le --output-utf32be --output-utf7 --output-utf1 --output-utf3 --output-utf5 --output-utf9 --output-utf11 --output-utf13 --output-utf15 --output-utf17 --output-utf19 --output-utf21 --output-utf23 --output-utf25 --output-utf27 --output
```

volatility imageinfo -f file.dmp volatility kdbgscan -f file.dmp

````
#### **Różnice między imageinfo a kdbgscan**

[Z **tego miejsca**](https://www.andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/): W przeciwieństwie do imageinfo, które po prostu sugeruje profile, **kdbgscan** został zaprojektowany w celu pozytywnego zidentyfikowania poprawnego profilu i poprawnego adresu KDBG (jeśli istnieje wiele). Ten plugin skanuje sygnatury nagłówka KDBGHeader powiązane z profilami Volatility i stosuje testy poprawności, aby zredukować fałszywe wyniki. Liczba wypisywanych informacji i liczba testów poprawności, które można przeprowadzić, zależy od tego, czy Volatility może znaleźć DTB, więc jeśli już znasz poprawny profil (lub jeśli masz sugestię profilu z imageinfo), upewnij się, że go używasz.

Zawsze spójrz na **liczbę procesów, które znalazł kdbgscan**. Czasami imageinfo i kdbgscan mogą znaleźć **więcej niż jeden** odpowiedni **profil**, ale tylko **ten poprawny będzie miał związane z nim pewne procesy** (wynika to z konieczności wyodrębnienia procesów przy użyciu poprawnego adresu KDBG).
```bash
# GOOD
PsActiveProcessHead           : 0xfffff800011977f0 (37 processes)
PsLoadedModuleList            : 0xfffff8000119aae0 (116 modules)
````

```bash
# BAD
PsActiveProcessHead           : 0xfffff800011947f0 (0 processes)
PsLoadedModuleList            : 0xfffff80001197ac0 (0 modules)
```

#### KDBG

**Kernel Debugger Block**, zwany **KDBG** przez Volatility, jest kluczowy dla zadań forensycznych wykonywanych przez Volatility i różne debuggery. Zidentyfikowany jako `KdDebuggerDataBlock` i typu `_KDDEBUGGER_DATA64`, zawiera istotne odwołania, takie jak `PsActiveProcessHead`. To konkretne odwołanie wskazuje na głowę listy procesów, umożliwiając wylistowanie wszystkich procesów, co jest podstawowe dla dokładnej analizy pamięci.

## Informacje o systemie operacyjnym

```bash
#vol3 has a plugin to give OS information (note that imageinfo from vol2 will give you OS info)
./vol.py -f file.dmp windows.info.Info
```

Wtyczka `banners.Banners` może być użyta w **vol3 do próby znalezienia banerów Linux** w dumpie.

## Skróty/Hasła

Wyodrębnij skróty SAM, [buforowane poświadczenia domeny](../../../windows-hardening/stealing-credentials/credentials-protections.md#cached-credentials) i [tajemnice LSA](../../../windows-hardening/authentication-credentials-uac-and-efs/#lsa-secrets).

{% tabs %}
{% tab title="undefined" %}
```bash
./vol.py -f file.dmp windows.hashdump.Hashdump #Grab common windows hashes (SAM+SYSTEM)
./vol.py -f file.dmp windows.cachedump.Cachedump #Grab domain cache hashes inside the registry
./vol.py -f file.dmp windows.lsadump.Lsadump #Grab lsa secrets
```
{% endtab %}

{% tab title="undefined" %}
```bash
volatility --profile=Win7SP1x86_23418 hashdump -f file.dmp #Grab common windows hashes (SAM+SYSTEM)
volatility --profile=Win7SP1x86_23418 cachedump -f file.dmp #Grab domain cache hashes inside the registry
volatility --profile=Win7SP1x86_23418 lsadump -f file.dmp #Grab lsa secrets
```
{% endtab %}

{% tab title="undefined" %}
### Zrzut pamięci
{% endtab %}

{% tab title="undefined" %}
Zrzut pamięci procesu **wydobędzie wszystko** dotyczące bieżącego stanu procesu. Moduł **procdump** wydobędzie tylko **kod**.
{% endtab %}

{% tab title="undefined" %}
```
volatility -f file.dmp --profile=Win7SP1x86 memdump -p 2168 -D conhost/
```
{% endtab %}

{% tab title="undefined" %}
<img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt="" data-size="original">
{% endtab %}

{% tab title="undefined" %}
[**RootedCON**](https://www.rootedcon.com/) to najważniejsze wydarzenie związane z cyberbezpieczeństwem w **Hiszpanii** i jedno z najważniejszych w **Europie**. Mając na celu promowanie wiedzy technicznej, ten kongres jest gorącym punktem spotkań dla profesjonalistów technologii i cyberbezpieczeństwa we wszystkich dziedzinach.
{% endtab %}

{% tab title="undefined" %}
{% embed url="https://www.rootedcon.com/" %}
{% endtab %}

{% tab title="undefined" %}
### Procesy
{% endtab %}

{% tab title="undefined" %}
#### Wyświetlanie procesów
{% endtab %}

{% tab title="undefined" %}
Spróbuj znaleźć **podejrzane** procesy (po nazwie) lub **niespodziewane** procesy potomne (na przykład cmd.exe jako proces potomny iexplorer.exe).\
Może być interesujące porównanie wyników polecenia pslist z wynikami polecenia psscan w celu zidentyfikowania ukrytych procesów.
{% endtab %}

{% tab title="undefined" %}
{% tabs %}
{% tab title="undefined" %}
```bash
python3 vol.py -f file.dmp windows.pstree.PsTree # Get processes tree (not hidden)
python3 vol.py -f file.dmp windows.pslist.PsList # Get process list (EPROCESS)
python3 vol.py -f file.dmp windows.psscan.PsScan # Get hidden process list(malware)
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=PROFILE pstree -f file.dmp # Get process tree (not hidden)
volatility --profile=PROFILE pslist -f file.dmp # Get process list (EPROCESS)
volatility --profile=PROFILE psscan -f file.dmp # Get hidden process list(malware)
volatility --profile=PROFILE psxview -f file.dmp # Get hidden process list
```
{% endtab %}
{% endtabs %}
{% endtab %}

{% tab title="undefined" %}
#### Dump proc
{% endtab %}

{% tab title="undefined" %}
{% tabs %}
{% tab title="undefined" %}
**Dump all processes**
{% endtab %}

{% tab title="undefined" %}
```bash
volatility -f <memory_dump> --profile=<profile> procdump --dump-dir=<output_directory>
```
{% endtab %}

{% tab title="undefined" %}
**Dump specific process by PID**
{% endtab %}

{% tab title="undefined" %}
```bash
volatility -f <memory_dump> --profile=<profile> procdump --pid=<pid> --dump-dir=<output_directory>
```
{% endtab %}

{% tab title="undefined" %}
**Dump specific process by name**
{% endtab %}

{% tab title="undefined" %}
```bash
volatility -f <memory_dump> --profile=<profile> procdump --name=<process_name> --dump-dir=<output_directory>
```
{% endtab %}

{% tab title="undefined" %}
**Dump specific process by name and parent process name**
{% endtab %}

{% tab title="undefined" %}
```bash
volatility -f <memory_dump> --profile=<profile> procdump --name=<process_name> --parent-name=<parent_process_name> --dump-dir=<output_directory>
```
{% endtab %}

{% tab title="undefined" %}
**Dump specific process by name and parent process PID**
{% endtab %}

{% tab title="undefined" %}
```bash
volatility -f <memory_dump> --profile=<profile> procdump --name=<process_name> --parent-pid=<parent_process_pid> --dump-dir=<output_directory>
```
{% endtab %}

{% tab title="undefined" %}
**Dump specific process by name and parent process name and parent process PID**
{% endtab %}

{% tab title="undefined" %}
```bash
volatility -f <memory_dump> --profile=<profile> procdump --name=<process_name> --parent-name=<parent_process_name> --parent-pid=<parent_process_pid> --dump-dir=<output_directory>
```
{% endtab %}

{% tab title="undefined" %}
**Dump specific process by name and parent process name and parent process PID and grandparent process name**
{% endtab %}

{% tab title="undefined" %}
```bash
volatility -f <memory_dump> --profile=<profile> procdump --name=<process_name> --parent-name=<parent_process_name> --parent-pid=<parent_process_pid> --grandparent-name=<grandparent_process_name> --dump-dir=<output_directory>
```
{% endtab %}

{% tab title="undefined" %}
**Dump specific process by name and parent process name and parent process PID and grandparent process name and grandparent process PID**
{% endtab %}

{% tab title="undefined" %}
```bash
volatility -f <memory_dump> --profile=<profile> procdump --name=<process_name> --parent-name=<parent_process_name> --parent-pid=<parent_process_pid> --grandparent-name=<grandparent_process_name> --grandparent-pid=<grandparent_process_pid> --dump-dir=<output_directory>
```
{% endtab %}

{% tab title="undefined" %}
**Dump specific process by name and parent process name and parent process PID and grandparent process name and grandparent process PID and great-grandparent process name**
{% endtab %}

{% tab title="undefined" %}
```bash
volatility -f <memory_dump> --profile=<profile> procdump --name=<process_name> --parent-name=<parent_process_name> --parent-pid=<parent_process_pid> --grandparent-name=<grandparent_process_name> --grandparent-pid=<grandparent_process_pid> --greatgrandparent-name=<greatgrandparent_process_name> --dump-dir=<output_directory>
```
{% endtab %}

{% tab title="undefined" %}
**Dump specific process by name and parent process name and parent process PID and grandparent process name and grandparent process PID and great-grandparent process name and great-grandparent process PID**
{% endtab %}

{% tab title="undefined" %}
```bash
volatility -f <memory_dump> --profile=<profile> procdump --name=<process_name> --parent-name=<parent_process_name> --parent-pid=<parent_process_pid> --grandparent-name=<grandparent_process_name> --grandparent-pid=<grandparent_process_pid> --greatgrandparent-name=<greatgrandparent_process_name> --greatgrandparent-pid=<greatgrandparent_process_pid> --dump-dir=<output_directory>
```
{% endtab %}

{% tab title="undefined" %}
**Dump specific process by name and parent process name and parent process PID and grandparent process name and grandparent process PID and great-grandparent process name and great-grandparent process PID and ancestor process name**
{% endtab %}

{% tab title="undefined" %}
```bash
volatility -f <memory_dump> --profile=<profile> procdump --name=<process_name> --parent-name=<parent_process_name> --parent-pid=<parent_process_pid> --grandparent-name=<grandparent_process_name> --grandparent-pid=<grandparent_process_pid> --greatgrandparent-name=<greatgrandparent_process_name> --greatgrandparent-pid=<greatgrandparent_process_pid> --ancestor-name=<ancestor_process_name> --dump-dir=<output_directory>
```
{% endtab %}

{% tab title="undefined" %}
**Dump specific process by name and parent process name and parent process PID and grandparent process name and grandparent process PID and great-grandparent process name and great-grandparent process PID and ancestor process name and ancestor process PID**
{% endtab %}

{% tab title="undefined" %}
```bash
volatility -f <memory_dump> --profile=<profile> procdump --name=<process_name> --parent-name=<parent_process_name> --parent-pid=<parent_process_pid> --grandparent-name=<grandparent_process_name> --grandparent-pid=<grandparent_process_pid> --greatgrandparent-name=<greatgrandparent_process_name> --greatgrandparent-pid=<greatgrandparent_process_pid> --ancestor-name=<ancestor_process_name> --ancestor-pid=<ancestor_process_pid> --dump-dir=<output_directory>
```
{% endtab %}

{% tab title="undefined" %}
**Dump specific process by name and parent process name and parent process PID and grandparent process name and grandparent process PID and great-grandparent process name and great-grandparent process PID and ancestor process name and ancestor process PID and sibling process name**
{% endtab %}

{% tab title="undefined" %}
```bash
volatility -f <memory_dump> --profile=<profile> procdump --name=<process_name> --parent-name=<parent_process_name> --parent-pid=<parent_process_pid> --grandparent-name=<grandparent_process_name> --grandparent-pid=<grandparent_process_pid> --greatgrandparent-name=<greatgrandparent_process_name> --greatgrandparent-pid=<greatgrandparent_process_pid> --ancestor-name=<ancestor_process_name> --ancestor-pid=<ancestor_process_pid> --sibling-name=<sibling_process_name> --dump-dir=<output_directory>
```
{% endtab %}

{% tab title="undefined" %}
**Dump specific process by name and parent process name and parent process PID and grandparent process name and grandparent process PID and great-grandparent process name and great-grandparent process PID and ancestor process name and ancestor process PID and sibling process name and sibling process PID**
{% endtab %}

{% tab title="undefined" %}
```bash
volatility -f <memory_dump> --profile=<profile> procdump --name=<process_name> --parent-name=<parent_process_name> --parent-pid=<parent_process_pid> --grandparent-name=<grandparent_process_name> --grandparent-pid=<grandparent_process_pid> --greatgrandparent-name=<greatgrandparent_process_name> --greatgrandparent-pid=<greatgrandparent_process_pid> --ancestor-name=<ancestor_process_name> --ancestor-pid=<ancestor_process_pid> --sibling-name=<sibling_process_name> --sibling-pid=<sibling_process_pid> --dump-dir=<output_directory>
```
{% endtab %}

{% tab title="undefined" %}
**Dump specific process by name and parent process name and parent process PID and grandparent process name and grandparent process PID and great-grandparent process name and great-grandparent process PID and ancestor process name and ancestor process PID and sibling process name and sibling process PID and child process name**
{% endtab %}

{% tab title="undefined" %}
```bash
volatility -f <memory_dump> --profile=<profile> procdump --name=<process_name> --parent-name=<parent_process_name> --parent-pid=<parent_process_pid> --grandparent-name=<grandparent_process_name> --grandparent-pid=<grandparent_process_pid> --greatgrandparent-name=<greatgrandparent_process_name> --greatgrandparent-pid=<greatgrandparent_process_pid> --ancestor-name=<ancestor_process_name> --ancestor-pid=<ancestor_process_pid> --sibling-name=<sibling_process_name> --sibling-pid=<sibling_process_pid> --child-name=<child_process_name> --dump-dir=<output_directory>
```
{% endtab %}

{% tab title="undefined" %}
**Dump specific process by name and parent process name and parent process PID and grandparent process name and grandparent process PID and great-grandparent process name and great-grandparent process PID and ancestor process name and ancestor process PID and sibling process name and sibling process PID and child process name and child process PID**
{% endtab %}

{% tab title="undefined" %}
```bash
volatility -f <memory_dump> --profile=<profile> procdump --name=<process_name> --parent-name=<parent_process_name> --parent-pid=<parent_process_pid> --grandparent-name=<grandparent_process_name> --grandparent-pid=<grandparent_process_pid> --greatgrandparent-name=<greatgrandparent_process_name> --greatgrandparent-pid=<greatgrandparent_process_pid> --ancestor-name=<ancestor_process_name> --ancestor-pid=<ancestor_process_pid> --sibling-name=<sibling_process_name> --sibling-pid=<sibling_process_pid> --child-name=<child_process_name> --child-pid=<child_process_pid> --dump-dir=<output_directory>
```
{% endtab %}

{% tab title="undefined" %}
**Dump specific process by name and parent process name and parent process PID and grandparent process name and grandparent process PID and great-grandparent process name and great-grandparent process PID and ancestor process name and ancestor process PID and sibling process name and sibling process PID and child process name and child process PID and grandchild process name**
{% endtab %}

{% tab title="undefined" %}
```bash
volatility -f <memory_dump> --profile=<profile> procdump --name=<process_name> --parent-name=<parent_process_name> --parent-pid=<parent_process_pid> --grandparent-name=<grandparent_process_name> --grandparent-pid=<grandparent_process_pid> --greatgrandparent-name=<greatgrandparent_process_name> --greatgrandparent-pid=<greatgrandparent_process_pid> --ancestor-name=<ancestor_process_name> --ancestor-pid=<ancestor_process_pid> --sibling-name=<sibling_process_name> --sibling-pid=<sibling_process_pid> --child-name=<child_process_name> --child-pid=<child_process_pid> --grandchild-name=<grandchild_process_name> --dump-dir=<output_directory>
```
{% endtab %}

{% tab title="undefined" %}
**Dump specific process by name and parent process name and parent process PID and grandparent process name and grandparent process PID and great-grandparent process name and great-grandparent process PID and ancestor process name and ancestor process PID and sibling process name and sibling process PID and child process name and child process PID and grandchild process name and grandchild process PID**
{% endtab %}

{% tab title="undefined" %}
```bash
volatility -f <memory_dump> --profile=<profile> procdump --name=<process_name> --parent-name=<parent_process_name> --parent-pid=<parent_process_pid> --grandparent-name=<grandparent_process_name> --grandparent-pid=<grandparent_process_pid> --greatgrandparent-name=<greatgrandparent_process_name> --greatgrandparent-pid=<greatgrandparent_process_pid> --ancestor-name=<ancestor_process_name> --ancestor-pid=<ancestor_process_pid> --sibling-name=<sibling_process_name> --sibling-pid=<sibling_process_pid> --child-name=<child_process_name> --child-pid=<child_process_pid> --grandchild-name=<grandchild_process_name> --grandchild-pid=<grandchild_process_pid> --dump-dir=<output_directory>
```
{% endtab %}

{% tab title="undefined" %}
**Dump specific process by name and parent process name and parent process PID and grandparent process name and grandparent process PID and great-grandparent process name and great-grandparent process PID and ancestor process name and ancestor process PID and sibling process name and sibling process PID and child process name and child process PID and grandchild process name and grandchild process PID and great-grandchild process name**
{% endtab %}

{% tab title="undefined" %}
```bash
volatility -f <memory_dump> --profile=<profile> procdump --name=<process_name> --parent-name=<parent_process_name> --parent-pid=<parent_process_pid> --grandparent-name=<grandparent_process_name> --grandparent-pid=<grandparent_process_pid> --greatgrandparent-name=<greatgrandparent_process_name> --greatgrandparent-pid=<greatgrandparent_process_pid> --ancestor-name=<ancestor_process_name> --ancestor-pid=<ancestor_process_pid> --sibling-name=<sibling_process_name> --sibling-pid=<sibling_process_pid> --child-name=<child_process_name> --child-pid=<child_process_pid> --grandchild-name=<grandchild_process_name> --grandchild-pid=<grandchild_process_pid> --greatgrandchild-name=<greatgrandchild_process_name> --dump-dir=<output_directory>
```
{% endtab %}

{% tab title="undefined" %}
**Dump specific process by name and parent process name and parent process PID and grandparent process name and grandparent process PID and great-grandparent process name and great-grandparent process PID and ancestor process name and ancestor process PID and sibling process name and sibling process PID and child process name and child process PID and grandchild process name and grandchild process PID and great-grandchild process name and great-grandchild process PID and ancestor process name**
{% endtab %}

{% tab title="undefined" %}
```bash
volatility -f <memory_dump> --profile=<profile> procdump --name=<process_name> --parent-name=<parent_process_name> --parent-pid=<parent_process_pid> --grandparent-name=<grandparent_process_name> --grandparent-pid=<grandparent_process_pid> --greatgrandparent-name=<greatgrandparent_process_name> --greatgrandparent-pid=<greatgrandparent_process_pid> --ancestor-name=<ancestor_process_name> --ancestor-pid=<ancestor_process_pid> --sibling-name=<sibling_process_name> --sibling-pid=<sibling_process_pid> --child-name=<child_process_name> --child-pid=<child_process_pid> --grandchild-name=<grandchild_process_name> --grandchild-pid=<grandchild_process_pid> --greatgrandchild-name=<greatgrandchild_process_name> --ancestor-name=<ancestor_process_name> --dump-dir=<output_directory>
```
{% endtab %}

{% tab title="undefined" %}
**Dump specific process by name and parent process name and parent process PID and grandparent process name and grandparent process PID and great-grandparent process name and great-grandparent process PID and ancestor process name and ancestor process PID and sibling process name and sibling process PID and child process name and child process PID and grandchild process name and grandchild process PID and great-grandchild process name and great-grandchild process PID and ancestor process name and ancestor process PID**
{% endtab %}

{% tab title="undefined" %}
```bash
volatility -f <memory_dump> --profile=<profile> procdump --name=<process_name> --parent-name=<parent_process_name> --parent-pid=<parent_process_pid> --grandparent-name=<grandparent_process_name> --grandparent-pid=<grandparent_process_pid> --greatgrandparent-name=<greatgrandparent_process_name> --greatgrandparent-pid=<greatgrandparent_process_pid> --ancestor-name=<ancestor_process_name> --ancestor-pid=<ancestor_process_pid> --sibling-name=<sibling_process_name> --sibling-pid=<sibling_process_pid> --child-name=<child_process_name> --child-pid=<child_process_pid> --grandchild-name=<grandchild_process_name> --grandchild-pid=<grandchild_process_pid> --greatgrandchild-name=<greatgrandchild_process_name> --ancestor-name=<ancestor_process_name> --ancestor-pid=<ancestor_process_pid> --dump-dir=<output_directory>
```
{% endtab %}

{% tab title="undefined" %}
**Dump specific process by name and parent process name and parent process PID and grandparent process name and grandparent process PID and great-grandparent process name and great-grandparent process PID and ancestor process name and ancestor process PID and sibling process name and sibling process PID and child process name and child process PID and grandchild process name and grandchild process PID and great-grandchild process name and great-grandchild process PID and ancestor process name and ancestor process PID and sibling process name**
{% endtab %}

{% tab title="undefined" %}
```bash
volatility -f <memory_dump> --profile=<profile> procdump --name=<process_name> --parent-name=<parent_process_name> --parent-pid=<parent_process_pid> --grandparent-name=<grandparent_process_name> --grandparent-pid=<grandparent_process_pid> --greatgrandparent-name=<greatgrandparent_process_name> --greatgrandparent-pid=<greatgrandparent_process_pid> --ancestor-name=<ancestor_process_name> --ancestor-pid=<ancestor_process_pid> --sibling-name=<sibling_process_name> --sibling-pid=<sibling_process_pid> --child-name=<child_process_name> --child-pid=<child_process_pid> --grandchild-name=<grandchild_process_name> --grandchild-pid=<grandchild_process_pid> --greatgrandchild-name=<greatgrandchild_process_name> --ancestor-name=<ancestor_process_name> --ancestor-pid=<ancestor_process_pid> --sibling-name=<sibling_process_name> --dump-dir=<output_directory>
```
{% endtab %}

{% tab title="undefined" %}
**Dump specific process by name and parent process name and parent process PID and grandparent process name and grandparent process PID and great-grandparent process name and great-grandparent process PID and ancestor process name and ancestor process PID and sibling process name and sibling process PID and child process name and child process PID and grandchild process name and grandchild process PID and great-grandchild process name and great-grandchild process PID and ancestor process name and ancestor process PID and sibling process name and sibling process PID**
{% endtab %}

{% tab title="undefined" %}
```bash
volatility -f <memory_dump> --profile=<profile> procdump --name=<process_name> --parent-name=<parent_process_name> --parent-pid=<parent_process_pid> --grandparent-name=<grandparent_process_name> --grandparent-pid=<grandparent_process_pid> --greatgrandparent-name=<greatgrandparent_process_name> --greatgrandparent-pid=<greatgrandparent_process_pid> --ancestor-name=<ancestor_process_name> --ancestor-pid=<ancestor_process_pid> --sibling-name=<sibling_process_name> --sibling-pid=<sibling_process_pid> --child-name=<child_process_name> --child-pid=<child_process_pid> --grandchild-name=<grandchild_process_name> --grandchild-pid=<grandchild_process_pid> --greatgrandchild-name=<greatgrandchild_process_name> --ancestor-name=<ancestor_process_name> --ancestor-pid=<ancestor_process_pid> --sibling-name=<sibling_process_name> --sibling-pid=<sibling_process_pid> --dump-dir=<output_directory>
```
{% endtab %}

{% tab title="undefined" %}
**Dump specific process by name and parent process name and parent process PID and grandparent process name and grandparent process PID and great-grandparent process name and great-grandparent process PID and ancestor process name and ancestor process PID and sibling process name and sibling process PID and child process name and child process PID and grandchild process name and grandchild process PID and great-grandchild process name and great-grandchild process PID and ancestor process name and ancestor process PID and sibling process name and sibling process PID and child process name**
{% endtab %}

{% tab title="undefined" %}
````bash
volatility -f <memory_dump> --profile=<profile> procdump --name=<process_name> --parent-name=<parent_process_name> --parent-pid=<parent_process_pid> --grandparent-name=<
```bash
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory
````
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 procdump --pid=3152 -n --dump-dir=. -f file.dmp
```
{% endtab %}
{% endtabs %}
{% endtab %}

{% tab title="undefined" %}
#### Wiersz poleceń
{% endtab %}

{% tab title="undefined" %}
Czy coś podejrzanego zostało wykonane?
{% endtab %}

{% tab title="undefined" %}
```bash
python3 vol.py -f file.dmp windows.cmdline.CmdLine #Display process command-line arguments
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=PROFILE cmdline -f file.dmp #Display process command-line arguments
volatility --profile=PROFILE consoles -f file.dmp #command history by scanning for _CONSOLE_INFORMATION
```
{% endtab %}
{% endtabs %}

Polecenia wykonane w `cmd.exe` są zarządzane przez **`conhost.exe`** (lub `csrss.exe` w systemach przed Windows 7). Oznacza to, że jeśli **`cmd.exe`** zostanie zakończony przez atakującego przed uzyskaniem zrzutu pamięci, wciąż można odzyskać historię poleceń sesji z pamięci **`conhost.exe`**. Aby to zrobić, jeśli wykryto nietypową aktywność w modułach konsoli, należy wykonać zrzut pamięci powiązanego procesu **`conhost.exe`**. Następnie, wyszukując **ciągi znaków** w tym zrzucie, można potencjalnie wyodrębnić używane w sesji linie poleceń.

### Środowisko

Pobierz zmienne środowiskowe każdego działającego procesu. Mogą być tam interesujące wartości.

{% tabs %}
{% tab title="undefined" %}
```bash
python3 vol.py -f file.dmp windows.envars.Envars [--pid <pid>] #Display process environment variables
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=PROFILE envars -f file.dmp [--pid <pid>] #Display process environment variables

volatility --profile=PROFILE -f file.dmp linux_psenv [-p <pid>] #Get env of process. runlevel var means the runlevel where the proc is initated
```
{% endtab %}
{% endtabs %}

### Przywileje tokena

Sprawdź, czy w nieoczekiwanych usługach występują tokeny uprawnień.\
Być może warto jest wymienić procesy korzystające z pewnego uprzywilejowanego tokenu.

```bash
#Get enabled privileges of some processes
python3 vol.py -f file.dmp windows.privileges.Privs [--pid <pid>]
#Get all processes with interesting privileges
python3 vol.py -f file.dmp windows.privileges.Privs | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```

```bash
#Get enabled privileges of some processes
volatility --profile=Win7SP1x86_23418 privs --pid=3152 -f file.dmp | grep Enabled
#Get all processes with interesting privileges
volatility --profile=Win7SP1x86_23418 privs -f file.dmp | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```

### SIDs

Sprawdź każde SSID posiadane przez proces.\
Może być interesujące wymienić procesy korzystające z SID uprawnień (oraz procesy korzystające z pewnego SID usługi).

{% tabs %}
{% tab title="undefined" %}
```bash
./vol.py -f file.dmp windows.getsids.GetSIDs [--pid <pid>] #Get SIDs of processes
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 getsids -f file.dmp #Get the SID owned by each process
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp #Get the SID of each service
```
{% endtab %}
{% endtabs %}

### Uchwyty

Przydatne do sprawdzenia, do których innych plików, kluczy, wątków, procesów... **proces ma uchwyt** (jest otwarty)

```bash
vol.py -f file.dmp windows.handles.Handles [--pid <pid>]
```

```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp handles [--pid=<pid>]
```

### Biblioteki DLL

{% tabs %}
{% tab title="undefined" %}
```bash
./vol.py -f file.dmp windows.dlllist.DllList [--pid <pid>] #List dlls used by each
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory process
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 dlllist --pid=3152 -f file.dmp #Get dlls of a proc
volatility --profile=Win7SP1x86_23418 dlldump --pid=3152 --dump-dir=. -f file.dmp #Dump dlls of a proc
```
{% endtab %}
{% endtabs %}

### Ciągi znaków dla procesów

Volatility pozwala nam sprawdzić, do którego procesu należy dany ciąg znaków.

{% tabs %}
{% tab title="undefined" %}
```bash
strings file.dmp > /tmp/strings.txt
./vol.py -f /tmp/file.dmp windows.strings.Strings --strings-file /tmp/strings.txt
```
{% endtab %}

{% tab title="vol2" %}
```bash
strings file.dmp > /tmp/strings.txt
volatility -f /tmp/file.dmp windows.strings.Strings --string-file /tmp/strings.txt

volatility -f /tmp/file.dmp --profile=Win81U1x64 memdump -p 3532 --dump-dir .
strings 3532.dmp > strings_file
```
{% endtab %}
{% endtabs %}

Pozwala również na wyszukiwanie ciągów znaków wewnątrz procesu za pomocą modułu yarascan:

{% tabs %}
{% tab title="undefined" %}
```bash
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-rules "https://" --pid 3692 3840 3976 3312 3084 2784
./vol.py -f file.dmp yarascan.YaraScan --yara-rules "https://"
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 yarascan -Y "https://" -p 3692,3840,3976,3312,3084,2784
```
{% endtab %}
{% endtabs %}

### UserAssist

**Windows** śledzi programy, które uruchamiasz za pomocą funkcji w rejestrze o nazwie **klucze UserAssist**. Te klucze rejestru zapisują, ile razy każdy program został uruchomiony i kiedy ostatnio był uruchamiany.

```bash
./vol.py -f file.dmp windows.registry.userassist.UserAssist
```

```
volatility --profile=Win7SP1x86_23418 -f file.dmp userassist
```

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​[**RootedCON**](https://www.rootedcon.com/) to najważniejsze wydarzenie związane z cyberbezpieczeństwem w **Hiszpanii** i jedno z najważniejszych w **Europie**. Mając na celu promowanie wiedzy technicznej, ten kongres jest gorącym punktem spotkań dla profesjonalistów technologii i cyberbezpieczeństwa we wszystkich dziedzinach.

{% embed url="https://www.rootedcon.com/" %}

## Usługi

{% tabs %}
{% tab title="undefined" %}
```bash
./vol.py -f file.dmp windows.svcscan.SvcScan #List services
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
{% endtab %}

{% tab title="undefined" %}
```bash
#Get services and binary path
volatility --profile=Win7SP1x86_23418 svcscan -f file.dmp
#Get name of the services and SID (slow)
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp
```
{% endtab %}

{% tab title="vol3" %}
### Sieć
{% endtab %}

{% tab title="undefined" %}
```bash
./vol.py -f file.dmp windows.netscan.NetScan
#For network info of linux use volatility2
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 netscan -f file.dmp
volatility --profile=Win7SP1x86_23418 connections -f file.dmp#XP and 2003 only
volatility --profile=Win7SP1x86_23418 connscan -f file.dmp#TCP connections
volatility --profile=Win7SP1x86_23418 sockscan -f file.dmp#Open sockets
volatility --profile=Win7SP1x86_23418 sockets -f file.dmp#Scanner for tcp socket objects

volatility --profile=SomeLinux -f file.dmp linux_ifconfig
volatility --profile=SomeLinux -f file.dmp linux_netstat
volatility --profile=SomeLinux -f file.dmp linux_netfilter
volatility --profile=SomeLinux -f file.dmp linux_arp #ARP table
volatility --profile=SomeLinux -f file.dmp linux_list_raw #Processes using promiscuous raw sockets (comm between processes)
volatility --profile=SomeLinux -f file.dmp linux_route_cache
```
{% endtab %}
{% endtabs %}

## Rejestr hive

### Wyświetl dostępne hives

{% tabs %}
{% tab title="undefined" %}
```bash
./vol.py -f file.dmp windows.registry.hivelist.HiveList #List roots
./vol.py -f file.dmp windows.registry.printkey.PrintKey #List roots and get initial subkeys
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp hivelist #List roots
volatility --profile=Win7SP1x86_23418 -f file.dmp printkey #List roots and get initial subkeys
```
{% endtab %}
{% endtabs %}

### Uzyskaj wartość

{% tabs %}
{% tab title="undefined" %}
```bash
./vol.py -f file.dmp windows.registry.printkey.PrintKey --key "Software\Microsoft\Windows NT\CurrentVersion"
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 printkey -K "Software\Microsoft\Windows NT\CurrentVersion" -f file.dmp
# Get Run binaries registry value
volatility -f file.dmp --profile=Win7SP1x86 printkey -o 0x9670e9d0 -K 'Software\Microsoft\Windows\CurrentVersion\Run'
```
{% endtab %}
{% endtabs %}

### Zrzut pamięci

```bash
#Dump a hive
volatility --profile=Win7SP1x86_23418 hivedump -o 0x9aad6148 -f file.dmp #Offset extracted by hivelist
#Dump all hives
volatility --profile=Win7SP1x86_23418 hivedump -f file.dmp
```

## System plików

### Montowanie

{% tabs %}
{% tab title="undefined" %}
```bash
#See vol2
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=SomeLinux -f file.dmp linux_mount
volatility --profile=SomeLinux -f file.dmp linux_recover_filesystem #Dump the entire filesystem (if possible)
```
{% endtab %}
{% endtabs %}

### Skanowanie/zrzut

{% tabs %}
{% tab title="undefined" %}
```bash
./vol.py -f file.dmp windows.filescan.FileScan #Scan for files inside the dump
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --physaddr <0xAAAAA> #Offset from previous command
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 filescan -f file.dmp #Scan for files inside the dump
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -f file.dmp #Dump all files
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -Q 0x000000007dcaa620 -f file.dmp

volatility --profile=SomeLinux -f file.dmp linux_enumerate_files
volatility --profile=SomeLinux -f file.dmp linux_find_file -F /path/to/file
volatility --profile=SomeLinux -f file.dmp linux_find_file -i 0xINODENUMBER -O /path/to/dump/file
```
{% endtab %}
{% endtabs %}

### Master File Table

{% tabs %}
{% tab title="undefined" %}
**MFT Parser**
{% endtab %}

{% tab title="undefined" %}
The MFT parser plugin in Volatility allows you to analyze the Master File Table (MFT) in a memory dump. The MFT is a database that stores information about files and directories on an NTFS file system. By analyzing the MFT, you can gather valuable information such as file names, creation dates, modification dates, and file sizes.
{% endtab %}

{% tab title="undefined" %}
To use the MFT parser plugin, you need to specify the address of the MFT in the memory dump. You can find this address by running the `mftparser` command with the `--info` option. This will display information about the MFT, including its address.
{% endtab %}

{% tab title="undefined" %}
Once you have the MFT address, you can run the `mftparser` command with the `--mft` option followed by the MFT address. This will parse the MFT and display the information stored in it.
{% endtab %}

{% tab title="undefined" %}
Here is an example of how to use the MFT parser plugin:
{% endtab %}

{% tab title="undefined" %}
```
volatility -f memory.dmp --profile=Win7SP1x64 mftparser --mft 0x12345678
```
{% endtab %}

{% tab title="undefined" %}
Replace `memory.dmp` with the path to your memory dump file, `Win7SP1x64` with the appropriate profile for your memory dump, and `0x12345678` with the address of the MFT.
{% endtab %}

{% tab title="undefined" %}
**MFT Parser Output**
{% endtab %}

{% tab title="undefined" %}
The output of the MFT parser plugin includes information about each file and directory in the MFT. This information is displayed in a tabular format, with columns for the file name, creation date, modification date, and file size.
{% endtab %}

{% tab title="undefined" %}
Here is an example of the output:
{% endtab %}

{% tab title="undefined" %}
```
File Name    Creation Date       Modification Date    File Size
-----------  ------------------  ------------------  ---------
file1.txt    2020-01-01 10:00   2020-01-02 15:30    1024 bytes
file2.txt    2020-01-03 12:00   2020-01-04 09:45    2048 bytes
directory1   2020-01-05 09:00   2020-01-06 14:20    -
```
{% endtab %}

{% tab title="undefined" %}
In this example, there are two files (`file1.txt` and `file2.txt`) and one directory (`directory1`) in the MFT. The file names, creation dates, modification dates, and file sizes are displayed for each entry.
{% endtab %}

{% tab title="undefined" %}
**MFT Parser Options**
{% endtab %}

{% tab title="undefined" %}
The MFT parser plugin supports several options that allow you to customize its behavior. Here are some of the most commonly used options:
{% endtab %}

{% tab title="undefined" %}
* `--output`: Specifies the format of the output. The default format is tabular, but you can also choose to output the results in CSV or JSON format.
* `--output-file`: Specifies the file to which the output should be written. By default, the output is displayed on the screen, but you can redirect it to a file using this option.
* `--filter`: Specifies a filter to apply to the MFT entries. You can use this option to only display entries that match a specific criteria, such as a certain file name or file size.
{% endtab %}

{% tab title="undefined" %}
For a complete list of options, you can run the `mftparser` command with the `--help` option.
{% endtab %}

{% tab title="undefined" %}
**MFT Parser Example**
{% endtab %}

{% tab title="undefined" %}
Here is an example of how to use the MFT parser plugin with some of the options mentioned above:
{% endtab %}

{% tab title="undefined" %}
```
volatility -f memory.dmp --profile=Win7SP1x64 mftparser --mft 0x12345678 --output csv --output-file mft.csv --filter "file size > 1000"
```
{% endtab %}

{% tab title="undefined" %}
This command will parse the MFT at address `0x12345678` in the memory dump file `memory.dmp` using the `Win7SP1x64` profile. It will output the results in CSV format and write them to the file `mft.csv`. It will also only display entries with a file size greater than 1000 bytes.
{% endtab %}

{% tab title="undefined" %}
**Conclusion**
{% endtab %}

{% tab title="undefined" %}
The MFT parser plugin in Volatility is a powerful tool for analyzing the Master File Table in a memory dump. By using this plugin, you can extract valuable information about files and directories, such as file names, creation dates, modification dates, and file sizes. This information can be useful for forensic analysis and investigation purposes.
{% endtab %}

{% tab title="undefined" %}
```bash
# I couldn't find any plugin to extract this information in volatility3
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 mftparser -f file.dmp
```
{% endtab %}
{% endtabs %}

System plików **NTFS** wykorzystuje kluczowy komponent znany jako _master file table_ (MFT). Ta tabela zawiera co najmniej jeden wpis dla każdego pliku na woluminie, obejmując również samą MFT. Istotne szczegóły dotyczące każdego pliku, takie jak **rozmiar, znaczniki czasu, uprawnienia i rzeczywiste dane**, są zawarte w wpisach MFT lub w obszarach zewnętrznych dla MFT, ale do których odwołują się te wpisy. Więcej szczegółów można znaleźć w [oficjalnej dokumentacji](https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table).

### Klucze/Certyfikaty SSL

{% tabs %}
{% tab title="undefined" %}
```bash
#vol3 allows to search for certificates inside the registry
./vol.py -f file.dmp windows.registry.certificates.Certificates
```
{% endtab %}

{% tab title="undefined" %}
```bash
#vol2 allos you to search and dump certificates from memory
#Interesting options for this modules are: --pid, --name, --ssl
volatility --profile=Win7SP1x86_23418 dumpcerts --dump-dir=. -f file.dmp
```
{% endtab %}

{% tab title="undefined" %}
### Złośliwe oprogramowanie
{% endtab %}

{% tab title="undefined" %}
{% tabs %}
{% tab title="undefined" %}
```bash
./vol.py -f file.dmp windows.malfind.Malfind [--dump] #Find hidden and injected code, [dump each suspicious section]
#Malfind will search for suspicious structures related to malware
./vol.py -f file.dmp windows.driverirp.DriverIrp #Driver IRP hook detection
./vol.py -f file.dmp windows.ssdt.SSDT #Check system call address from unexpected addresses

./vol.py -f file.dmp linux.check_afinfo.Check_afinfo #Verifies the operation function pointers of network protocols
./vol.py -f file.dmp linux.check_creds.Check_creds #Checks if any processes are sharing credential structures
./vol.py -f file.dmp linux.check_idt.Check_idt #Checks if the IDT has been altered
./vol.py -f file.dmp linux.check_syscall.Check_syscall #Check system call table for hooks
./vol.py -f file.dmp linux.check_modules.Check_modules #Compares module list to sysfs info, if available
./vol.py -f file.dmp linux.tty_check.tty_check #Checks tty devices for hooks
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp malfind [-D /tmp] #Find hidden and injected code [dump each suspicious section]
volatility --profile=Win7SP1x86_23418 -f file.dmp apihooks #Detect API hooks in process and kernel memory
volatility --profile=Win7SP1x86_23418 -f file.dmp driverirp #Driver IRP hook detection
volatility --profile=Win7SP1x86_23418 -f file.dmp ssdt #Check system call address from unexpected addresses

volatility --profile=SomeLinux -f file.dmp linux_check_afinfo
volatility --profile=SomeLinux -f file.dmp linux_check_creds
volatility --profile=SomeLinux -f file.dmp linux_check_fop
volatility --profile=SomeLinux -f file.dmp linux_check_idt
volatility --profile=SomeLinux -f file.dmp linux_check_syscall
volatility --profile=SomeLinux -f file.dmp linux_check_modules
volatility --profile=SomeLinux -f file.dmp linux_check_tty
volatility --profile=SomeLinux -f file.dmp linux_keyboard_notifiers #Keyloggers
```
{% endtab %}
{% endtabs %}
{% endtab %}

{% tab title="undefined" %}
#### Skanowanie za pomocą yara
{% endtab %}

{% tab title="undefined" %}
Użyj tego skryptu, aby pobrać i połączyć wszystkie zasady malware yara z githuba: [https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9](https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9)\
Utwórz katalog _**rules**_ i go uruchom. Spowoduje to utworzenie pliku o nazwie _**malware\_rules.yar**_, który zawiera wszystkie zasady yara dla malware.
{% endtab %}

{% tab title="undefined" %}
```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
#Only Windows
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-file /tmp/malware_rules.yar
#All
./vol.py -f file.dmp yarascan.YaraScan --yara-file /tmp/malware_rules.yar
```
{% endtab %}

{% tab title="vol2" %}
```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
volatility --profile=Win7SP1x86_23418 yarascan -y malware_rules.yar -f ch2.dmp | grep "Rule:" | grep -v "Str_Win32" | sort | uniq
```
{% endtab %}
{% endtabs %}

## MISC

### Wtyczki zewnętrzne

Jeśli chcesz używać wtyczek zewnętrznych, upewnij się, że foldery związane z wtyczkami są pierwszym parametrem używanym.

```bash
./vol.py --plugin-dirs "/tmp/plugins/" [...]
```

```bash
volatilitye --plugins="/tmp/plugins/" [...]
```

#### Autoruns

Pobierz go z [https://github.com/tomchop/volatility-autoruns](https://github.com/tomchop/volatility-autoruns)

```
volatility --plugins=volatility-autoruns/ --profile=WinXPSP2x86 -f file.dmp autoruns
```

### Mutexy

{% tabs %}
{% tab title="undefined" %}
```
./vol.py -f file.dmp windows.mutantscan.MutantScan
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 mutantscan -f file.dmp
volatility --profile=Win7SP1x86_23418 -f file.dmp handles -p <PID> -t mutant
```
{% endtab %}
{% endtabs %}

### Symlinki

{% tabs %}
{% tab title="undefined" %}
```bash
./vol.py -f file.dmp windows.symlinkscan.SymlinkScan
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp symlinkscan
```
{% endtab %}
{% endtabs %}

### Bash

Możliwe jest **odczytanie historii poleceń bash z pamięci.** Można również wyeksportować plik _.bash\_history_, ale jeśli jest on wyłączony, będziesz zadowolony, że możesz skorzystać z tego modułu w narzędziu Volatility.

```
./vol.py -f file.dmp linux.bash.Bash
```

```
volatility --profile=Win7SP1x86_23418 -f file.dmp linux_bash
```

### Harmonogram

{% tabs %}
{% tab title="undefined" %}
```bash
./vol.py -f file.dmp timeLiner.TimeLiner
```
{% endtab %}

{% tab title="vol2" %}
```
volatility --profile=Win7SP1x86_23418 -f timeliner
```
{% endtab %}
{% endtabs %}

### Sterowniki

{% tabs %}
{% tab title="undefined" %}
```
./vol.py -f file.dmp windows.driverscan.DriverScan
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp driverscan
```
{% endtab %}
{% endtabs %}

### Pobierz schowek

```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 clipboard -f file.dmp
```

### Pobierz historię przeglądarki Internet Explorer

```bash
volatility -f <memory_dump> --profile=<profile> iehistory
```

### Get IE cookies

```bash
volatility -f <memory_dump> --profile=<profile> iecookies
```

### Get IE typed URLs

```bash
volatility -f <memory_dump> --profile=<profile> ietypedurls
```

### Get IE search queries

```bash
volatility -f <memory_dump> --profile=<profile> iesearch
```

### Get IE form data

```bash
volatility -f <memory_dump> --profile=<profile> ieforms
```

### Get IE saved passwords

```bash
volatility -f <memory_dump> --profile=<profile> iepwd
```

### Get IE autocomplete data

```bash
volatility -f <memory_dump> --profile=<profile> ieautocomplete
```

### Get IE open tabs

```bash
volatility -f <memory_dump> --profile=<profile> ieopenpages
```

### Get IE download history

```bash
volatility -f <memory_dump> --profile=<profile> iedownloadhistory
```

### Get IE cache entries

```bash
volatility -f <memory_dump> --profile=<profile> iecache
```

### Get IE DOM storage

```bash
volatility -f <memory_dump> --profile=<profile> iedomstorage
```

### Get IE zones

```bash
volatility -f <memory_dump> --profile=<profile> iezones
```

### Get IE extensions

```bash
volatility -f <memory_dump> --profile=<profile> ieext
```

### Get IE ActiveX controls

```bash
volatility -f <memory_dump> --profile=<profile> ieactivex
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

```bash
volatility -f <memory_dump> --profile=<profile> ietoolbars
```

### Get IE browser helper objects

```bash
volatility -f <memory_dump> --profile=<profile> iebho
```

### Get IE toolbars

````bash
volatility -f <memory_dump> --profile=<
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 iehistory -f file.dmp
````

### Pobierz tekst z notatnika

```bash
volatility -f memory_dump.mem notepad
```

### Get clipboard text

### Pobierz tekst ze schowka

```bash
volatility -f memory_dump.mem clipboard
```

### Get command history

### Pobierz historię poleceń

```bash
volatility -f memory_dump.mem cmdscan
```

### Get network connections

### Pobierz połączenia sieciowe

```bash
volatility -f memory_dump.mem netscan
```

### Get running processes

### Pobierz uruchomione procesy

```bash
volatility -f memory_dump.mem pslist
```

### Get loaded modules

### Pobierz załadowane moduły

```bash
volatility -f memory_dump.mem modules
```

### Get open files

### Pobierz otwarte pliki

```bash
volatility -f memory_dump.mem handles
```

### Get registry hives

### Pobierz pliki rejestru

```bash
volatility -f memory_dump.mem hivelist
```

### Get user accounts

### Pobierz konta użytkowników

```bash
volatility -f memory_dump.mem useraccounts
```

### Get system information

### Pobierz informacje o systemie

```bash
volatility -f memory_dump.mem sysinfo
```

### Get network connections

### Pobierz połączenia sieciowe

```bash
volatility -f memory_dump.mem netscan
```

### Get network sockets

### Pobierz gniazda sieciowe

```bash
volatility -f memory_dump.mem sockets
```

### Get network routes

### Pobierz trasy sieciowe

```bash
volatility -f memory_dump.mem routes
```

### Get network interfaces

### Pobierz interfejsy sieciowe

```bash
volatility -f memory_dump.mem ifconfig
```

### Get loaded drivers

### Pobierz załadowane sterowniki

```bash
volatility -f memory_dump.mem driverscan
```

### Get kernel modules

### Pobierz moduły jądra

```bash
volatility -f memory_dump.mem modscan
```

### Get system services

### Pobierz usługi systemowe

```bash
volatility -f memory_dump.mem svcscan
```

### Get scheduled tasks

### Pobierz zaplanowane zadania

```bash
volatility -f memory_dump.mem schedtasks
```

### Get event logs

### Pobierz dzienniki zdarzeń

```bash
volatility -f memory_dump.mem evtlogs
```

### Get registry keys

### Pobierz klucze rejestru

```bash
volatility -f memory_dump.mem printkey -K "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
```

### Get file metadata

### Pobierz metadane pliku

```bash
volatility -f memory_dump.mem filescan
```

### Get file contents

### Pobierz zawartość pliku

```bash
volatility -f memory_dump.mem dumpfiles -Q 0x0000000001a2b3c4 -D .
```

```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 notepad -f file.dmp
```

### Zrzut ekranu

```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 screenshot -f file.dmp
```

### Master Boot Record (MBR)

### Rekord głównego rozruchowego (MBR)

The Master Boot Record (MBR) is the first sector of a storage device (such as a hard disk) that contains the boot loader and partition table. It plays a crucial role in the boot process of a computer.

Rekord głównego rozruchowego (MBR) to pierwszy sektor urządzenia pamięci masowej (takiego jak dysk twardy), który zawiera program rozruchowy i tabelę partycji. Odgrywa on kluczową rolę w procesie uruchamiania komputera.

When a computer starts up, the BIOS (Basic Input/Output System) reads the MBR from the storage device and transfers control to the boot loader code stored in the MBR. The boot loader then loads the operating system into memory and starts its execution.

Podczas uruchamiania komputera BIOS (Basic Input/Output System) odczytuje MBR z urządzenia pamięci masowej i przekazuje kontrolę do kodu programu rozruchowego przechowywanego w MBR. Następnie program rozruchowy wczytuje system operacyjny do pamięci i rozpoczyna jego wykonanie.

The MBR also contains the partition table, which defines the layout of the storage device and the location of each partition. This information is crucial for the operating system to access and manage the data stored on the device.

MBR zawiera również tabelę partycji, która definiuje układ urządzenia pamięci masowej oraz położenie każdej partycji. Ta informacja jest kluczowa dla systemu operacyjnego w celu dostępu i zarządzania danymi przechowywanymi na urządzeniu.

During forensic analysis, examining the MBR can provide valuable information about the storage device, such as the number and size of partitions, the file system used, and the presence of any bootkits or other malicious code.

Podczas analizy śledczej badanie MBR może dostarczyć cennych informacji na temat urządzenia pamięci masowej, takich jak liczba i rozmiar partycji, używany system plików oraz obecność jakichkolwiek bootkitów lub innych złośliwych kodów.

Volatility provides several plugins that can be used to analyze the MBR in a memory dump. These plugins can extract information about the partition table, boot loader code, and other relevant data.

Volatility udostępnia kilka wtyczek, które można użyć do analizy MBR w dumpie pamięci. Te wtyczki mogą wyodrębnić informacje dotyczące tabeli partycji, kodu programu rozruchowego i innych istotnych danych.

```bash
volatility --profile=Win7SP1x86_23418 mbrparser -f file.dmp
```

**Master Boot Record (MBR)** odgrywa kluczową rolę w zarządzaniu logicznymi partycjami nośnika pamięci, które są strukturalnie zorganizowane z różnymi [systemami plików](https://en.wikipedia.org/wiki/File\_system). Nie tylko przechowuje informacje o układzie partycji, ale także zawiera kod wykonywalny działający jako ładowacz rozruchowy. Ten ładowacz rozruchowy albo bezpośrednio inicjuje proces drugiego etapu ładowania systemu operacyjnego (patrz [ładowacz drugiego etapu](https://en.wikipedia.org/wiki/Second-stage\_boot\_loader)), albo współpracuje z [rekordem rozruchowym woluminu](https://en.wikipedia.org/wiki/Volume\_boot\_record) (VBR) każdej partycji. Aby uzyskać szczegółowe informacje, odwołaj się do strony [Wikipedia MBR](https://en.wikipedia.org/wiki/Master\_boot\_record).

## Odwołania

* [https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/](https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/)
* [https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html](https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html)
* [https://or10nlabs.tech/cgi-sys/suspendedpage.cgi](https://or10nlabs.tech/cgi-sys/suspendedpage.cgi)
* [https://www.aldeid.com/wiki/Windows-userassist-keys](https://www.aldeid.com/wiki/Windows-userassist-keys) ​\* [https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table](https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table)
* [https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa](https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) to najważniejsze wydarzenie związane z cyberbezpieczeństwem w **Hiszpanii** i jedno z najważniejszych w **Europie**. Mając na celu promowanie wiedzy technicznej, ten kongres stanowi gorące miejsce spotkań dla profesjonalistów technologii i cyberbezpieczeństwa we wszystkich dziedzinach.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi trikami hakerskimi, przesyłając PR do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
