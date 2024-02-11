# FISSURE - Framework RF

**Niezależne od częstotliwości zrozumienie sygnałów opartych na SDR i inżynieria wsteczna**

FISSURE to otwarte oprogramowanie do inżynierii wstecznej i RF, zaprojektowane dla wszystkich poziomów umiejętności, z możliwościami wykrywania i klasyfikacji sygnałów, odkrywania protokołów, wykonywania ataków, manipulacji IQ, analizy podatności, automatyzacji oraz AI/ML. Framework został stworzony w celu promowania szybkiej integracji modułów oprogramowania, radiów, protokołów, danych sygnałowych, skryptów, grafów przepływu, materiałów referencyjnych i narzędzi firm trzecich. FISSURE to narzędzie ułatwiające pracę, które umożliwia przechowywanie oprogramowania w jednym miejscu i pozwala zespołom łatwo nadążyć za postępem, jednocześnie udostępniając tę samą sprawdzoną konfigurację podstawową dla określonych dystrybucji Linuxa.

Framework i narzędzia zawarte w FISSURE są przeznaczone do wykrywania obecności energii RF, zrozumienia charakterystyki sygnału, zbierania i analizowania próbek, opracowywania technik transmisji i/lub wstrzykiwania oraz tworzenia niestandardowych ładunków lub wiadomości. FISSURE zawiera rosnącą bibliotekę informacji o protokołach i sygnałach, które pomagają w identyfikacji, tworzeniu pakietów i testowaniu. Istnieje możliwość pobierania plików sygnałowych i tworzenia list odtwarzania w celu symulowania ruchu i testowania systemów.

Przyjazny kod Python i interfejs użytkownika umożliwiają początkującym szybkie zapoznanie się z popularnymi narzędziami i technikami związanymi z RF i inżynierią wsteczną. Nauczyciele w dziedzinie cyberbezpieczeństwa i inżynierii mogą skorzystać z wbudowanego materiału lub wykorzystać framework do demonstracji własnych zastosowań w rzeczywistych warunkach. Programiści i badacze mogą używać FISSURE do codziennych zadań lub udostępniać swoje najnowocześniejsze rozwiązania szerszej publiczności. Wraz z rozwojem świadomości i użytkowania FISSURE w społeczności, rozszerzą się możliwości frameworka i zakres technologii, które obejmuje.

**Dodatkowe informacje**

* [Strona AIS](https://www.ainfosec.com/technologies/fissure/)
* [Slajdy GRCon22](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [Artykuł GRCon22](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [Wideo GRCon22](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Transkrypt Hack Chat](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Rozpoczęcie pracy

**Obsługiwane**

W FISSURE są trzy gałęzie, które ułatwiają nawigację po plikach i zmniejszają redundancję kodu. Gałąź Python2\_maint-3.7 zawiera kod oparty na Pythonie 2, PyQt4 i GNU Radio 3.7; gałąź Python3\_maint-3.8 jest oparta na Pythonie 3, PyQt5 i GNU Radio 3.8; natomiast gałąź Python3\_maint-3.10 jest oparta na Pythonie 3, PyQt5 i GNU Radio 3.10.

|   System operacyjny   |   Gałąź FISSURE   |
| :------------------: | :----------------: |
|  Ubuntu 18.04 (x64)  | Python2\_maint-3.7 |
| Ubuntu 18.04.5 (x64) | Python2\_maint-3.7 |
| Ubuntu 18.04.6 (x64) | Python2\_maint-3.7 |
| Ubuntu 20.04.1 (x64) | Python3\_maint-3.8 |
| Ubuntu 20.04.4 (x64) | Python3\_maint-3.8 |
|  KDE neon 5.25 (x64) | Python3\_maint-3.8 |

**W trakcie (beta)**

Te systemy operacyjne są nadal w fazie beta. Są one w trakcie rozwoju i brakuje w nich kilku funkcji. Elementy w instalatorze mogą kolidować z istniejącymi programami lub nie udać się zainstalować, dopóki status nie zostanie usunięty.

|     System operacyjny     |    Gałąź FISSURE   |
| :----------------------: | :-----------------: |
| DragonOS Focal (x86\_64) |  Python3\_maint-3.8 |
|    Ubuntu 22.04 (x64)    | Python3\_maint-3.10 |

Uwaga: Niektóre narzędzia oprogramowania nie działają na każdym systemie operacyjnym. Odwołaj się do [Oprogramowanie i konflikty](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Help/Markdown/SoftwareAndConflicts.md)

**Instalacja**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout <Python2_maint-3.7> or <Python3_maint-3.8> or <Python3_maint-3.10>
git submodule update --init
./install
```
To zainstaluje zależności oprogramowania PyQt wymagane do uruchomienia interfejsów instalacyjnych, jeśli nie zostaną one znalezione.

Następnie wybierz opcję, która najlepiej odpowiada Twojemu systemowi operacyjnemu (powinna być wykrywana automatycznie, jeśli Twój system operacyjny pasuje do jednej z opcji).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

Zaleca się instalację FISSURE na czystym systemie operacyjnym, aby uniknąć istniejących konfliktów. Zaznacz wszystkie zalecane pola wyboru (przycisk Domyślne), aby uniknąć błędów podczas korzystania z różnych narzędzi w ramach FISSURE. Podczas instalacji pojawi się wiele monitów, głównie dotyczących podwyższonych uprawnień i nazw użytkowników. Jeśli element zawiera sekcję "Weryfikacja" na końcu, instalator uruchomi polecenie, które następuje po nim i zaznaczy pole wyboru na zielono lub czerwono, w zależności od tego, czy polecenie wygeneruje jakiekolwiek błędy. Zaznaczone elementy bez sekcji "Weryfikacja" pozostaną czarne po zakończeniu instalacji.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**Użycie**

Otwórz terminal i wprowadź:
```
fissure
```
Zobacz menu Pomoc FISSURE, aby uzyskać więcej informacji na temat korzystania.

## Szczegóły

**Komponenty**

* Panel sterowania
* Centralny punkt (HIPRFISR)
* Identyfikacja sygnału docelowego (TSI)
* Odkrywanie protokołów (PD)
* Graf przepływu i wykonawca skryptów (FGE)

![komponenty](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Możliwości**

| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Detektor sygnału**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**Manipulacja IQ**_      | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Wyszukiwanie sygnałów**_          | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Rozpoznawanie wzorców**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Ataki**_           | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Listy odtwarzania sygnałów**_       | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Galeria obrazów**_  |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Tworzenie pakietów**_   | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Integracja Scapy**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**Kalkulator CRC**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Logowanie**_            |

**Sprzęt**

Poniżej znajduje się lista "obsługiwanego" sprzętu o różnym stopniu integracji:

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx
* HackRF
* RTL2832U
* Adaptery 802.11
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR

## Lekcje

FISSURE zawiera kilka pomocnych przewodników, które pomogą zapoznać się z różnymi technologiami i technikami. Wiele z nich zawiera kroki dotyczące korzystania z różnych narzędzi zintegrowanych z FISSURE.

* [Lekcja 1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Lekcja 2: Lua Dissectors](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Lekcja 3: Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Lekcja 4: Płytki ESP](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Lekcja 5: Śledzenie radiosond](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Lekcja 6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Lekcja 7: Typy danych](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Lekcja 8: Niestandardowe bloki GNU Radio](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Lekcja 9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Lekcja 10: Egzaminy radiowe](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Lekcja 11: Narzędzia Wi-Fi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)

## Roadmap

* [ ] Dodaj więcej typów sprzętu, protokołów RF, parametrów sygnałów, narzędzi analizy
* [ ] Wsparcie dla większej liczby systemów operacyjnych
* [ ] Opracowanie materiałów dydaktycznych dotyczących FISSURE (Ataki RF, Wi-Fi, GNU Radio, PyQt itp.)
* [ ] Stworzenie kondycjonera sygnału, ekstraktora cech i klasyfikatora sygnałów z wybieralnymi technikami AI/ML
* [ ] Wdrożenie mechanizmów rekurencyjnej demodulacji do generowania strumienia bitów z nieznanych sygnałów
* [ ] Przejście głównych komponentów FISSURE do ogólnego schematu wdrożenia węzłów czujnikowych

## Współpraca

Zachęcamy do zgłaszania sugestii dotyczących poprawy FISSURE. Zostaw komentarz na stronie [Dyskusje](https://github.com/ainfosec/FISSURE/discussions) lub na serwerze Discord, jeśli masz jakiekolwiek pomysły dotyczące:

* Sugestie nowych funkcji i zmian projektowych
* Narzędzia oprogramowania wraz z instrukcjami instalacji
* Nowe lekcje lub dodatkowe materiały do istniejących lekcji
* Interesujące protokoły RF
* Więcej sprzętu i typów SDR do integracji
* Skrypty analizy IQ w języku Python
* Korekty i ulepszenia instalacji

Wkład w poprawę FISSURE jest niezwykle ważny dla przyspieszenia jego rozwoju. Wszelkie wniesione przez Ciebie zmiany są bardzo doceniane. Jeśli chcesz przyczynić się poprzez rozwój kodu, proszę o skopiowanie repozytorium i utworzenie żądania pull:

1. Skopiuj projekt
2. Utwórz nową gałąź funkcji (`git checkout -b feature/AmazingFeature`)
3. Zatwierdź zmiany (`git commit -m 'Dodaj niesamowitą funkcję'`)
4. Wyślij do gałęzi (`git push origin feature/AmazingFeature`)
5. Otwórz żądanie pull

Tworzenie [Zgłoszeń](https://github.com/ainfosec/FISSURE/issues) w celu zwrócenia uwagi na błędy jest również mile widziane.

## Współpraca

Skontaktuj się z działem Rozwoju Biznesu Assured Information Security, Inc. (AIS), aby zaproponować i sformalizować możliwości współpracy z FISSURE - czy to poprzez poświęcenie czasu na integrację oprogramowania, stworzenie rozwiązań dla Twoich wyzwań technicznych przez utalentowanych specjalistów AIS lub integrację FISSURE z innymi platformami/aplikacjami.

## Licencja

GPL-3.0

Szczegóły licencji znajdują się w pliku LICENSE.
## Kontakt

Dołącz do serwera Discord: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Obserwuj na Twitterze: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Rozwój biznesu - Assured Information Security, Inc. - bd@ainfosec.com

## Uznania

Doceniamy i jesteśmy wdzięczni tym deweloperom:

[Uznania](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Podziękowania

Szczególne podziękowania dla dr. Samuela Mantravadi i Josepha Reitha za ich wkład w ten projekt.
