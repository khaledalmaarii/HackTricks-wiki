# Modelowanie zagrożeń

## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) to wyszukiwarka zasilana przez **dark web**, która oferuje **darmowe** funkcje do sprawdzenia, czy firma lub jej klienci zostali **skompromitowani** przez **złośliwe oprogramowanie kradnące dane**.

Głównym celem WhiteIntel jest zwalczanie przejęć kont i ataków ransomware wynikających z oprogramowania kradnącego informacje.

Możesz odwiedzić ich stronę internetową i wypróbować ich silnik **za darmo** pod adresem:

{% embed url="https://whiteintel.io" %}

---

## Modelowanie zagrożeń

Witaj w kompleksowym przewodniku HackTricks na temat modelowania zagrożeń! Wyrusz w podróż po tym kluczowym aspekcie cyberbezpieczeństwa, gdzie identyfikujemy, rozumiemy i strategizujemy przeciwko potencjalnym podatnościom w systemie. Ten wątek służy jako przewodnik krok po kroku, wypełniony przykładami z życia wziętymi, pomocnym oprogramowaniem i łatwymi do zrozumienia wyjaśnieniami. Idealny zarówno dla początkujących, jak i doświadczonych praktyków, którzy chcą wzmocnić swoje obronne środki cyberbezpieczeństwa.

### Powszechne scenariusze

1. **Rozwój oprogramowania**: W ramach Bezpiecznego Cyklu Życia Rozwoju Oprogramowania (SSDLC), modelowanie zagrożeń pomaga w **identyfikowaniu potencjalnych źródeł podatności** we wczesnych etapach rozwoju.
2. **Testowanie penetracyjne**: Ramy Standardu Wykonania Testów Penetracyjnych (PTES) wymagają **modelowania zagrożeń do zrozumienia podatności systemu** przed przeprowadzeniem testu.

### Model zagrożeń w pigułce

Model zagrożeń jest zazwyczaj przedstawiany jako diagram, obraz lub inna forma wizualizacji, która przedstawia zaplanowaną architekturę lub istniejącą budowę aplikacji. Przypomina diagram przepływu danych, ale kluczowa różnica polega na jego zorientowanym na bezpieczeństwo projekcie.

Modele zagrożeń często zawierają elementy oznaczone na czerwono, symbolizujące potencjalne podatności, ryzyka lub bariery. Aby usprawnić proces identyfikacji ryzyka, wykorzystywana jest triada CIA (Confidentiality, Integrity, Availability), stanowiąca podstawę wielu metod modelowania zagrożeń, przy czym STRIDE jest jednym z najczęściej stosowanych. Jednak wybrana metodologia może się różnić w zależności od konkretnego kontekstu i wymagań.

### Triada CIA

Triada CIA to powszechnie uznany model w dziedzinie bezpieczeństwa informacji, oznaczający poufność, integralność i dostępność. Te trzy filary stanowią fundament, na którym opierają się wiele środków bezpieczeństwa i polityk, w tym metodyki modelowania zagrożeń.

1. **Poufność**: Zapewnienie, że dane lub system nie są dostępne dla nieautoryzowanych osób. Jest to centralny aspekt bezpieczeństwa, wymagający odpowiednich kontroli dostępu, szyfrowania i innych środków zapobiegających naruszeniom danych.
2. **Integralność**: Dokładność, spójność i wiarygodność danych w trakcie ich cyklu życia. Zasada ta zapewnia, że dane nie są modyfikowane ani manipulowane przez nieautoryzowane strony. Często obejmuje sumy kontrolne, hashowanie i inne metody weryfikacji danych.
3. **Dostępność**: Zapewnienie, że dane i usługi są dostępne dla autoryzowanych użytkowników w razie potrzeby. Często wymaga redundancji, tolerancji na awarie i konfiguracji o wysokiej dostępności, aby systemy działały nawet w obliczu zakłóceń.

### Metodologie modelowania zagrożeń

1. **STRIDE**: Opracowany przez Microsoft, STRIDE to akronim od **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service i Elevation of Privilege**. Każda kategoria reprezentuje rodzaj zagrożenia, a ta metodyka jest powszechnie stosowana we wczesnej fazie projektowania programu lub systemu do identyfikacji potencjalnych zagrożeń.
2. **DREAD**: Jest to kolejna metodyka od Microsoftu używana do oceny ryzyka zidentyfikowanych zagrożeń. DREAD oznacza **Damage potential, Reproducibility, Exploitability, Affected users i Discoverability**. Każdy z tych czynników jest oceniany, a wynik jest wykorzystywany do priorytetyzacji zidentyfikowanych zagrożeń.
3. **PASTA** (Process for Attack Simulation and Threat Analysis): To siedmiostopniowa, **zorientowana na ryzyko** metodyka. Obejmuje definiowanie i identyfikowanie celów bezpieczeństwa, tworzenie zakresu technicznego, dekompozycję aplikacji, analizę zagrożeń, analizę podatności oraz ocenę ryzyka/priorytetów.
4. **Trike**: Jest to metodyka oparta na ryzyku, która skupia się na obronie zasobów. Rozpoczyna się od perspektywy **zarządzania ryzykiem** i analizuje zagrożenia i podatności w tym kontekście.
5. **VAST** (Visual, Agile, and Simple Threat modeling): To podejście ma na celu być bardziej dostępne i integrować się z środowiskami rozwoju Agile. Łączy elementy z innych metodologii i skupia się na **wizualnych reprezentacjach zagrożeń**.
6. **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation): Opracowany przez CERT Coordination Center, ten framework jest ukierunkowany na **ocenę ryzyka organizacyjnego, a nie konkretnych systemów ani oprogramowania**.

## Narzędzia

Dostępne są różne narzędzia i rozwiązania programowe, które mogą **pomóc** w tworzeniu i zarządzaniu modelami zagrożeń. Oto kilka, które warto rozważyć.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

Zaawansowany wieloplatformowy i wielofunkcyjny interfejs graficzny do przeglądania stron internetowych dla profesjonalistów zajmujących się cyberbezpieczeństwem. Spider Suite może być używany do mapowania powierzchni ataku i analizy.

**Użycie**

1. Wybierz adres URL i Przeglądaj

<figure><img src="../.gitbook/assets/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Wyświetl Graf

<figure><img src="../.gitbook/assets/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

Projekt open-source od OWASP, Threat Dragon to zarówno aplikacja internetowa, jak i desktopowa, która obejmuje diagramowanie systemu oraz silnik reguł do automatycznego generowania zagrożeń/zapobiegania.

**Użycie**

1. Utwórz Nowy Projekt

<figure><img src="../.gitbook/assets/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

Czasami może wyglądać to tak:

<figure><img src="../.gitbook/assets/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. Uruchom Nowy Projekt

<figure><img src="../.gitbook/assets/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. Zapisz Nowy Projekt

<figure><img src="../.gitbook/assets/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. Utwórz swój model

Możesz użyć narzędzi takich jak SpiderSuite Crawler, aby dać Ci inspirację, podstawowy model będzie wyglądał mniej więcej tak

<figure><img src="../.gitbook/assets/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Krótka wyjaśnienie dotyczące jednostek:

* Proces (Sama jednostka, taka jak serwer WWW lub funkcjonalność sieciowa)
* Aktor (Osoba, taka jak Odwiedzający stronę internetową, Użytkownik lub Administrator)
* Linia przepływu danych (Wskaźnik interakcji)
* Granica zaufania (Różne segmenty sieciowe lub zakresy.)
* Magazyn (Miejsca, w których przechowywane są dane, takie jak bazy danych)

5. Utwórz Zagrożenie (Krok 1)

Najpierw musisz wybrać warstwę, do której chcesz dodać zagrożenie

<figure><img src="../.gitbook/assets/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Teraz możesz utworzyć zagrożenie

<figure><img src="../.gitbook/assets/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Pamiętaj, że istnieje różnica między Zagrożeniami Aktora a Zagrożeniami Procesu. Jeśli dodasz zagrożenie do Aktora, będziesz mógł wybrać tylko "Podrobienie" i "Zaprzeczenie". Jednak w naszym przykładzie dodajemy zagrożenie do jednostki Procesu, więc zobaczymy to w oknie tworzenia zagrożenia:

<figure><img src="../.gitbook/assets/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. Gotowe

Teraz Twój ukończony model powinien wyglądać mniej więcej tak. I tak tworzysz prosty model zagrożeń za pomocą OWASP Threat Dragon.

<figure><img src="../.gitbook/assets/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>
### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

Jest to darmowe narzędzie od Microsoftu, które pomaga w znajdowaniu zagrożeń na etapie projektowania projektów oprogramowania. Wykorzystuje metodologię STRIDE i jest szczególnie odpowiednie dla tych, którzy rozwijają na platformie Microsoft.

## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) to wyszukiwarka zasilana **dark webem**, która oferuje **darmowe** funkcje do sprawdzania, czy firma lub jej klienci nie zostali **skompromitowani** przez **złośliwe oprogramowanie kradnące dane**.

Ich głównym celem WhiteIntel jest zwalczanie przejęć kont i ataków ransomware wynikających z złośliwego oprogramowania kradnącego informacje.

Możesz sprawdzić ich stronę internetową i wypróbować ich silnik **za darmo** pod adresem:

{% embed url="https://whiteintel.io" %}
