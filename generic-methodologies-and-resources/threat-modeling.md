# Modelowanie zagrożeń

## Modelowanie zagrożeń

Witaj w kompleksowym przewodniku HackTricks dotyczącym modelowania zagrożeń! Przejdź przez eksplorację tego kluczowego aspektu cyberbezpieczeństwa, gdzie identyfikujemy, rozumiemy i strategizujemy przeciwko potencjalnym podatnościom w systemie. Ten wątek służy jako przewodnik krok po kroku, wypełniony przykładami z prawdziwego świata, pomocnym oprogramowaniem i łatwymi do zrozumienia wyjaśnieniami. Idealny zarówno dla początkujących, jak i doświadczonych praktyków, którzy chcą wzmocnić swoje obronne środki cyberbezpieczeństwa.

### Powszechnie stosowane scenariusze

1. **Rozwój oprogramowania**: W ramach cyklu życia bezpiecznego rozwoju oprogramowania (SSDLC), modelowanie zagrożeń pomaga w **identyfikacji potencjalnych źródeł podatności** we wczesnych fazach rozwoju.
2. **Testowanie penetracyjne**: Ramy Penetration Testing Execution Standard (PTES) wymagają **modelowania zagrożeń w celu zrozumienia podatności systemu** przed przeprowadzeniem testu.

### Model zagrożeń w skrócie

Model zagrożeń jest zwykle przedstawiany jako diagram, obraz lub inna forma wizualizacji, która przedstawia planowaną architekturę lub istniejącą konstrukcję aplikacji. Przypomina **diagram przepływu danych**, ale kluczowa różnica polega na jego bezpieczeństwo-skoncentrowanym projekcie.

Modele zagrożeń często zawierają elementy oznaczone na czerwono, symbolizujące potencjalne podatności, ryzyka lub bariery. Aby usprawnić proces identyfikacji ryzyka, stosuje się triadę CIA (Confidentiality, Integrity, Availability), która stanowi podstawę wielu metodologii modelowania zagrożeń, z których STRIDE jest jedną z najbardziej popularnych. Jednak wybrana metodyka może się różnić w zależności od konkretnego kontekstu i wymagań.

### Triada CIA

Triada CIA to powszechnie uznany model w dziedzinie bezpieczeństwa informacji, oznaczający poufność (Confidentiality), integralność (Integrity) i dostępność (Availability). Te trzy filary stanowią podstawę wielu środków bezpieczeństwa i polityk, w tym metodologii modelowania zagrożeń.

1. **Poufność**: Zapewnienie, że dane lub system nie są dostępne dla nieuprawnionych osób. Jest to centralny aspekt bezpieczeństwa, wymagający odpowiednich kontroli dostępu, szyfrowania i innych środków zapobiegających naruszeniom danych.
2. **Integralność**: Dokładność, spójność i wiarygodność danych w trakcie ich cyklu życia. Zasada ta zapewnia, że dane nie są zmieniane ani modyfikowane przez nieuprawnione strony. Często obejmuje sumy kontrolne, funkcje skrótu i inne metody weryfikacji danych.
3. **Dostępność**: Zapewnienie, że dane i usługi są dostępne dla uprawnionych użytkowników w razie potrzeby. Często obejmuje redundancję, odporność na awarie i konfiguracje wysokiej dostępności, aby systemy działały nawet w przypadku zakłóceń.

### Metodyki modelowania zagrożeń

1. **STRIDE**: Opracowany przez Microsoft, STRIDE to skrót od **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service i Elevation of Privilege**. Każda kategoria reprezentuje rodzaj zagrożenia, a ta metodyka jest często stosowana we fa
