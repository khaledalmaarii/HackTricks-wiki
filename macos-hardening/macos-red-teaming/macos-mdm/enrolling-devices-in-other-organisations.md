# Rejestrowanie urządzeń w innych organizacjach

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów GitHub.

</details>

## Wprowadzenie

Jak [**wcześniej wspomniano**](./#what-is-mdm-mobile-device-management), aby spróbować zarejestrować urządzenie w organizacji, potrzebny jest tylko numer seryjny należący do tej organizacji. Po zarejestrowaniu urządzenia, wiele organizacji zainstaluje na nowym urządzeniu wrażliwe dane: certyfikaty, aplikacje, hasła WiFi, konfiguracje VPN [i tak dalej](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Dlatego ten proces rejestracji może stanowić niebezpieczne wejście dla atakujących, jeśli nie jest odpowiednio chroniony.

**Poniżej znajduje się podsumowanie badania [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Sprawdź je dla dalszych szczegółów technicznych!**

## Przegląd DEP i analiza binarna MDM

To badanie zagłębia się w binarne pliki związane z programem Device Enrollment Program (DEP) i zarządzaniem urządzeniami mobilnymi (MDM) w systemie macOS. Kluczowe komponenty to:

- **`mdmclient`**: Komunikuje się z serwerami MDM i wywołuje sprawdzanie DEP w wersjach macOS przed 10.13.4.
- **`profiles`**: Zarządza profilami konfiguracyjnymi i wywołuje sprawdzanie DEP w wersjach macOS 10.13.4 i nowszych.
- **`cloudconfigurationd`**: Zarządza komunikacją z interfejsem API DEP i pobiera profile rejestracji urządzeń.

Sprawdzanie DEP wykorzystuje funkcje `CPFetchActivationRecord` i `CPGetActivationRecord` z prywatnego frameworka Configuration Profiles do pobierania Rejestru Aktywacji, przy czym `CPFetchActivationRecord` współpracuje z `cloudconfigurationd` za pośrednictwem XPC.

## Reverse Engineering protokołu Tesla i schematu Absinthe

Sprawdzanie DEP obejmuje wysłanie przez `cloudconfigurationd` zaszyfrowanego i podpisanego ładunku JSON na adres _iprofiles.apple.com/macProfile_. Ładunek zawiera numer seryjny urządzenia i akcję "RequestProfileConfiguration". Schemat szyfrowania używany wewnętrznie nosi nazwę "Absinthe". Rozwiązanie tego schematu jest skomplikowane i wymaga wielu kroków, co doprowadziło do badania alternatywnych metod wstawiania dowolnych numerów seryjnych w żądaniu Rejestru Aktywacji.

## Proxy DEP

Próby przechwycenia i modyfikacji żądań DEP do _iprofiles.apple.com_ za pomocą narzędzi takich jak Charles Proxy były utrudnione przez szyfrowanie ładunku i środki bezpieczeństwa SSL/TLS. Jednak włączenie konfiguracji `MCCloudConfigAcceptAnyHTTPSCertificate` umożliwia ominięcie weryfikacji certyfikatu serwera, chociaż zaszyfrowany charakter ładunku nadal uniemożliwia modyfikację numeru seryjnego bez klucza deszyfracji.

## Instrumentowanie binarnych plików systemowych współpracujących z DEP

Instrumentowanie binarnych plików systemowych, takich jak `cloudconfigurationd`, wymaga wyłączenia System Integrity Protection (SIP) w systemie macOS. Po wyłączeniu SIP można użyć narzędzi takich jak LLDB do dołączenia do procesów systemowych i potencjalnej modyfikacji numeru seryjnego używanego w interakcjach z interfejsem API DEP. Metoda ta jest preferowana, ponieważ omija złożoność uprawnień i podpisywania kodu.

**Wykorzystywanie instrumentacji binarnej:**
Modyfikacja ładunku żądania DEP przed serializacją JSON w `cloudconfigurationd` okazała się skuteczna. Proces ten obejmował:

1. Dołączenie LLDB do `cloudconfigurationd`.
2. Zlokalizowanie miejsca, w którym pobierany jest numer seryjny systemu.
3. Wstrzyknięcie dowolnego numeru seryjnego do pamięci przed zaszyfrowaniem i wysłaniem ładunku.

Ta metoda umożliwiła pobieranie kompletnych profili DEP dla dowolnych numerów seryjnych, co dowodzi potencjalnej podatności.

### Automatyzacja instrumentacji za pomocą Pythona

Proces eksploatacji został zautomatyzowany za pomocą Pythona z wykorzystaniem interfejsu API LLDB, co umożliwiło programowe wstrzykiwanie dowolnych numerów seryjnych i pobieranie odpowiadających im profili DEP.

### Potencjalne skutki podatności DEP i MDM

Badanie podkreśliło istotne zagrożenia dla bezpieczeństwa:

1. **Ujawnienie informacji**: Podając zarejestrowany numer seryjny DEP, można uzyskać wrażliwe informacje organizacyjne zawarte w profilu DEP.
2. **Rejestracja nieautoryzowanego urządzenia DEP**: Bez odpowiedniej autoryzacji atakujący posiadający zarejestrowany numer seryjny DEP może zarejestrować nieautoryzowane urządzenie w serwerze MDM organizacji, co potencjalnie umożliwia dostęp do wrażliwych danych i zasobów sieciowych.

Podsumowując, chociaż DEP i MDM dostarczają potężne narzędzia do zarządzania urządzeniami Apple w środowiskach przedsiębiorstwowych, stanowią również potencjalne wektory ataku, które należy zabezpieczyć i monitorować.


<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów GitHub.

</details>
