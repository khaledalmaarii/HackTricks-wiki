# Rejestracja urządzeń w innych organizacjach

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się sztuczkami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na GitHubie.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

## Wprowadzenie

Jak [**wcześniej wspomniano**](./#what-is-mdm-mobile-device-management)**,** aby spróbować zarejestrować urządzenie w organizacji **wystarczy tylko numer seryjny należący do tej organizacji**. Po zarejestrowaniu urządzenia, kilka organizacji zainstaluje wrażliwe dane na nowym urządzeniu: certyfikaty, aplikacje, hasła WiFi, konfiguracje VPN [i tak dalej](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Dlatego może to być niebezpieczny punkt wejścia dla atakujących, jeśli proces rejestracji nie jest odpowiednio zabezpieczony.

**Poniżej znajduje się podsumowanie badań [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Sprawdź to, aby uzyskać dalsze szczegóły techniczne!**

## Przegląd analizy binarnej DEP i MDM

Badania te zagłębiają się w binaria związane z Programem Rejestracji Urządzeń (DEP) i Zarządzaniem Urządzeniami Mobilnymi (MDM) na macOS. Kluczowe komponenty to:

- **`mdmclient`**: Komunikuje się z serwerami MDM i wyzwala rejestracje DEP w wersjach macOS przed 10.13.4.
- **`profiles`**: Zarządza profilami konfiguracyjnymi i wyzwala rejestracje DEP w wersjach macOS 10.13.4 i nowszych.
- **`cloudconfigurationd`**: Zarządza komunikacją z API DEP i pobiera profile rejestracji urządzeń.

Rejestracje DEP wykorzystują funkcje `CPFetchActivationRecord` i `CPGetActivationRecord` z prywatnej ramy profili konfiguracyjnych do pobierania rekordu aktywacji, przy czym `CPFetchActivationRecord` współpracuje z `cloudconfigurationd` przez XPC.

## Inżynieria odwrotna protokołu Tesla i schematu Absinthe

Rejestracja DEP polega na tym, że `cloudconfigurationd` wysyła zaszyfrowany, podpisany ładunek JSON do _iprofiles.apple.com/macProfile_. Ładunek zawiera numer seryjny urządzenia oraz akcję "RequestProfileConfiguration". Schemat szyfrowania używany jest wewnętrznie jako "Absinthe". Rozwiązanie tego schematu jest skomplikowane i wymaga wielu kroków, co doprowadziło do zbadania alternatywnych metod wstawiania dowolnych numerów seryjnych w żądaniu rekordu aktywacji.

## Proxying żądań DEP

Próby przechwycenia i modyfikacji żądań DEP do _iprofiles.apple.com_ za pomocą narzędzi takich jak Charles Proxy były utrudnione przez szyfrowanie ładunku i środki bezpieczeństwa SSL/TLS. Jednak włączenie konfiguracji `MCCloudConfigAcceptAnyHTTPSCertificate` pozwala na ominięcie walidacji certyfikatu serwera, chociaż zaszyfrowana natura ładunku nadal uniemożliwia modyfikację numeru seryjnego bez klucza deszyfrującego.

## Instrumentacja binariów systemowych współpracujących z DEP

Instrumentacja binariów systemowych, takich jak `cloudconfigurationd`, wymaga wyłączenia Ochrony Integralności Systemu (SIP) w macOS. Po wyłączeniu SIP, narzędzia takie jak LLDB mogą być używane do podłączenia się do procesów systemowych i potencjalnej modyfikacji numeru seryjnego używanego w interakcjach z API DEP. Ta metoda jest preferowana, ponieważ unika złożoności związanych z uprawnieniami i podpisywaniem kodu.

**Wykorzystywanie instrumentacji binarnej:**
Modyfikacja ładunku żądania DEP przed serializacją JSON w `cloudconfigurationd` okazała się skuteczna. Proces obejmował:

1. Podłączenie LLDB do `cloudconfigurationd`.
2. Zlokalizowanie punktu, w którym pobierany jest numer seryjny systemu.
3. Wstrzyknięcie dowolnego numeru seryjnego do pamięci przed zaszyfrowaniem ładunku i wysłaniem go.

Ta metoda pozwoliła na pobranie pełnych profili DEP dla dowolnych numerów seryjnych, co wykazało potencjalną lukę.

### Automatyzacja instrumentacji za pomocą Pythona

Proces eksploatacji został zautomatyzowany za pomocą Pythona z użyciem API LLDB, co umożliwiło programowe wstrzykiwanie dowolnych numerów seryjnych i pobieranie odpowiadających im profili DEP.

### Potencjalne skutki luk w DEP i MDM

Badania podkreśliły istotne problemy z bezpieczeństwem:

1. **Ujawnienie informacji**: Podając zarejestrowany w DEP numer seryjny, można uzyskać wrażliwe informacje organizacyjne zawarte w profilu DEP.
{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się sztuczkami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na GitHubie.

</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
