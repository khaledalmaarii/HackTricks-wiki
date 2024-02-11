# Cienie hasł

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć swoją **firmę reklamowaną w HackTricks**? A może chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do repozytorium [hacktricks](https://github.com/carlospolop/hacktricks) i [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Wprowadzenie <a href="#3f17" id="3f17"></a>

**Sprawdź oryginalny post, aby uzyskać [wszystkie informacje na temat tej techniki](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**

Podsumowując: jeśli możesz zapisać do właściwości **msDS-KeyCredentialLink** użytkownika/komputera, możesz odzyskać **hash NT tego obiektu**.

W poście opisana jest metoda konfiguracji uwierzytelniania klucza publicznego-prywatnego w celu uzyskania unikalnego **biletu usługi**, który zawiera hash NTLM docelowego obiektu. Proces ten obejmuje zaszyfrowane NTLM_SUPPLEMENTAL_CREDENTIAL w ramach Certyfikatu Atrybutu Uprawnień (PAC), które można odszyfrować.

### Wymagania

Aby zastosować tę technikę, muszą zostać spełnione pewne warunki:
- Wymagany jest co najmniej jeden kontroler domeny Windows Server 2016.
- Kontroler domeny musi mieć zainstalowany certyfikat uwierzytelniania serwera.
- Katalog Active Directory musi mieć poziom funkcjonalności Windows Server 2016.
- Wymagane jest konto z uprawnieniami do modyfikowania atrybutu msDS-KeyCredentialLink obiektu docelowego.

## Nadużycie

Nadużycie Key Trust dla obiektów komputerowych obejmuje kroki poza uzyskaniem Biletu Grantowego (TGT) i hasha NTLM. Opcje obejmują:
1. Tworzenie **srebrnego biletu RC4** w celu działania jako uprzywilejowani użytkownicy na docelowym hoście.
2. Użycie TGT z **S4U2Self** do podszycia się pod **uprzywilejowanych użytkowników**, co wymaga zmian w Bilecie Usługi w celu dodania klasy usługi do nazwy usługi.

Znaczącą zaletą nadużycia Key Trust jest ograniczenie do prywatnego klucza wygenerowanego przez atakującego, unikając delegacji do potencjalnie podatnych kont i nie wymagając tworzenia konta komputera, co mogłoby być trudne do usunięcia.

## Narzędzia

### [**Whisker**](https://github.com/eladshamir/Whisker)

Opiera się na DSInternals i zapewnia interfejs C# do tego ataku. Whisker i jego odpowiednik w języku Python, **pyWhisker**, umożliwiają manipulację atrybutem `msDS-KeyCredentialLink`, aby uzyskać kontrolę nad kontami Active Directory. Narzędzia te obsługują różne operacje, takie jak dodawanie, wyświetlanie, usuwanie i czyszczenie kluczowych poświadczeń z obiektu docelowego.

Funkcje **Whisker** obejmują:
- **Dodaj**: Generuje parę kluczy i dodaje kluczowe poświadczenie.
- **Lista**: Wyświetla wszystkie wpisy kluczowych poświadczeń.
- **Usuń**: Usuwa określone kluczowe poświadczenie.
- **Wyczyść**: Usuwa wszystkie kluczowe poświadczenia, potencjalnie zakłócając prawidłowe korzystanie z WHfB.
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

Rozszerza funkcjonalność Whisker na systemy **oparte na UNIX**, wykorzystując Impacket i PyDSInternals do kompleksowych możliwości eksploatacji, w tym listowania, dodawania i usuwania KeyCredentials, a także importowania i eksportowania ich w formacie JSON.
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray ma na celu **wykorzystanie uprawnień GenericWrite/GenericAll, które szerokie grupy użytkowników mogą mieć wobec obiektów domeny** w celu szerokiego zastosowania ShadowCredentials. Polega to na zalogowaniu się do domeny, sprawdzeniu poziomu funkcjonalnego domeny, wyliczeniu obiektów domeny i próbie dodania KeyCredentials w celu uzyskania TGT i ujawnienia skrótu NT. Opcje czyszczenia i taktyki rekurencyjnego wykorzystania zwiększają jego użyteczność.


## Referencje

* [https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
* [https://github.com/eladshamir/Whisker](https://github.com/eladshamir/Whisker)
* [https://github.com/Dec0ne/ShadowSpray/](https://github.com/Dec0ne/ShadowSpray/)
* [https://github.com/ShutdownRepo/pywhisker](https://github.com/ShutdownRepo/pywhisker)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Czy pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć, jak Twoja **firma jest reklamowana w HackTricks**? A może chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do repozytorium [hacktricks](https://github.com/carlospolop/hacktricks) i [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
