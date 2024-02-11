# Atak Skeleton Key

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Atak Skeleton Key

Atak **Skeleton Key** to zaawansowana technika, która umożliwia atakującym **ominięcie uwierzytelniania Active Directory** poprzez **wstrzyknięcie hasła głównego** do kontrolera domeny. Pozwala to atakującemu **uwierzytelniać się jako dowolny użytkownik** bez znajomości jego hasła, co efektywnie **daje mu nieograniczony dostęp** do domeny.

Może być przeprowadzany za pomocą narzędzia [Mimikatz](https://github.com/gentilkiwi/mimikatz). Aby przeprowadzić ten atak, **wymagane są uprawnienia Domain Admin**, a atakujący musi skierować swoje działania na każdy kontroler domeny, aby zapewnić kompleksowe naruszenie. Jednak skutki ataku są tymczasowe, ponieważ **ponowne uruchomienie kontrolera domeny usuwa złośliwe oprogramowanie**, co wymaga ponownej implementacji w celu uzyskania trwałego dostępu.

**Wykonanie ataku** wymaga jednej komendy: `misc::skeleton`.

## Środki zaradcze

Strategie łagodzenia takich ataków obejmują monitorowanie określonych identyfikatorów zdarzeń, które wskazują na instalację usług lub wykorzystanie poufnych uprawnień. Szczególnie warto zwrócić uwagę na identyfikator zdarzenia systemowego 7045 lub identyfikator zdarzenia zabezpieczeń 4673, które mogą ujawnić podejrzane działania. Dodatkowo, uruchomienie `lsass.exe` jako chronionego procesu może znacznie utrudnić działania atakujących, ponieważ wymaga od nich użycia sterownika trybu jądra, co zwiększa złożoność ataku.

Oto polecenia PowerShell, które zwiększają środki bezpieczeństwa:

- Aby wykryć instalację podejrzanych usług, użyj: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`

- W szczególności, aby wykryć sterownik Mimikatz, można użyć następującego polecenia: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`

- Aby wzmocnić `lsass.exe`, zaleca się włączenie go jako chronionego procesu: `New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -Value 1 -Verbose`

Weryfikacja po ponownym uruchomieniu systemu jest kluczowa, aby upewnić się, że środki ochronne zostały skutecznie zastosowane. Można to osiągnąć za pomocą: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*`

## Odwołania
* [https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
