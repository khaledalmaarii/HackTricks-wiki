# Skeleton Key

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>qa'vIn HackTricks AWS Red Team Expert</strong></a><strong>!</strong></summary>

HackTricks vItlhutlh:

* qaStaHvIS **company HackTricks advertise** 'ej **HackTricks PDF download** [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) **qaStaHvIS**.
* [**official PEASS & HackTricks swag**](https://peass.creator-spring.com) **ghItlh**.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) **qay'be'** [**NFTs**](https://opensea.io/collection/the-peass-family) **ghItlh**.
* 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) **joq** **telegram group**](https://t.me/peass) **'ej** **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Hacking tricks** **submit PRs** [**HackTricks**](https://github.com/carlospolop/hacktricks) **'ej** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github repos** **Share**.

</details>

## Skeleton Key Attack

**Skeleton Key attack** **Active Directory authentication** **bypass** **attackers** **injecting a master password** **domain controller** **'ej** **authenticate as any user** **password** **ghItlh** **access** **domain** **unrestricted** **granting**.

[Mimikatz](https://github.com/gentilkiwi/mimikatz) **attack** **perform**. **Domain Admin rights** **prerequisite**, **attacker** **domain controller** **target** **comprehensive breach** **ensure**. **attack** **temporary effect**, **restarting the domain controller eradicates the malware**, **reimplementation** **sustained access** **necessitate**.

**Executing the attack** **single command**: `misc::skeleton`.

## Mitigations

**Mitigation strategies** **attacks** **monitoring** **specific event IDs** **installation of services** **use of sensitive privileges** **reveal**. **System Event ID 7045** **Security Event ID 4673** **suspicious activities** **reveal**. **`lsass.exe`** **protected process** **significantly hinder** **attackers' efforts**, **kernel mode driver** **employ** **attack** **complexity** **increase**.

**PowerShell commands** **enhance security measures** **following**:

- **detect** **installation of suspicious services**: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`

- **detect Mimikatz's driver**: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`

- **fortify `lsass.exe`**, **protected process** **enable**: `New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -Value 1 -Verbose`

**Verification** **system reboot** **crucial** **protective measures** **successfully applied**. **achievable** **following**: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*`

## References
* [https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>qa'vIn HackTricks AWS Red Team Expert</strong></a><strong>!</strong></summary>

HackTricks vItlhutlh:

* qaStaHvIS **company HackTricks advertise** 'ej **HackTricks PDF download** [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) **qaStaHvIS**.
* [**official PEASS & HackTricks swag**](https://peass.creator-spring.com) **ghItlh**.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) **qay'be'** [**NFTs**](https://opensea.io/collection/the-peass-family) **ghItlh**.
* 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) **joq** **telegram group**](https://t.me/peass) **'ej** **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Hacking tricks** **submit PRs** [**HackTricks**](https://github.com/carlospolop/hacktricks) **'ej** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github repos** **Share**.

</details>
