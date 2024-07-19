# Skeleton Key

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

## Skeleton Key Attack

**Skeleton Key攻撃**は、攻撃者が**ドメインコントローラーにマスターパスワードを注入することによってActive Directory認証をバイパスする**高度な技術です。これにより、攻撃者は**任意のユーザーとして認証できる**ようになり、実質的に**ドメインへの無制限のアクセスを付与**します。

この攻撃は[Mimikatz](https://github.com/gentilkiwi/mimikatz)を使用して実行できます。この攻撃を実行するには、**ドメイン管理者権限が前提条件**であり、攻撃者は包括的な侵害を確実にするために各ドメインコントローラーをターゲットにする必要があります。ただし、攻撃の効果は一時的であり、**ドメインコントローラーを再起動するとマルウェアが消去される**ため、持続的なアクセスのためには再実装が必要です。

**攻撃を実行する**には、単一のコマンドが必要です：`misc::skeleton`。

## Mitigations

このような攻撃に対する緩和策には、サービスのインストールや敏感な特権の使用を示す特定のイベントIDを監視することが含まれます。具体的には、システムイベントID 7045またはセキュリティイベントID 4673を探すことで、疑わしい活動を明らかにできます。さらに、`lsass.exe`を保護されたプロセスとして実行することで、攻撃者の努力を大幅に妨げることができ、これによりカーネルモードドライバーを使用する必要が生じ、攻撃の複雑さが増します。

セキュリティ対策を強化するためのPowerShellコマンドは以下の通りです：

- 疑わしいサービスのインストールを検出するには、次のコマンドを使用します：`Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`

- 特にMimikatzのドライバーを検出するには、次のコマンドを利用できます：`Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`

- `lsass.exe`を強化するためには、保護されたプロセスとして有効にすることが推奨されます：`New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -Value 1 -Verbose`

システム再起動後の検証は、保護措置が正常に適用されたことを確認するために重要です。これは次のコマンドで実現できます：`Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*`

## References
* [https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)

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
