# Skeleton Key

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

## Ataque Skeleton Key

O **ataque Skeleton Key** é uma técnica sofisticada que permite que atacantes **bypassem a autenticação do Active Directory** ao **injetar uma senha mestra** no controlador de domínio. Isso permite que o atacante **se autentique como qualquer usuário** sem a senha deles, efetivamente **concedendo acesso irrestrito** ao domínio.

Pode ser realizado usando [Mimikatz](https://github.com/gentilkiwi/mimikatz). Para executar esse ataque, **direitos de Admin do Domínio são pré-requisitos**, e o atacante deve direcionar cada controlador de domínio para garantir uma violação abrangente. No entanto, o efeito do ataque é temporário, pois **reiniciar o controlador de domínio erradica o malware**, necessitando de uma reimplementação para acesso sustentado.

**Executar o ataque** requer um único comando: `misc::skeleton`.

## Mitigações

As estratégias de mitigação contra tais ataques incluem monitorar IDs de eventos específicos que indicam a instalação de serviços ou o uso de privilégios sensíveis. Especificamente, procurar pelo ID de Evento do Sistema 7045 ou ID de Evento de Segurança 4673 pode revelar atividades suspeitas. Além disso, executar `lsass.exe` como um processo protegido pode dificultar significativamente os esforços dos atacantes, pois isso exige que eles utilizem um driver em modo kernel, aumentando a complexidade do ataque.

Aqui estão os comandos PowerShell para aprimorar as medidas de segurança:

- Para detectar a instalação de serviços suspeitos, use: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`

- Especificamente, para detectar o driver do Mimikatz, o seguinte comando pode ser utilizado: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`

- Para fortalecer `lsass.exe`, é recomendável habilitá-lo como um processo protegido: `New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -Value 1 -Verbose`

A verificação após a reinicialização do sistema é crucial para garantir que as medidas de proteção tenham sido aplicadas com sucesso. Isso pode ser alcançado através de: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*`

## Referências
* [https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
