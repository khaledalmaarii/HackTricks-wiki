# Ataque Skeleton Key

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Ataque Skeleton Key

O **ataque Skeleton Key** é uma técnica sofisticada que permite aos atacantes **burlar a autenticação do Active Directory** ao **injetar uma senha mestra** no controlador de domínio. Isso permite ao atacante **autenticar-se como qualquer usuário** sem a necessidade de suas senhas, concedendo-lhes acesso irrestrito ao domínio.

Pode ser realizado usando o [Mimikatz](https://github.com/gentilkiwi/mimikatz). Para executar esse ataque, **é necessário ter direitos de Administrador de Domínio**, e o atacante deve visar cada controlador de domínio para garantir uma violação abrangente. No entanto, o efeito do ataque é temporário, pois **reiniciar o controlador de domínio erradica o malware**, exigindo uma nova implementação para acesso sustentado.

**Executar o ataque** requer um único comando: `misc::skeleton`.

## Mitigações

Estratégias de mitigação contra tais ataques incluem monitorar IDs de eventos específicos que indicam a instalação de serviços ou o uso de privilégios sensíveis. Especificamente, procurar pelo ID de Evento do Sistema 7045 ou ID de Evento de Segurança 4673 pode revelar atividades suspeitas. Além disso, executar o `lsass.exe` como um processo protegido pode dificultar significativamente os esforços dos atacantes, pois isso os obriga a empregar um driver de modo kernel, aumentando a complexidade do ataque.

Aqui estão os comandos PowerShell para aprimorar as medidas de segurança:

- Para detectar a instalação de serviços suspeitos, use: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Driver de Modo Kernel*"}`

- Especificamente, para detectar o driver do Mimikatz, o seguinte comando pode ser utilizado: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Driver de Modo Kernel*" -and $_.message -like "*mimidrv*"}`

- Para fortalecer o `lsass.exe`, recomendamos habilitá-lo como um processo protegido: `New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -Value 1 -Verbose`

A verificação após a reinicialização do sistema é crucial para garantir que as medidas de proteção tenham sido aplicadas com sucesso. Isso é alcançável por meio de: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*processo protegido*`

## Referências
* [https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
