# Skeleton Key

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs exclusivos**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## **Skeleton Key**

**De:** [**https://blog.stealthbits.com/unlocking-all-the-doors-to-active-directory-with-the-skeleton-key-attack/**](https://blog.stealthbits.com/unlocking-all-the-doors-to-active-directory-with-the-skeleton-key-attack/)

Existem vários métodos que atacantes podem usar para comprometer contas do Active Directory, elevar privilégios e criar persistência uma vez que se estabeleceram no seu domínio. O Skeleton Key é um malware particularmente assustador direcionado a domínios do Active Directory para tornar alarmantemente fácil sequestrar qualquer conta. Este malware **injeta-se no LSASS e cria uma senha mestra que funcionará para qualquer conta no domínio**. As senhas existentes também continuarão a funcionar, então é muito difícil saber que este ataque ocorreu a menos que você saiba o que procurar.

Não surpreendentemente, este é um dos muitos ataques que é empacotado e muito fácil de realizar usando [Mimikatz](https://github.com/gentilkiwi/mimikatz). Vamos ver como funciona.

### Requisitos para o Ataque Skeleton Key

Para perpetrar este ataque, **o atacante deve ter direitos de Administrador do Domínio**. Este ataque deve ser **realizado em cada controlador de domínio para comprometimento completo, mas até mesmo mirar em um único controlador de domínio pode ser eficaz**. **Reiniciar** um controlador de domínio **removerá este malware** e ele terá que ser redistribuído pelo atacante.

### Realizando o Ataque Skeleton Key

Realizar o ataque é muito simples. Requer apenas o seguinte **comando a ser executado em cada controlador de domínio**: `misc::skeleton`. Depois disso, você pode se autenticar como qualquer usuário com a senha padrão do Mimikatz.

![Injetando uma skeleton key usando o comando misc::skeleton em um controlador de domínio com Mimikatz](https://blog.stealthbits.com/wp-content/uploads/2017/07/1-3.png)

Aqui está uma autenticação para um membro de Administrador do Domínio usando a skeleton key como senha para obter acesso administrativo a um controlador de domínio:

![Usando a skeleton key como senha com o comando misc::skeleton para obter acesso administrativo a um controlador de domínio com a senha padrão do Mimikatz](https://blog.stealthbits.com/wp-content/uploads/2017/07/2-5.png)

Nota: Se você receber uma mensagem dizendo, “Erro de sistema 86 ocorreu. A senha de rede especificada está incorreta”, apenas tente usar o formato domínio\conta para o nome de usuário e deve funcionar.

![Usando o formato domínio\conta para o nome de usuário se você receber uma mensagem dizendo Erro de sistema 86 ocorreu A senha de rede especificada está incorreta](https://blog.stealthbits.com/wp-content/uploads/2017/07/3-3.png)

Se o lsass já foi **corrigido** com skeleton, então este **erro** aparecerá:

![](<../../.gitbook/assets/image (160).png>)

### Mitigações

* Eventos:
* ID de Evento do Sistema 7045 - Um serviço foi instalado no sistema. (Tipo de driver do Modo Kernel)
* ID de Evento de Segurança 4673 – Uso de Privilégio Sensível ("Auditoria de uso de privilégio" deve estar ativada)
* ID de Evento 4611 – Um processo de logon confiável foi registrado com a Autoridade de Segurança Local ("Auditoria de uso de privilégio" deve estar ativada)
* `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "`_`Kernel Mode Driver"}`_
* Isso só detecta mimidrv `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$`_`.message -like "Kernel Mode Driver" -and $`_`.message -like "`_`mimidrv`_`"}`
* Mitigação:
* Execute lsass.exe como um processo protegido, isso força um atacante a carregar um driver de modo kernel
* `New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -Value 1 -Verbose`
* Verifique após reiniciar: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "`_`protected process"}`_

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs exclusivos**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
