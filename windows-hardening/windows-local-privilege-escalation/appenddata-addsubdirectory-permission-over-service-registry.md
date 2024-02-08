<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>


**A postagem original está em** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## Resumo

Foram encontradas duas chaves de registro que podem ser gravadas pelo usuário atual:

- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**

Foi sugerido verificar as permissões do serviço **RpcEptMapper** usando o **regedit GUI**, especificamente a guia **Effective Permissions** da janela **Advanced Security Settings**. Esta abordagem permite a avaliação das permissões concedidas a usuários ou grupos específicos sem a necessidade de examinar cada entrada de controle de acesso (ACE) individualmente.

Uma captura de tela mostrou as permissões atribuídas a um usuário de baixo privilégio, entre as quais a permissão **Create Subkey** era notável. Esta permissão, também referida como **AppendData/AddSubdirectory**, corresponde às descobertas do script.

Foi observada a incapacidade de modificar certos valores diretamente, mas a capacidade de criar novas subchaves. Um exemplo destacado foi uma tentativa de alterar o valor **ImagePath**, que resultou em uma mensagem de acesso negado.

Apesar dessas limitações, foi identificado um potencial de escalonamento de privilégios por meio da possibilidade de alavancar a subchave **Performance** dentro da estrutura de registro do serviço **RpcEptMapper**, uma subchave não presente por padrão. Isso poderia permitir o registro de DLL e monitoramento de desempenho.

A documentação sobre a subchave **Performance** e sua utilização para monitoramento de desempenho foi consultada, levando ao desenvolvimento de uma DLL de prova de conceito. Esta DLL, demonstrando a implementação das funções **OpenPerfData**, **CollectPerfData** e **ClosePerfData**, foi testada via **rundll32**, confirmando seu sucesso operacional.

O objetivo era forçar o **serviço RPC Endpoint Mapper** a carregar a DLL de Desempenho criada. Observações revelaram que a execução de consultas de classe WMI relacionadas aos Dados de Desempenho via PowerShell resultou na criação de um arquivo de log, permitindo a execução de código arbitrário sob o contexto do **LOCAL SYSTEM**, concedendo assim privilégios elevados.

A persistência e as potenciais implicações dessa vulnerabilidade foram destacadas, ressaltando sua relevância para estratégias pós-exploração, movimentação lateral e evasão de sistemas antivírus/EDR.

Embora a vulnerabilidade tenha sido inicialmente divulgada acidentalmente por meio do script, foi enfatizado que sua exploração está limitada a versões desatualizadas do Windows (por exemplo, **Windows 7 / Server 2008 R2**) e requer acesso local.

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
