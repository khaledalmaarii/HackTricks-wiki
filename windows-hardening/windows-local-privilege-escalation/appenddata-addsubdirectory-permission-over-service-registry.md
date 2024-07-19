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


**O post original é** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## Resumo

Duas chaves de registro foram encontradas como graváveis pelo usuário atual:

- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**

Foi sugerido verificar as permissões do serviço **RpcEptMapper** usando a **GUI do regedit**, especificamente a aba **Permissões Eficazes** da janela **Configurações de Segurança Avançadas**. Essa abordagem permite a avaliação das permissões concedidas a usuários ou grupos específicos sem a necessidade de examinar cada Entrada de Controle de Acesso (ACE) individualmente.

Uma captura de tela mostrou as permissões atribuídas a um usuário com poucos privilégios, entre as quais a permissão **Criar Subchave** era notável. Essa permissão, também referida como **AppendData/AddSubdirectory**, corresponde às descobertas do script.

A incapacidade de modificar certos valores diretamente, mas a capacidade de criar novas subchaves, foi observada. Um exemplo destacado foi uma tentativa de alterar o valor **ImagePath**, que resultou em uma mensagem de acesso negado.

Apesar dessas limitações, um potencial para escalonamento de privilégios foi identificado através da possibilidade de aproveitar a subchave **Performance** dentro da estrutura de registro do serviço **RpcEptMapper**, uma subchave que não está presente por padrão. Isso poderia permitir o registro de DLL e monitoramento de desempenho.

A documentação sobre a subchave **Performance** e sua utilização para monitoramento de desempenho foi consultada, levando ao desenvolvimento de uma DLL de prova de conceito. Esta DLL, demonstrando a implementação das funções **OpenPerfData**, **CollectPerfData** e **ClosePerfData**, foi testada via **rundll32**, confirmando seu sucesso operacional.

O objetivo era forçar o **serviço de Mapeamento de Endpoint RPC** a carregar a DLL de Performance criada. Observações revelaram que a execução de consultas de classe WMI relacionadas a Dados de Desempenho via PowerShell resultou na criação de um arquivo de log, permitindo a execução de código arbitrário sob o contexto de **SISTEMA LOCAL**, concedendo assim privilégios elevados.

A persistência e as potenciais implicações dessa vulnerabilidade foram destacadas, ressaltando sua relevância para estratégias de pós-exploração, movimento lateral e evasão de sistemas antivírus/EDR.

Embora a vulnerabilidade tenha sido inicialmente divulgada inadvertidamente através do script, foi enfatizado que sua exploração é restrita a versões desatualizadas do Windows (por exemplo, **Windows 7 / Server 2008 R2**) e requer acesso local.

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
