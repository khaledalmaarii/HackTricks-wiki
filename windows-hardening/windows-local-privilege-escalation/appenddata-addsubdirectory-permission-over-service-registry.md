<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


**O post original está em** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## Resumo
A saída do script indica que o usuário atual possui permissões de escrita em duas chaves de registro:

- `HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`
- `HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`

Para investigar mais a fundo as permissões do serviço RpcEptMapper, o usuário menciona o uso da GUI regedit e destaca a utilidade da aba de Permissões Efetivas na janela de Configurações de Segurança Avançadas. Esta aba permite aos usuários verificar as permissões efetivas concedidas a um usuário ou grupo específico sem inspecionar os ACEs individuais.

A captura de tela fornecida mostra as permissões para a conta de usuário lab-user com privilégios baixos. A maioria das permissões são padrão, como Consultar Valor, mas uma permissão se destaca: Criar Subchave. O nome genérico para esta permissão é AppendData/AddSubdirectory, o que está alinhado com o que foi relatado pelo script.

O usuário prossegue explicando que isso significa que eles não podem modificar certos valores diretamente, mas podem apenas criar novas subchaves. Eles mostram um exemplo onde a tentativa de modificar o valor ImagePath resulta em um erro de acesso negado.

No entanto, eles esclarecem que isso não é um falso positivo e que há uma oportunidade interessante aqui. Eles investigam a estrutura do registro do Windows e descobrem uma maneira potencial de aproveitar a subchave Performance, que não existe por padrão para o serviço RpcEptMapper. Esta subchave poderia potencialmente permitir o registro de DLL e monitoramento de desempenho, oferecendo uma oportunidade para escalonamento de privilégios.

Eles mencionam que encontraram documentação relacionada à subchave Performance e como usá-la para monitoramento de desempenho. Isso os leva a criar uma DLL de prova de conceito e mostrar o código para implementar as funções necessárias: OpenPerfData, CollectPerfData e ClosePerfData. Eles também exportam essas funções para uso externo.

O usuário demonstra testar a DLL usando rundll32 para garantir que ela funcione conforme o esperado, registrando informações com sucesso.

Em seguida, eles explicam que o desafio é enganar o serviço RPC Endpoint Mapper para carregar sua DLL de Performance. Eles mencionam que observaram seu arquivo de log sendo criado ao consultar classes WMI relacionadas a Dados de Desempenho no PowerShell. Isso permite que eles executem código arbitrário no contexto do serviço WMI, que é executado como LOCAL SYSTEM. Isso lhes proporciona acesso elevado e inesperado.

Em conclusão, o usuário destaca a persistência inexplicada dessa vulnerabilidade e seu impacto potencial, que pode se estender a pós-exploração, movimento lateral e evasão de antivírus/EDR.

Eles também mencionam que, embora inicialmente tenham tornado a vulnerabilidade pública involuntariamente por meio de seu script, seu impacto é limitado a versões não suportadas do Windows (por exemplo, Windows 7 / Server 2008 R2) com acesso local.


<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
