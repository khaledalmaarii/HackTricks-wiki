# ACLs - DACLs/SACLs/ACEs

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=acls-dacls-sacls-aces) para construir e **automatizar fluxos de trabalho** facilmente, impulsionados pelas **ferramentas comunitárias mais avançadas** do mundo.\
Obtenha Acesso Hoje:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=acls-dacls-sacls-aces" %}

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

## **Lista de Controle de Acesso (ACL)**

Uma Lista de Controle de Acesso (ACL) consiste em um conjunto ordenado de Entradas de Controle de Acesso (ACEs) que ditam as proteções para um objeto e suas propriedades. Em essência, uma ACL define quais ações por quais princípios de segurança (usuários ou grupos) são permitidas ou negadas em um determinado objeto.

Existem dois tipos de ACLs:

* **Lista de Controle de Acesso Discricionária (DACL):** Especifica quais usuários e grupos têm ou não têm acesso a um objeto.
* **Lista de Controle de Acesso do Sistema (SACL):** Regula a auditoria de tentativas de acesso a um objeto.

O processo de acesso a um arquivo envolve o sistema verificando o descritor de segurança do objeto em relação ao token de acesso do usuário para determinar se o acesso deve ser concedido e a extensão desse acesso, com base nas ACEs.

### **Componentes Chave**

* **DACL:** Contém ACEs que concedem ou negam permissões de acesso a usuários e grupos para um objeto. É essencialmente a ACL principal que dita os direitos de acesso.
* **SACL:** Usada para auditar o acesso a objetos, onde as ACEs definem os tipos de acesso a serem registrados no Log de Eventos de Segurança. Isso pode ser inestimável para detectar tentativas de acesso não autorizadas ou solucionar problemas de acesso.

### **Interação do Sistema com ACLs**

Cada sessão de usuário está associada a um token de acesso que contém informações de segurança relevantes para essa sessão, incluindo identidades de usuário, grupo e privilégios. Este token também inclui um SID de logon que identifica exclusivamente a sessão.

A Autoridade de Segurança Local (LSASS) processa solicitações de acesso a objetos examinando a DACL em busca de ACEs que correspondam ao princípio de segurança que está tentando acessar. O acesso é imediatamente concedido se nenhuma ACE relevante for encontrada. Caso contrário, a LSASS compara as ACEs com o SID do princípio de segurança no token de acesso para determinar a elegibilidade de acesso.

### **Processo Resumido**

* **ACLs:** Definem permissões de acesso através de DACLs e regras de auditoria através de SACLs.
* **Token de Acesso:** Contém informações de usuário, grupo e privilégio para uma sessão.
* **Decisão de Acesso:** Feita comparando as ACEs da DACL com o token de acesso; SACLs são usadas para auditoria.

### ACEs

Existem **três tipos principais de Entradas de Controle de Acesso (ACEs)**:

* **ACE de Acesso Negado**: Esta ACE nega explicitamente o acesso a um objeto para usuários ou grupos especificados (em uma DACL).
* **ACE de Acesso Permitido**: Esta ACE concede explicitamente acesso a um objeto para usuários ou grupos especificados (em uma DACL).
* **ACE de Auditoria do Sistema**: Posicionada dentro de uma Lista de Controle de Acesso do Sistema (SACL), esta ACE é responsável por gerar logs de auditoria em tentativas de acesso a um objeto por usuários ou grupos. Ela documenta se o acesso foi permitido ou negado e a natureza do acesso.

Cada ACE tem **quatro componentes críticos**:

1. O **Identificador de Segurança (SID)** do usuário ou grupo (ou seu nome principal em uma representação gráfica).
2. Uma **bandeira** que identifica o tipo de ACE (acesso negado, permitido ou auditoria do sistema).
3. **Bandeiras de herança** que determinam se objetos filhos podem herdar a ACE de seu pai.
4. Uma [**máscara de acesso**](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN), um valor de 32 bits que especifica os direitos concedidos ao objeto.

A determinação de acesso é realizada examinando sequencialmente cada ACE até:

* Uma **ACE de Acesso Negado** negar explicitamente os direitos solicitados a um fiduciário identificado no token de acesso.
* **ACE(s) de Acesso Permitido** conceder explicitamente todos os direitos solicitados a um fiduciário no token de acesso.
* Após verificar todas as ACEs, se algum direito solicitado **não foi explicitamente permitido**, o acesso é implicitamente **negado**.

### Ordem das ACEs

A forma como as **ACEs** (regras que dizem quem pode ou não acessar algo) são organizadas em uma lista chamada **DACL** é muito importante. Isso porque, uma vez que o sistema concede ou nega acesso com base nessas regras, ele para de olhar para o resto.

Há uma melhor maneira de organizar essas ACEs, e é chamada de **"ordem canônica."** Este método ajuda a garantir que tudo funcione de maneira suave e justa. Aqui está como funciona para sistemas como **Windows 2000** e **Windows Server 2003**:

* Primeiro, coloque todas as regras que são feitas **especificamente para este item** antes das que vêm de outro lugar, como uma pasta pai.
* Dentro dessas regras específicas, coloque as que dizem **"não" (negar)** antes das que dizem **"sim" (permitir)**.
* Para as regras que vêm de outro lugar, comece com as que vêm da **fonte mais próxima**, como a pasta pai, e depois retroceda a partir daí. Novamente, coloque **"não"** antes de **"sim."**

Essa configuração ajuda de duas maneiras principais:

* Garante que, se houver um **"não"** específico, ele seja respeitado, não importando quais outras regras de **"sim"** estejam presentes.
* Permite que o proprietário de um item tenha a **última palavra** sobre quem pode entrar, antes que quaisquer regras de pastas pai ou mais distantes entrem em jogo.

Ao fazer as coisas dessa maneira, o proprietário de um arquivo ou pasta pode ser muito preciso sobre quem tem acesso, garantindo que as pessoas certas possam entrar e as erradas não possam.

![](https://www.ntfs.com/images/screenshots/ACEs.gif)

Assim, essa **"ordem canônica"** é toda sobre garantir que as regras de acesso sejam claras e funcionem bem, colocando regras específicas primeiro e organizando tudo de maneira inteligente.

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) para construir e **automatizar fluxos de trabalho** facilmente, impulsionados pelas **ferramentas comunitárias mais avançadas** do mundo.\
Obtenha Acesso Hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### Exemplo de GUI

[**Exemplo daqui**](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)

Esta é a aba de segurança clássica de uma pasta mostrando a ACL, DACL e ACEs:

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../.gitbook/assets/classicsectab.jpg)

Se clicarmos no **botão Avançado**, teremos mais opções como herança:

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../.gitbook/assets/aceinheritance.jpg)

E se você adicionar ou editar um Princípio de Segurança:

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../.gitbook/assets/editseprincipalpointers1.jpg)

E por último, temos a SACL na aba de Auditoria:

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../.gitbook/assets/audit-tab.jpg)

### Explicando o Controle de Acesso de Forma Simplificada

Ao gerenciar o acesso a recursos, como uma pasta, usamos listas e regras conhecidas como Listas de Controle de Acesso (ACLs) e Entradas de Controle de Acesso (ACEs). Estas definem quem pode ou não acessar certos dados.

#### Negando Acesso a um Grupo Específico

Imagine que você tem uma pasta chamada Custo, e deseja que todos tenham acesso, exceto a equipe de marketing. Ao configurar as regras corretamente, podemos garantir que a equipe de marketing seja explicitamente negada antes de permitir o acesso a todos os outros. Isso é feito colocando a regra para negar acesso à equipe de marketing antes da regra que permite acesso a todos.

#### Permitindo Acesso a um Membro Específico de um Grupo Negado

Vamos supor que Bob, o diretor de marketing, precise de acesso à pasta Custo, mesmo que a equipe de marketing geralmente não deva ter acesso. Podemos adicionar uma regra específica (ACE) para Bob que lhe concede acesso, e colocá-la antes da regra que nega acesso à equipe de marketing. Dessa forma, Bob obtém acesso apesar da restrição geral em sua equipe.

#### Entendendo as Entradas de Controle de Acesso

As ACEs são as regras individuais em uma ACL. Elas identificam usuários ou grupos, especificam qual acesso é permitido ou negado e determinam como essas regras se aplicam a sub-itens (herança). Existem dois tipos principais de ACEs:

* **ACEs Genéricas**: Estas se aplicam amplamente, afetando todos os tipos de objetos ou distinguindo apenas entre contêineres (como pastas) e não contêineres (como arquivos). Por exemplo, uma regra que permite que os usuários vejam o conteúdo de uma pasta, mas não acessem os arquivos dentro dela.
* **ACEs Específicas de Objeto**: Estas fornecem controle mais preciso, permitindo que regras sejam definidas para tipos específicos de objetos ou até mesmo propriedades individuais dentro de um objeto. Por exemplo, em um diretório de usuários, uma regra pode permitir que um usuário atualize seu número de telefone, mas não suas horas de login.

Cada ACE contém informações importantes, como para quem a regra se aplica (usando um Identificador de Segurança ou SID), o que a regra permite ou nega (usando uma máscara de acesso) e como é herdada por outros objetos.

#### Principais Diferenças Entre os Tipos de ACE

* **ACEs Genéricas** são adequadas para cenários simples de controle de acesso, onde a mesma regra se aplica a todos os aspectos de um objeto ou a todos os objetos dentro de um contêiner.
* **ACEs Específicas de Objeto** são usadas para cenários mais complexos, especialmente em ambientes como o Active Directory, onde você pode precisar controlar o acesso a propriedades específicas de um objeto de maneira diferente.

Em resumo, ACLs e ACEs ajudam a definir controles de acesso precisos, garantindo que apenas os indivíduos ou grupos certos tenham acesso a informações ou recursos sensíveis, com a capacidade de personalizar os direitos de acesso até o nível de propriedades individuais ou tipos de objetos.

### Layout da Entrada de Controle de Acesso

| Campo ACE   | Descrição                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Tipo        | Bandeira que indica o tipo de ACE. Windows 2000 e Windows Server 2003 suportam seis tipos de ACE: Três tipos de ACE genéricos que estão anexados a todos os objetos securáveis. Três tipos de ACE específicas de objeto que podem ocorrer para objetos do Active Directory.                                                                                                                                                                                                                                                            |
| Bandeiras   | Conjunto de bandeiras de bits que controlam herança e auditoria.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Tamanho     | Número de bytes de memória que são alocados para a ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Máscara de Acesso | Valor de 32 bits cujos bits correspondem aos direitos de acesso para o objeto. Os bits podem ser ativados ou desativados, mas o significado da configuração depende do tipo de ACE. Por exemplo, se o bit que corresponde ao direito de ler permissões estiver ativado, e o tipo de ACE for Negar, a ACE nega o direito de ler as permissões do objeto. Se o mesmo bit estiver ativado, mas o tipo de ACE for Permitir, a ACE concede o direito de ler as permissões do objeto. Mais detalhes da Máscara de Acesso aparecem na próxima tabela. |
| SID         | Identifica um usuário ou grupo cujo acesso é controlado ou monitorado por esta ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Layout da Máscara de Acesso

| Bit (Intervalo) | Significado                            | Descrição/Exemplo                       |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | Direitos de Acesso Específicos do Objeto      | Ler dados, Executar, Anexar dados           |
| 16 - 22     | Direitos de Acesso Padrão             | Excluir, Escrever ACL, Escrever Proprietário            |
| 23          | Pode acessar a ACL de segurança            |                                           |
| 24 - 27     | Reservado                           |                                           |
| 28          | Genérico TODOS (Ler, Escrever, Executar) | Tudo abaixo                          |
| 29          | Genérico Executar                    | Todas as coisas necessárias para executar um programa |
| 30          | Genérico Escrever                      | Todas as coisas necessárias para escrever em um arquivo   |
| 31          | Genérico Ler                       | Todas as coisas necessárias para ler um arquivo       |

## Referências

* [https://www.ntfs.com/ntfs-permissions-acl-use.htm](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
* [https://secureidentity.se/acl-dacl-sacl-and-the-ace/](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)
* [https://www.coopware.in2.info/_ntfsacl_ht.htm](https://www.coopware.in2.info/_ntfsacl_ht.htm)

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

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=acls-dacls-sacls-aces) para construir e **automatizar fluxos de trabalho** facilmente, impulsionados pelas **ferramentas comunitárias mais avançadas** do mundo.\
Obtenha Acesso Hoje:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=acls-dacls-sacls-aces" %}
