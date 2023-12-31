# macOS Keychain

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Principais Keychains

* O **User Keychain** (`~/Library/Keychains/login.keycahin-db`), que é usado para armazenar **credenciais específicas do usuário** como senhas de aplicativos, senhas da internet, certificados gerados pelo usuário, senhas de rede e chaves públicas/privadas geradas pelo usuário.
* O **System Keychain** (`/Library/Keychains/System.keychain`), que armazena **credenciais de todo o sistema** como senhas de WiFi, certificados raiz do sistema, chaves privadas do sistema e senhas de aplicativos do sistema.

### Acesso ao Keychain de Senhas

Esses arquivos, embora não tenham proteção inerente e possam ser **baixados**, são criptografados e requerem a **senha em texto claro do usuário para serem descriptografados**. Uma ferramenta como [**Chainbreaker**](https://github.com/n0fate/chainbreaker) poderia ser usada para descriptografia.

## Proteções das Entradas do Keychain

### ACLs

Cada entrada no keychain é regida por **Listas de Controle de Acesso (ACLs)** que ditam quem pode realizar várias ações na entrada do keychain, incluindo:

* **ACLAuhtorizationExportClear**: Permite ao detentor obter o texto claro do segredo.
* **ACLAuhtorizationExportWrapped**: Permite ao detentor obter o texto claro criptografado com outra senha fornecida.
* **ACLAuhtorizationAny**: Permite ao detentor realizar qualquer ação.

As ACLs são acompanhadas por uma **lista de aplicativos confiáveis** que podem realizar essas ações sem solicitação. Isso pode ser:

* &#x20;**N`il`** (nenhuma autorização necessária, **todos são confiáveis**)
* Uma lista **vazia** (**ninguém** é confiável)
* **Lista** de **aplicativos específicos**.

Além disso, a entrada pode conter a chave **`ACLAuthorizationPartitionID`,** que é usada para identificar o **teamid, apple,** e **cdhash.**

* Se o **teamid** for especificado, então para **acessar o valor da entrada** **sem** uma **solicitação**, o aplicativo usado deve ter o **mesmo teamid**.
* Se o **apple** for especificado, então o aplicativo precisa ser **assinado** pela **Apple**.
* Se o **cdhash** for indicado, então o **aplicativo** deve ter o específico **cdhash**.

### Criando uma Entrada no Keychain

Quando uma **nova** **entrada** é criada usando **`Keychain Access.app`**, as seguintes regras se aplicam:

* Todos os aplicativos podem criptografar.
* **Nenhum aplicativo** pode exportar/descriptografar (sem solicitar ao usuário).
* Todos os aplicativos podem ver a verificação de integridade.
* Nenhum aplicativo pode alterar as ACLs.
* O **partitionID** é definido como **`apple`**.

Quando um **aplicativo cria uma entrada no keychain**, as regras são um pouco diferentes:

* Todos os aplicativos podem criptografar.
* Apenas o **aplicativo criador** (ou quaisquer outros aplicativos explicitamente adicionados) podem exportar/descriptografar (sem solicitar ao usuário).
* Todos os aplicativos podem ver a verificação de integridade.
* Nenhum aplicativo pode alterar as ACLs.
* O **partitionID** é definido como **`teamid:[teamID aqui]`**.

## Acessando o Keychain

### `security`
```bash
# Dump all metadata and decrypted secrets (a lot of pop-ups)
security dump-keychain -a -d

# Find generic password for the "Slack" account and print the secrets
security find-generic-password -a "Slack" -g

# Change the specified entrys PartitionID entry
security set-generic-password-parition-list -s "test service" -a "test acount" -S
```
### APIs

{% hint style="success" %}
A **enumeração de chaveiros e o despejo** de segredos que **não gerarão um aviso** podem ser feitos com a ferramenta [**LockSmith**](https://github.com/its-a-feature/LockSmith)
{% endhint %}

Listar e obter **informações** sobre cada entrada do chaveiro:

* A API **`SecItemCopyMatching`** fornece informações sobre cada entrada e existem alguns atributos que você pode definir ao usá-la:
* **`kSecReturnData`**: Se verdadeiro, tentará descriptografar os dados (defina como falso para evitar pop-ups potenciais)
* **`kSecReturnRef`**: Obter também referência ao item do chaveiro (defina como verdadeiro caso depois você veja que pode descriptografar sem pop-up)
* **`kSecReturnAttributes`**: Obter metadados sobre as entradas
* **`kSecMatchLimit`**: Quantos resultados retornar
* **`kSecClass`**: Que tipo de entrada do chaveiro

Obter **ACLs** de cada entrada:

* Com a API **`SecAccessCopyACLList`** você pode obter o **ACL para o item do chaveiro**, e ela retornará uma lista de ACLs (como `ACLAuhtorizationExportClear` e os outros mencionados anteriormente) onde cada lista tem:
* Descrição
* **Lista de Aplicações Confiáveis**. Isso poderia ser:
* Um aplicativo: /Applications/Slack.app
* Um binário: /usr/libexec/airportd
* Um grupo: group://AirPort

Exportar os dados:

* A API **`SecKeychainItemCopyContent`** obtém o texto claro
* A API **`SecItemExport`** exporta as chaves e certificados, mas pode ser necessário definir senhas para exportar o conteúdo criptografado

E estes são os **requisitos** para poder **exportar um segredo sem um aviso**:

* Se **1+ aplicações confiáveis** listadas:
* Necessário as **autorizações** apropriadas (**`Nil`**, ou fazer **parte** da lista permitida de aplicações na autorização para acessar a informação secreta)
* Necessário que a assinatura de código corresponda ao **PartitionID**
* Necessário que a assinatura de código corresponda à de uma **aplicação confiável** (ou ser membro do correto KeychainAccessGroup)
* Se **todas as aplicações confiáveis**:
* Necessário as **autorizações** apropriadas
* Necessário que a assinatura de código corresponda ao **PartitionID**
* Se **nenhum PartitionID**, então isso não é necessário

{% hint style="danger" %}
Portanto, se houver **1 aplicação listada**, você precisará **injetar código nessa aplicação**.

Se **apple** estiver indicado no **partitionID**, você poderia acessá-lo com **`osascript`** então qualquer coisa que confie em todas as aplicações com apple no partitionID. **`Python`** também poderia ser usado para isso.
{% endhint %}

### Dois atributos adicionais

* **Invisível**: É um indicador booleano para **ocultar** a entrada do aplicativo **UI** Keychain
* **Geral**: É para armazenar **metadados** (portanto, NÃO É CRIPTOGRAFADO)
* A Microsoft estava armazenando em texto claro todos os tokens de atualização para acessar pontos finais sensíveis.

## Referências

* [**#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas**](https://www.youtube.com/watch?v=jKE1ZW33JpY)

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**merchandising oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-me no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas dicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
