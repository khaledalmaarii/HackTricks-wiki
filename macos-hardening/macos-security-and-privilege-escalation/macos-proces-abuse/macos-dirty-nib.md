# macOS Dirty NIB

<details>

<summary><strong>Aprenda hacking AWS do zero ao avançado com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

**Para mais detalhes sobre a técnica, confira o post original em: [https://blog.xpnsec.com/dirtynib/**](https://blog.xpnsec.com/dirtynib/).** Aqui está um resumo:

Os arquivos NIB, parte do ecossistema de desenvolvimento da Apple, são destinados a definir **elementos de UI** e suas interações em aplicativos. Eles englobam objetos serializados como janelas e botões, e são carregados em tempo de execução. Apesar de seu uso contínuo, a Apple agora defende o uso de Storyboards para uma visualização mais abrangente do fluxo de UI.

### Preocupações de Segurança com Arquivos NIB
É crucial notar que os **arquivos NIB podem representar um risco de segurança**. Eles têm o potencial de **executar comandos arbitrários**, e alterações nos arquivos NIB dentro de um aplicativo não impedem o Gatekeeper de executar o aplicativo, representando uma ameaça significativa.

### Processo de Injeção de Dirty NIB
#### Criando e Configurando um Arquivo NIB
1. **Configuração Inicial**:
- Crie um novo arquivo NIB usando o XCode.
- Adicione um Objeto à interface, definindo sua classe como `NSAppleScript`.
- Configure a propriedade `source` inicial via Atributos de Tempo de Execução Definidos pelo Usuário.

2. **Gadget de Execução de Código**:
- A configuração facilita a execução de AppleScript sob demanda.
- Integre um botão para ativar o objeto `Apple Script`, acionando especificamente o seletor `executeAndReturnError:`.

3. **Teste**:
- Um Apple Script simples para fins de teste:
```bash
set theDialogText to "PWND"
display dialog theDialogText
```
- Teste executando no depurador XCode e clicando no botão.

#### Mirando em um Aplicativo (Exemplo: Pages)
1. **Preparação**:
- Copie o aplicativo alvo (por exemplo, Pages) para um diretório separado (por exemplo, `/tmp/`).
- Inicie o aplicativo para contornar problemas com o Gatekeeper e armazene em cache.

2. **Sobrescrevendo o Arquivo NIB**:
- Substitua um arquivo NIB existente (por exemplo, Painel Sobre NIB) pelo arquivo DirtyNIB criado.

3. **Execução**:
- Acione a execução interagindo com o aplicativo (por exemplo, selecionando o item de menu `Sobre`).

#### Prova de Conceito: Acessando Dados do Usuário
- Modifique o AppleScript para acessar e extrair dados do usuário, como fotos, sem o consentimento do usuário.

### Exemplo de Código: Arquivo .xib Malicioso
- Acesse e revise um [**exemplo de um arquivo .xib malicioso**](https://gist.github.com/xpn/16bfbe5a3f64fedfcc1822d0562636b4) que demonstra a execução de código arbitrário.

### Abordando Restrições de Inicialização
- Restrições de Inicialização impedem a execução do aplicativo em locais inesperados (por exemplo, `/tmp`).
- É possível identificar aplicativos não protegidos por Restrições de Inicialização e direcioná-los para a injeção de arquivo NIB.

### Proteções Adicionais do macOS
A partir do macOS Sonoma em diante, modificações dentro de pacotes de aplicativos são restritas. No entanto, métodos anteriores envolviam:
1. Copiar o aplicativo para um local diferente (por exemplo, `/tmp/`).
2. Renomear diretórios dentro do pacote do aplicativo para contornar proteções iniciais.
3. Após executar o aplicativo para registrar no Gatekeeper, modificar o pacote do aplicativo (por exemplo, substituindo MainMenu.nib por Dirty.nib).
4. Renomear os diretórios de volta e executar novamente o aplicativo para executar o arquivo NIB injetado.

**Nota**: Atualizações recentes do macOS mitigaram essa exploração ao impedir modificações de arquivos dentro dos pacotes de aplicativos após o cache do Gatekeeper, tornando a exploração ineficaz.


<details>

<summary><strong>Aprenda hacking AWS do zero ao avançado com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
