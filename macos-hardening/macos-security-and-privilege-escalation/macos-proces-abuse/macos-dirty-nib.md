# macOS Dirty NIB

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
{% endhint %}

**Para mais detalhes sobre a técnica, confira o post original em:** [**https://blog.xpnsec.com/dirtynib/**](https://blog.xpnsec.com/dirtynib/) e o seguinte post por [**https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/**](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)**.** Aqui está um resumo:

### O que são arquivos Nib

Arquivos Nib (abreviação de NeXT Interface Builder), parte do ecossistema de desenvolvimento da Apple, são destinados a definir **elementos de UI** e suas interações em aplicativos. Eles abrangem objetos serializados, como janelas e botões, e são carregados em tempo de execução. Apesar de seu uso contínuo, a Apple agora defende o uso de Storyboards para uma visualização mais abrangente do fluxo de UI.

O arquivo Nib principal é referenciado no valor **`NSMainNibFile`** dentro do arquivo `Info.plist` do aplicativo e é carregado pela função **`NSApplicationMain`** executada na função `main` do aplicativo.

### Processo de Injeção de Nib Sujo

#### Criando e Configurando um Arquivo NIB

1. **Configuração Inicial**:
* Crie um novo arquivo NIB usando o XCode.
* Adicione um Objeto à interface, definindo sua classe como `NSAppleScript`.
* Configure a propriedade `source` inicial através de Atributos de Tempo de Execução Definidos pelo Usuário.
2. **Gadget de Execução de Código**:
* A configuração facilita a execução de AppleScript sob demanda.
* Integre um botão para ativar o objeto `Apple Script`, acionando especificamente o seletor `executeAndReturnError:`.
3. **Teste**:
* Um simples Apple Script para fins de teste:

```bash
set theDialogText to "PWND"
display dialog theDialogText
```
* Teste executando no depurador do XCode e clicando no botão.

#### Alvo de um Aplicativo (Exemplo: Pages)

1. **Preparação**:
* Copie o aplicativo alvo (por exemplo, Pages) para um diretório separado (por exemplo, `/tmp/`).
* Inicie o aplicativo para contornar problemas do Gatekeeper e armazená-lo em cache.
2. **Substituindo o Arquivo NIB**:
* Substitua um arquivo NIB existente (por exemplo, NIB do Painel Sobre) pelo arquivo DirtyNIB criado.
3. **Execução**:
* Acione a execução interagindo com o aplicativo (por exemplo, selecionando o item de menu `Sobre`).

#### Prova de Conceito: Acessando Dados do Usuário

* Modifique o AppleScript para acessar e extrair dados do usuário, como fotos, sem o consentimento do usuário.

### Exemplo de Código: Arquivo .xib Malicioso

* Acesse e revise um [**exemplo de um arquivo .xib malicioso**](https://gist.github.com/xpn/16bfbe5a3f64fedfcc1822d0562636b4) que demonstra a execução de código arbitrário.

### Outro Exemplo

No post [https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/) você pode encontrar um tutorial sobre como criar um nib sujo.&#x20;

### Abordando Restrições de Lançamento

* Restrições de Lançamento dificultam a execução de aplicativos de locais inesperados (por exemplo, `/tmp`).
* É possível identificar aplicativos que não estão protegidos por Restrições de Lançamento e direcioná-los para injeção de arquivo NIB.

### Proteções Adicionais do macOS

A partir do macOS Sonoma, modificações dentro de pacotes de aplicativos são restritas. No entanto, métodos anteriores envolviam:

1. Copiar o aplicativo para um local diferente (por exemplo, `/tmp/`).
2. Renomear diretórios dentro do pacote do aplicativo para contornar as proteções iniciais.
3. Após executar o aplicativo para registrar com o Gatekeeper, modificar o pacote do aplicativo (por exemplo, substituindo MainMenu.nib por Dirty.nib).
4. Renomear os diretórios de volta e executar novamente o aplicativo para executar o arquivo NIB injetado.

**Nota**: Atualizações recentes do macOS mitigaram essa exploração, impedindo modificações de arquivos dentro de pacotes de aplicativos após o cache do Gatekeeper, tornando a exploração ineficaz.

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
{% endhint %}
