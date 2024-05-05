# Modelagem de Ameaças

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) é um mecanismo de busca alimentado pela **dark web** que oferece funcionalidades **gratuitas** para verificar se uma empresa ou seus clientes foram **comprometidos** por **malwares de roubo**.

O principal objetivo do WhiteIntel é combater a apropriação de contas e ataques de ransomware resultantes de malwares que roubam informações.

Você pode acessar o site deles e experimentar o mecanismo gratuitamente em:

{% embed url="https://whiteintel.io" %}

***

## Modelagem de Ameaças

Bem-vindo ao guia abrangente da HackTricks sobre Modelagem de Ameaças! Embarque em uma exploração deste aspecto crítico da cibersegurança, onde identificamos, entendemos e elaboramos estratégias contra vulnerabilidades potenciais em um sistema. Este guia serve como um passo a passo repleto de exemplos do mundo real, software útil e explicações fáceis de entender. Ideal tanto para iniciantes quanto para profissionais experientes que buscam fortalecer suas defesas de cibersegurança.

### Cenários Comumente Utilizados

1. **Desenvolvimento de Software**: Como parte do Ciclo de Vida de Desenvolvimento de Software Seguro (SSDLC), a modelagem de ameaças ajuda na **identificação de possíveis fontes de vulnerabilidades** nas fases iniciais do desenvolvimento.
2. **Teste de Penetração**: O framework Padrão de Execução de Teste de Penetração (PTES) requer a **modelagem de ameaças para entender as vulnerabilidades do sistema** antes de realizar o teste.

### Modelo de Ameaças em Poucas Palavras

Um Modelo de Ameaças é tipicamente representado como um diagrama, imagem ou outra forma de ilustração visual que mostra a arquitetura planejada ou a construção existente de um aplicativo. Ele se assemelha a um **diagrama de fluxo de dados**, mas a distinção chave está em seu design orientado para a segurança.

Os modelos de ameaças frequentemente apresentam elementos marcados em vermelho, simbolizando vulnerabilidades, riscos ou barreiras potenciais. Para simplificar o processo de identificação de riscos, a tríade CIA (Confidencialidade, Integridade, Disponibilidade) é empregada, formando a base de muitas metodologias de modelagem de ameaças, sendo o STRIDE um dos mais comuns. No entanto, a metodologia escolhida pode variar dependendo do contexto e requisitos específicos.

### A Tríade CIA

A Tríade CIA é um modelo amplamente reconhecido no campo da segurança da informação, representando Confidencialidade, Integridade e Disponibilidade. Esses três pilares formam a base sobre a qual muitas medidas de segurança e políticas são construídas, incluindo metodologias de modelagem de ameaças.

1. **Confidencialidade**: Garantir que os dados ou sistema não sejam acessados por indivíduos não autorizados. Este é um aspecto central da segurança, exigindo controles de acesso apropriados, criptografia e outras medidas para evitar violações de dados.
2. **Integridade**: A precisão, consistência e confiabilidade dos dados ao longo de seu ciclo de vida. Este princípio garante que os dados não sejam alterados ou adulterados por partes não autorizadas. Muitas vezes envolve checksums, hashing e outros métodos de verificação de dados.
3. **Disponibilidade**: Isso garante que os dados e serviços sejam acessíveis aos usuários autorizados quando necessário. Isso frequentemente envolve redundância, tolerância a falhas e configurações de alta disponibilidade para manter os sistemas em funcionamento mesmo diante de interrupções.

### Metodologias de Modelagem de Ameaças

1. **STRIDE**: Desenvolvido pela Microsoft, STRIDE é um acrônimo para **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service e Elevation of Privilege**. Cada categoria representa um tipo de ameaça, e essa metodologia é comumente usada na fase de design de um programa ou sistema para identificar ameaças potenciais.
2. **DREAD**: Esta é outra metodologia da Microsoft usada para avaliação de riscos de ameaças identificadas. DREAD significa **Damage potential, Reproducibility, Exploitability, Affected users e Discoverability**. Cada um desses fatores é pontuado, e o resultado é usado para priorizar as ameaças identificadas.
3. **PASTA** (Process for Attack Simulation and Threat Analysis): Esta é uma metodologia de sete etapas, centrada em **risco**. Inclui a definição e identificação de objetivos de segurança, criação de um escopo técnico, decomposição de aplicativos, análise de ameaças, análise de vulnerabilidades e avaliação de riscos/triagem.
4. **Trike**: Esta é uma metodologia baseada em risco que se concentra na defesa de ativos. Ela parte de uma perspectiva de **gestão de riscos** e analisa ameaças e vulnerabilidades nesse contexto.
5. **VAST** (Modelagem de Ameaças Visual, Ágil e Simples): Esta abordagem visa ser mais acessível e se integra a ambientes de desenvolvimento ágil. Ela combina elementos de outras metodologias e se concentra em **representações visuais de ameaças**.
6. **OCTAVE** (Avaliação de Ameaças, Ativos e Vulnerabilidades Operacionalmente Críticas): Desenvolvido pelo Centro de Coordenação CERT, este framework é direcionado para **avaliação de riscos organizacionais em vez de sistemas ou software específicos**.

## Ferramentas

Existem várias ferramentas e soluções de software disponíveis que podem **auxiliar** na criação e gerenciamento de modelos de ameaças. Aqui estão algumas que você pode considerar.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

Uma avançada aranha/crawler web GUI multiplataforma para profissionais de segurança cibernética. O Spider Suite pode ser usado para mapeamento e análise da superfície de ataque.

**Uso**

1. Escolha um URL e Rastreie

<figure><img src="../.gitbook/assets/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Visualize o Gráfico

<figure><img src="../.gitbook/assets/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

Um projeto de código aberto da OWASP, o Threat Dragon é tanto uma aplicação web quanto desktop que inclui diagramação de sistemas, bem como um mecanismo de regras para gerar automaticamente ameaças/mitigações.

**Uso**

1. Criar Novo Projeto

<figure><img src="../.gitbook/assets/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

Às vezes pode parecer assim:

<figure><img src="../.gitbook/assets/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. Iniciar Novo Projeto

<figure><img src="../.gitbook/assets/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. Salvar o Novo Projeto

<figure><img src="../.gitbook/assets/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. Criar seu modelo

Você pode usar ferramentas como o SpiderSuite Crawler para se inspirar, um modelo básico se pareceria com isso

<figure><img src="../.gitbook/assets/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Apenas um pouco de explicação sobre as entidades:

* Processo (A própria entidade, como um Servidor Web ou funcionalidade web)
* Ator (Uma pessoa, como um Visitante do Site, Usuário ou Administrador)
* Linha de Fluxo de Dados (Indicador de Interação)
* Limite de Confiança (Diferentes segmentos de rede ou escopos.)
* Armazenar (Locais onde os dados são armazenados, como Bancos de Dados)

5. Criar uma Ameaça (Passo 1)

Primeiro você deve escolher a camada à qual deseja adicionar uma ameaça

<figure><img src="../.gitbook/assets/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Agora você pode criar a ameaça

<figure><img src="../.gitbook/assets/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Lembre-se de que há uma diferença entre Ameaças de Ator e Ameaças de Processo. Se você adicionar uma ameaça a um Ator, só poderá escolher "Spoofing" e "Repudiation". No entanto, em nosso exemplo, adicionamos uma ameaça a uma entidade de Processo, então veremos isso na caixa de criação de ameaças:

<figure><img src="../.gitbook/assets/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. Concluído

Agora seu modelo finalizado deve se parecer com isso. E assim você cria um modelo de ameaças simples com o OWASP Threat Dragon.

<figure><img src="../.gitbook/assets/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>
### [Ferramenta de Modelagem de Ameaças da Microsoft](https://aka.ms/threatmodelingtool)

Esta é uma ferramenta gratuita da Microsoft que ajuda a encontrar ameaças na fase de design de projetos de software. Utiliza a metodologia STRIDE e é particularmente adequada para aqueles que desenvolvem na pilha da Microsoft.

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) é um mecanismo de busca alimentado pela **dark web** que oferece funcionalidades **gratuitas** para verificar se uma empresa ou seus clientes foram **comprometidos** por **malwares ladrões**.

O objetivo principal do WhiteIntel é combater tomadas de conta e ataques de ransomware resultantes de malwares que roubam informações.

Você pode acessar o site deles e experimentar o mecanismo de busca de forma **gratuita** em:

{% embed url="https://whiteintel.io" %}
