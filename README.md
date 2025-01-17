
# Script para logs Firewall PaloAlto

## Descrição
Esta aplicação desenvolvida  para gerenciar logs de firewalls paloalto com  criação de redução de linhas de logs e padronização.

---

**Foi realizado um parâmetro para identificar automaticamente se o logs são os mesmos e reduzir**

---

### Incrementações:
- Implementar **Inteligência Artificial** para verificar automaticamente os logs detectar ameaça e abrir um chamado.
- Integração com um banco de dados para armazenamento persistente dos logs.

---

## Funcionalidades
O codigo oferece os seguintes parametros:
- **`Buscar logs `** - Listar todos os logs.
- **`Novo arquivo reduzido`** - Adicionar um novo csv com dados reduzidos.
- **`Db com os logs`** - Atualizar um logs no banco de dados existente.


---

## Configuração e Instalação

### Requisitos Locais
- **Python** 3.12 ou superior.
- **Bibliotecas Python**:
  - Flask
  - Pytest (para testes).
  - schedule

---

### Passos para Implantação Local

1. **Clone o repositório:**
   ```bash
   git clone <url do repositorio>
   cd <para onde foi copiado o arquivo>

2. **Crie e ative o ambiente virtual:**
  python -m venv venv
  source venv/bin/activate  # No Windows: venv\\Scripts\\activate

3. **Instale as dependências:**
  pip install -r requirements.txt

4. **Execute a aplicação localmente:**
  python3 Fpaloalto.py



---
## Implantação no Google Cloud Platform (GCP)
 - Pré-requisitos
 - Conta no Google Cloud Platform.
 - Ativação do projeto GCP.
 - Cloud SDK instalado localmente.
 - App Engine habilitado no GCP.


**Passos**
  1. Autenticação no GCP:
  gcloud auth login
  
  2. Selecione o projeto GCP:
  gcloud config set project <SEU_ID_DO_PROJETO>

  3. Prepare o ambiente para App Engine:
  gcloud app create --region=<REGIAO>

  4. Adicione o arquivo app.yaml: Crie o arquivo app.yaml na raiz do projeto:
  runtime: python310
  entrypoint: python app.py
  env: standard

 5. Instale as dependências localmente para GCP: requirements.txt:
  
  requests==2.31.0
  pandas==1.5.3
  pyodbc==4.0.35
  schedule==1.1.0
  python-dotenv==1.0.0


 6. Realize o deploy da aplicação:
  gcloud app deploy
  
7. Acesse a URL fornecida pelo GCP: Após o deploy, você verá uma mensagem com a URL da aplicação:
  Deployed service [default] to [https://<SEU_PROJETO>.uc.r.appspot.com]
---

## Testes Automatizados
**Executar Testes Locais**
 1. Instale o Pytest:
    pip install pytest

 2. Execute os testes:
   pytest -vv

**Executar Testes no GCP**
Atualize o arquivo test_app.py para utilizar o Base URL do GCP: 
  BASE_URL = "https://<SEU_PROJETO>.uc.r.appspot.com/items"
  Execute os testes:
  pytest test_app.py







