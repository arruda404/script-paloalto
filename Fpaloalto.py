
import os
import subprocess
import datetime
import requests
import json
import time
import csv
import urllib.parse as urlencode
import xml.etree.ElementTree as ET
import pandas as pd
import pyodbc
import schedule
import time
from datetime import datetime
import dotenv

host= ''
apiUser = ""
# Obtenha os valores das variáveis de ambiente NAO SE DEVE MANTER DADOS DIRETAMENTE NO CODIGO AQUI E PARA MOSTRAR O PADRAO
server_name = ''
database_name = ''
username = ''
password = ''
user = ''
pws = ''

def job():
    print("Executando o código inicio", datetime.now().strftime("%d/%m/%Y %H:%M:%S"))


    def apagarAntigos():
        ARQUIVO_TEMPORARIO = "/tmp/ULTIMA_EXECUCAO.txt"
        data_atual = datetime.datetime.now().strftime("%Y-%m-%d")
        
        if os.path.exists(ARQUIVO_TEMPORARIO):
            with open(ARQUIVO_TEMPORARIO, "r") as f:
                data_controle = f.read().strip()
            
            if data_atual != data_controle:
                server_name = ''
                database_name = ''
                username = ''
                password = ''
                
                delete_command = "DELETE FROM tb_Log WHERE time_generated < DATEADD(DAY, -3, GETDATE());"
                
                subprocess.run([
                    "/opt/mssql-tools/bin/sqlcmd",
                    "-S", server_name,
                    "-d", database_name,
                    "-U", username,
                    "-P", password,
                    "-Q", delete_command
                ], check=True, text=True, stdout=open("linhasAfetadas.txt", "w"))
                
                with open(ARQUIVO_TEMPORARIO, "w") as f:
                    f.write(data_atual)

    
    # Ping realizado aqui
    api_host = ''
    username = ''
    password = ''

    try:
        # Realiza o ping
        response = os.system("ping " + api_host)
        # Verifica se o ping foi bem-sucedido
        if response == 0:
            # Código caso o ping seja respondido
            urlApiKey = f'https://{api_host}/api/?type=keygen'

            # Credenciais de autenticação para a solicitação GET
            auth_credentials = (username), (password)

            # Fazendo a solicitação GET para pegar a API-KEY com autenticação básica
            response = requests.get(urlApiKey, auth=auth_credentials, verify=False)

            # Parâmetros para a solicitação GET
            params1 = {
                'user': (username),
                'password': (password)
            }

            # Headers (se necessário)
            headers1 = {'Content-Type': 'application/json'}

            # Fazendo a solicitação GET para pegar a API-KEY com parâmetros
            response = requests.get(urlApiKey, params=params1, headers=headers1, verify=False)

            response_xml = response.text
            root = ET.fromstring(response_xml)
            # Encontrar e armazenar o valor da tag <key>
            key_value = root.find('.//key').text
            print("Valor da chave:", key_value)
            ip = (api_host)  # IP FW
            key = key_value
            queryJobID = "(receive_time geq '2025/01/01 00:00:05')"  # Mudar aqui pra query que vc quer rodar no FW
            Pegar_jobid = requests.post(
                f"https://{ip}/api/?key={key}&type=log&log-type=threat&nlogs=5000&query={queryJobID}", timeout=5,
                verify=False)
            root_JobID = ET.fromstring(Pegar_jobid.text)
            job_element_JobID = root_JobID.find('.//job')
            job_ID = job_element_JobID.text

            # Request pra pegar os dados do JobID que geramos acima, com a query usada acima
            JobResult = requests.post(f"https://{ip}/api?key={key}&type=log&action=get&job-id={job_ID}", timeout=5,
                                    verify=False)
            print(f"Resultado do Job numero {job_ID}: ", JobResult)

            # Aqui usando a biblioteca XML vamos pegar os valores dos campos do FW um a um
            rootJobResult = ET.fromstring(JobResult.text)
            LogEntries = rootJobResult.findall('.//entry')

            # Lista para armazenar todas as entradas
            conteudo = []

            for entry in LogEntries:
                # Inicializando as variáveis para cada entrada
                TimeGenerated = DeviceName = SourceIP = DestinationIP = ThreatID = ThreatName = Rule = Application = Protocol = From = To = SourcePort = DestinationPort = Action = Severity = None

                # Definindo as variáveis se os elementos estiverem presentes
                TimeGenerated_element = entry.find('time_generated')
                if TimeGenerated_element is not None:
                    TimeGenerated = TimeGenerated_element.text

                DeviceName_element = entry.find('device_name')
                if DeviceName_element is not None:
                    DeviceName = DeviceName_element.text

                SourceIP_element = entry.find('src')
                if SourceIP_element is not None:
                    SourceIP = SourceIP_element.text

                DestinationIP_element = entry.find('dst')
                if DestinationIP_element is not None:
                    DestinationIP = DestinationIP_element.text

                ThreatID_element = entry.find('threatid')
                if ThreatID_element is not None:
                    ThreatID = ThreatID_element.text

                ThreatName_element = entry.find('threat_name')
                if ThreatName_element is not None:
                    ThreatName = ThreatName_element.text

                Rule_element = entry.find('rule')
                if Rule_element is not None:
                    Rule = Rule_element.text

                Application_element = entry.find('app')
                if Application_element is not None:
                    Application = Application_element.text

                Protocol_element = entry.find('proto')
                if Protocol_element is not None:
                    Protocol = Protocol_element.text

                From_element = entry.find('from')
                if From_element is not None:
                    From = From_element.text

                To_element = entry.find('to')
                if To_element is not None:
                    To = To_element.text

                SourcePort_element = entry.find('sport')
                if SourcePort_element is not None:
                    SourcePort = SourcePort_element.text

                DestinationPort_element = entry.find('dport')
                if DestinationPort_element is not None:
                    DestinationPort = DestinationPort_element.text

                Action_element = entry.find('action')
                if Action_element is not None:
                    Action = Action_element.text

                Severity_element = entry.find('severity')
                if Severity_element is not None:
                    Severity = Severity_element.text

                # Adicionando as informações da entrada atual à lista de conteúdo
                conteudo.append({
                    "TimeGenerated": TimeGenerated ,  # Valor padrão se vazio
                    "DeviceName": DeviceName if DeviceName else "not-applicable",            # Valor padrão se vazio
                    "SourceIP": SourceIP if SourceIP else "not-applicable",                  # Valor padrão se vazio
                    "DestinationIP": DestinationIP if DestinationIP else "not-applicable",  # Valor padrão se vazio
                    "ThreatID": ThreatID if ThreatID else "not-applicable",                  # Valor padrão se vazio
                    "ThreatName": ThreatName if ThreatName else "not-applicable",            # Valor padrão se vazio
                    "Rule": Rule if Rule else "not-applicable",                              # Valor padrão se vazio
                    "Application": Application if Application else "not-applicable",        # Valor padrão se vazio
                    "Protocol": Protocol if Protocol else "not-applicable",                  # Valor padrão se vazio
                    "From": From if From else "not-applicable",                              # Valor padrão se vazio
                    "To": To if To else "not-applicable",                                    # Valor padrão se vazio
                    "SourcePort": SourcePort if SourcePort else "not-applicable",            # Valor padrão se vazio
                    "DestinationPort": DestinationPort if DestinationPort else "not-pplicable",  # Valor padrão se vazio
                    "Action": Action if Action else "not-applicable",                        # Valor padrão se vazio
                    "Severity": Severity if Severity else "not-applicable"                   # Valor padrão se vazio
                })

            # Caminho para o arquivo CSV
            caminho_arquivo_csv = "LogsFW.csv"
            

            # Lista de chaves que representam o cabeçalho do CSV
            cabecalho = [
                "TimeGenerated", "DeviceName", "SourceIP", "DestinationIP",
                "ThreatID", "ThreatName", "Rule", "Application", "Protocol",
                "From", "To", "SourcePort", "DestinationPort", "Action", "Severity"
            ]

            # Escrevendo no arquivo CSV
            with open(caminho_arquivo_csv, "a", newline="") as arquivo_csv:
                escritor_csv = csv.DictWriter(arquivo_csv, fieldnames=cabecalho)
                # Verifica se o arquivo já existe, se não, escreve o cabeçalho
                if arquivo_csv.tell() == 0:
                    escritor_csv.writeheader()
                # Escreve o conteúdo
                for linha in conteudo:
                    escritor_csv.writerow(linha)
        else:
            # Caso o ping falhe, salva diretamente no CSV
            conteudo = [
                {
                    "TimeGenerated": datetime.now().strftime("%Y/%m/%d %H:%M:%S"),
                    "DeviceName": "Nome-do-Firewall",
                    "SourceIP": "IP-do-Firewall",
                    "DestinationIP":"Host Inacessível",
                    "ThreatID": "Host Inacessível",
                    "ThreatName": "Host Inacessível",
                    "Rule": "Host Inacessível",
                    "Application": "Host Inacessível",
                    "Protocol": "Host Inacessível",
                    "From": "Host Inacessível",
                    "To": "Host Inacessível",
                    "SourcePort": "Host Inacessível",
                    "DestinationPort": "Host Inacessível",
                    "Action": "Host Inacessível",
                    "Severity": "Alta"
                }
            ]
            # Caminho para o arquivo CSV
            caminho_arquivo_csv = "LogsFW.csv"

            # Lista de chaves que representam o cabeçalho do CSV
            cabecalho = [
                "TimeGenerated", "DeviceName", "SourceIP", "DestinationIP",
                "ThreatID", "ThreatName", "Rule", "Application", "Protocol",
                "From", "To", "SourcePort", "DestinationPort", "Action", "Severity"
            ]

            # Escrevendo no arquivo CSV
            with open(caminho_arquivo_csv, "a", newline="") as arquivo_csv:
                escritor_csv = csv.DictWriter(arquivo_csv, fieldnames=cabecalho)
                # Verifica se o arquivo já existe, se não, escreve o cabeçalho
                if arquivo_csv.tell() == 0:
                    escritor_csv.writeheader()
                # Escreve o conteúdo
                for linha in conteudo:
                    escritor_csv.writerow(linha)
    except Exception as e:
        print("Erro durante o ping:", e)
    def comparalog():
        # Read the original CSV file
        original_csv = 'LogsFW.csv'
        with open(original_csv, 'r') as f:
            original_reader = csv.reader(f)
            original_data = [row for row in original_reader]

        # Read the FW CSV file
        reduced_csv = 'Logs300.csv'
        reduced_data = []
        with open(reduced_csv, 'r') as f:
            reduced_reader = csv.reader(f)
            for row in reduced_reader:
                reduced_data.append(row)

        # Compare the two CSV files and save any new information
        new_data = []
        for row in original_data:
            if row not in reduced_data:
                new_data.append(row)

        if new_data:
            # Save new data to a new CSV file
            new_csv = 'novos_dados.csv'
            
            # Adiciona o cabeçalho
            colunas_chave_nomes = [
                "TimeGenerated","DeviceName", "SourceIP", "DestinationIP",
                "ThreatID", "ThreatName", "Rule", "Application", "Protocol",
                "From", "To", "SourcePort", "DestinationPort", "Action", "Severity"
            ]
            with open(new_csv, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(colunas_chave_nomes)
                writer.writerows(new_data)
            
            print('Novos dados salvos no arquivo:', new_csv)
        else:
            print('Nenhuma nova informação encontrada.')

    comparalog()

    def reduzir_csv():
        arquivo_entrada = "novos_dados.csv"  # Arquivo de entrada é o Logs.csv gerado anteriormente
        arquivo_saida = "reduzido.csv"  # Arquivo de saída será o reduzido.csv
        colunas_chave_nomes = [
            "DeviceName", "SourceIP", "DestinationIP",
            "ThreatID", "ThreatName", "Rule", "Application", "Protocol",
            "From", "To", "SourcePort", "DestinationPort", "Action", "Severity"
        ]

        print("Arquivo de entrada:", arquivo_entrada)
        
        # Carregar o CSV para um DataFrame
        try:
            df = pd.read_csv(arquivo_entrada, encoding='latin1')
        except Exception as e:
            print(f"Erro ao carregar o arquivo CSV: {e}")
            return

        print("Dados carregados com sucesso.")
        
        # Converter a coluna TimeGenerated para datetime, tratando erros
        try:
            df['TimeGenerated'] = pd.to_datetime(df['TimeGenerated'], errors='coerce')
            # Remover linhas onde TimeGenerated é inválido
            df = df.dropna(subset=['TimeGenerated'])
        except Exception as e:
            print(f"Erro ao converter TimeGenerated: {e}")
            return

        # Arredondar os valores de tempo para intervalos de 5 minutos
        df['TimeGenerated'] = df['TimeGenerated'].dt.floor('5min')

        # Agrupar por colunas-chave e contagem de eventos
        agrupado = df.groupby(colunas_chave_nomes + ['TimeGenerated']).size().reset_index(name='Quantidade')

        # Salvar o DataFrame resumido em um novo arquivo CSV
        try:
            agrupado.to_csv(arquivo_saida, index=False)
            print(f"Arquivo reduzido salvo com sucesso em: {arquivo_saida}")
        except Exception as e:
            print(f"Erro ao salvar o arquivo reduzido: {e}")

    reduzir_csv()

    def inserir_dados_SQL():
        #ESSES DADOS NAO DEVEM ESTAR AQUI SOMENTE PARA ILUSTRACAO DO MODELO
        server = 'nomedoservidor'
        database = 'bancodedados'
        username = 'usuariodb'
        password ='senhadodb'
        driver = '{ODBC Driver 17 for SQL Server}' # Altere para o driver apropriado, se necessário
    
        # Carregar o arquivo CSV
        df = pd.read_csv('reduzido.csv')
        

        # Conectar ao banco de dados
        conn = pyodbc.connect(f"DRIVER={driver};SERVER={server};DATABASE={database};UID={username};PWD={password}")
        cursor = conn.cursor()

        # Iniciar contador de tempo
        start_time = time.time()
        # Iterar sobre as linhas do DataFrame e inserir os dados na tabela SQL Server
        for index, row in df.iterrows():
            # Verificar se o valor da coluna 'TimeGenerated' é uma string
            if isinstance(row['TimeGenerated'], str):
                time_generated = row['TimeGenerated']  # Valor já é uma string
            else:
                # Converter o valor para um objeto datetime
                time_generated = pd.to_datetime(row['TimeGenerated']).strftime('%Y-%m-%d %H:%M:%S')

            # Insira os dados na tabela
            insert_query = """
            INSERT INTO tb_ThreatsLog (DeviceName, SourceIP, DestinationIP, ThreatID, ThreatName, [Rule], [Application], Protocol, [From], [To], SourcePort, DestinationPort, Action, Severity, Quantidade, TimeGenerated)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            cursor.execute(insert_query, (row['DeviceName'], row['SourceIP'], row['DestinationIP'], row['ThreatID'], row['ThreatName'], row['Rule'], row['Application'], row['Protocol'], row['From'], row['To'], row['SourcePort'], row['DestinationPort'], row['Action'], row['Severity'], row['Quantidade'], time_generated))

        # Commit das alterações
        conn.commit()

    # Chamar a função para inserir os dados

        # Tempo total de execução
        end_time = time.time()
        total_time = end_time - start_time
        minuto= total_time /60
        # Arredondar para 2 casas decimais e converter para string
        total_time_formatted = "{:.2f}".format(minuto)
        print(f"Tempo de execução: {total_time_formatted} Minutos")
        print("Dados inseridos com sucesso.")

    # Chamar a função de inserção de dados
    inserir_dados_SQL()

def inicio_execucao():
    print("Executando o código inicio", datetime.now().strftime("%d/%m/%Y %H:%M:%S"))

def termino_execucao():
    print("Termino do código", datetime.now().strftime("%d/%m/%Y %H:%M:%S"))

schedule.every(1).minutes.do(job)
# Imprimir hora de início da execução
inicio_execucao()

# Loop infinito para manter o programa em execução
while True:
    schedule.run_pending()
    time.sleep(30)  # Pausa de 30 segundos para evitar alto consumo de CPU
    
termino_execucao()