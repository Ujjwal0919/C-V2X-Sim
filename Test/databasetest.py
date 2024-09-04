import pyodbc


def get_azure_sql_connection():
    server = 'fleetmanagementdb.database.windows.net'
    database = 'fleet-management-db'
    username = 'fmsadmin@fleetmanagementdb'
    password = 'Ujjwal0919@'  # Replace with your actual password
    driver = '{ODBC Driver 17 for SQL Server}'

    connection_str = f'DRIVER={driver};SERVER={server};PORT=1433;DATABASE={database};UID={username};PWD={password};Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;'
    conn = pyodbc.connect(connection_str)
    return conn


def store_obu_data(sid, public_key, shared_secret, session_id):
    conn = get_azure_sql_connection()
    cursor = conn.cursor()
    insert_query = '''
    INSERT INTO dbo.obu_data (sid, public_key, shared_secret, session_id)
    VALUES (?, ?, ?, ?)
    '''
    cursor.execute(insert_query, (sid, public_key, shared_secret, session_id))
    conn.commit()
    conn.close()


def fetch_challenge(sid):
    conn = get_azure_sql_connection()
    cursor = conn.cursor()
    query = "SELECT challenge FROM dbo.obu_challenges WHERE sid=?"
    cursor.execute(query, (sid,))
    result = cursor.fetchone()
    conn.close()
    if result:
        return result[0]
    else:
        return None


sid = 'OBU12345'
challenge = fetch_challenge(sid)
if challenge:
    print(f"The challenge for SID {sid} is: {challenge}")
else:
    print(f"No challenge found for SID {sid}")
