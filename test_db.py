import mysql.connector

DATABASE_CONFIG = {
    'host': 'localhost',
    'user': 'sfts_user',
    'password': 'Wzy020618',
    'database': 'secure_file_transfer'
}

try:
    conn = mysql.connector.connect(**DATABASE_CONFIG)
    print("数据库连接成功!")

    # 检查数据库表是否存在
    cursor = conn.cursor()
    cursor.execute("SHOW TABLES")
    tables = cursor.fetchall()
    print("数据库中的表:")
    for table in tables:
        print(f"- {table[0]}")

    cursor.close()
    conn.close()
except mysql.connector.Error as err:
    print(f"数据库连接错误: {err}")