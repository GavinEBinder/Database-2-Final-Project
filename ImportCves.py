import mysql.connector

conn = mysql.connector.connect(
    host="localhost",
    user="root",
    password="root",
    database="cve_database"
)

cursor = conn.cursor()
with open("cve_database.sql", "r", encoding="utf-8") as sql_file:
    sql_commands = sql_file.read()
    commands = sql_commands.split(";")
    for command in commands:
        command = command.strip()
        if command:
            cursor.execute(command)
            if command.lower().startswith("select"):
                results = cursor.fetchall()
                for row in results:
                    print(row)
    conn.commit()

    print("Database has been successfully populated")
    if conn.is_connected():
        cursor.close()
        conn.close()
