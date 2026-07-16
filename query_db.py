import sqlite3

# Connect to the local database file
conn = sqlite3.connect('cyber_telemetry.db')
cursor = conn.cursor()

print("Fetching records from the 'ip_intel' table:\n")
print(f"{'ID':<4} | {'Timestamp':<20} | {'PCAP Source':<15} | {'Destination IP':<18} | {'VirusTotal Status'}")
print("-" * 85)

# Execute a standard SQL query to retrieve all data
cursor.execute("SELECT id, timestamp, pcap_source, destination_ip, vt_status FROM ip_intel")
records = cursor.fetchall()

# Loop through and print out the rows cleanly
for row in records:
    print(f"{row[0]:<4} | {row[1]:<20} | {row[2]:<15} | {row[3]:<18} | {row[4]}")

# Clean up the connection
conn.close()