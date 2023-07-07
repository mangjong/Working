import json
import csv
import sys

def reputation(parsed_data, rows):
    Computer_name = parsed_data['Computer Name']
    Computer_ip = parsed_data['Computer IP']

    data = parsed_data['Match Details']['match']['properties']
    
    md5 = data['md5']
    fullpath = data['fullpath']
    
    print("\nComputer Name : ", Computer_name)
    print("Computer IP : ", Computer_ip)
    print("hash :        ", md5)
    print("Path :        ", fullpath)

    row = [Computer_name, Computer_ip, md5, fullpath]
    rows.append(row)

def read_csv_column(filename, column_number):
    with open(filename, 'r', newline='', encoding="utf-8") as f:
        reader = csv.reader(f)
        values = []

        for row in reader:
            if len(row) > column_number:
                values.append(row[column_number])
    return values

def write_csv(filename, rows):
    with open(filename, 'w', newline='', encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(['Computer Name', 'Computer IP', 'hash', 'Path'])
        writer.writerows(rows)

def main():
    filename = sys.argv[1]
    CSV_FILENAME = 'tatnium_Reputation_Result.csv'
    column_number = 4  
    rows = []
    column_values = read_csv_column(filename, column_number)

    for data in column_values:
        try:
            parsed_data = json.loads(data)
            if "Reputation Malicious Hashes" == parsed_data['Intel Name']:
                reputation(parsed_data, rows)
                write_csv(CSV_FILENAME, rows)
        except json.JSONDecodeError as e:
            print("JSON 파싱 오류: ", str(e))

if __name__ == '__main__':
    main()
