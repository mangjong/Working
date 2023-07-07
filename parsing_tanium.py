import sys
import re
import csv

"""

Reputation 내역은 입력 값에서 제외, 별도 쿼리문으로 조회하기
입력되는 값 필드의 순서는 시간, IntelName, sourceIP, Payload

* 주요 봐야 할 부분
- User Added to Local Administrators
- Administrator Account Enumeration
- Suspicious PowerShell Command Line

"""

def read_csv_column(filename, column_number):
    with open(filename, 'r', encoding="utf-8") as f:
        reader = csv.reader(f)
        values = []

        for row in reader:
            if len(row) > column_number:
                values.append(row[column_number])
    return values

def write_csv(filename, rows):
    with open(filename, 'w', newline='', encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(['Time', 'Computer Name', 'Computer IP', 'Intel Name', 'Command Line', 'Parent_1', 'Parent_2', 'Parent_3', 'Parent_4', 'Parent_5', 'Parent_6'])
        writer.writerows(rows)

def parsing_csv_column(column_values, rows):
    pattern = r'"arguments":"(?:\\")?(.*?)",'

    for column_match in column_values:
        Time_statmp = re.search(r'"Timestamp":"(.*?)"', column_match)
        Computer_name = re.search(r'"Computer Name":"(.*?)"', column_match)
        Computer_ip = re.search(r'"Computer IP":"(.*?)"', column_match)
        Intel_Name = re.search(r'"Intel Name":"(.*?)"', column_match)
        
        print("\nTime : ", Time_statmp.group(1))
        print("Computer Name : ", Computer_name.group(1))
        print("Computer IP : ", Computer_ip.group(1))
        print("Intel Name : ", Intel_Name.group(1))

        matching = re.findall(pattern, column_match)
        
        i = len(matching)
        matching_values = []
        command_line = ""
        for match in matching:
            match = match.replace('\\\\', '\\').replace('\\\\', '\\').rstrip('\\')
            matching_values.append(match)
            command_line = matching_values[0]
        print(f"Command Line : {command_line}")
        
        row = [Time_statmp.group(1), Computer_name.group(1), Computer_ip.group(1), Intel_Name.group(1), command_line]
         
        for index, match in enumerate(matching_values[1:], start=2):
            Process_Ancestry = i - index + 1
            print(f'{Process_Ancestry} - Process Ancestry: {match}')
            row.append(match)
        rows.append(row)
            
def main():
    filename = sys.argv[1]
    
    CSV_FILENAME = 'tatnium_result.csv'
    column_number = 3  # payload 부분의 열 번호
    rows = []
    column_values = read_csv_column(filename, column_number)
    parsing_csv_column(column_values, rows)
    write_csv(CSV_FILENAME, rows)

if __name__ == '__main__':
    main()
