import sys
import time
from alienvault import get_info
from abuseip import check_abuseIP

start_time = time.time()

rows = []

if len(sys.argv) == 2:
    args = sys.argv[1]
    print("\n Checking...\n")

    print("Alienvault Check\n")
    get_info(args, rows)

    print("\n--------------------------------\n")
    print("AbuseIPDB Check\n")
    check_abuseIP(args, rows)
else:
    print("값을 입력하세요. \n")

print(f'Total Time:       {round((time.time() - start_time), 2)} seconds')
