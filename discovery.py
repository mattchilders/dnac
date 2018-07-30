from dnac import DNAC
import sys
from dnac_credentials import USERNAME, PASSWORD, INSTANCE_IP, CLI_CREDENTIAL_GUID, SNMP_CREDENTIAL_GUID

store_discovery_jobs = {}
instance = INSTANCE_IP

with open('discovery.txt', 'r') as stores:
    for line in stores:
        values = line.split(',')
        name = values[0].strip()
        range = values[1].strip()
        store_discovery_jobs[name] = {
            "ipAddressList": range,
            "name": "API Discovery for " + str(name),
            "discoveryType": "Range",
            "protocolOrder": "ssh",
            "timeOut": 5,
            "retryCount": 3,
            "globalCredentialIdList": [
                CLI_CREDENTIAL_GUID,
                SNMP_CREDENTIAL_GUID
            ]
        }


dna = DNAC(instance, USERNAME, PASSWORD)

for name, job in store_discovery_jobs.items():
    r = dna.create_discovery_job(job)
    task = dna.get_task_from_response(r)
    task['name'] = name
    print(task['name'] + ' has been requested.')

    if (task):
        task = dna.get_job_id_from_task(task)
        if task is None:
            sys.exit()
        if 'job_id' not in task:
            print('Unable to retrieve Job ID from task')
            sys.exit()

    print(task['name'] + ' has been started, waiting for discovery to complete...')
    task = dna.get_discovered_devices_from_job(task)

    if task is None:
        print('No Devices found in Discovery Job')
        sys.exit()
    if 'device_ids' not in task:
        print('No Devices found in Discovery Job')
        sys.exit()

    with open(name + '_discovery.txt', 'w') as output_file:
        for device in task['device_ids']:
            r = dna.get_network_device_by_id(device)
            response = dna.error_check(r)
            if (response):
                if response['managementIpAddress'] is not None and response['hostname'] is not None:
                    print(response['hostname'] + ' (' + response['managementIpAddress'] + ') found.')
                elif response['hostname'] is not None:
                    print(response['hostname'] + ' (Unknown IP) found.')
                else:
                    print(str(device) + ' found, but unable to determinen hostname or IP.')

            output_file.write(str(device) + '\n')
