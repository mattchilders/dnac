import requests
import os
import json
import sys
import time
from dnac_credentials import USERNAME, PASSWORD, INSTANCE_IP, CLI_CREDENTIAL_GUID, SNMP_CREDENTIAL_GUID
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class DNAC:
	def __init__(self, dnac_instance, username, password):
		self.GET = 1
		self.PUT = 2
		self.POST = 3
		self.DELETE = 4
		self.PROXIES = {
		  "http": None,
		  "https": None,
		}
		self.instance = dnac_instance
		self.API = "https://" + self.instance + "/api/v1/"
		self.AUTH_API = "https://" + self.instance + "/api/system/v1/"
		self.username = username
		self.password = password
		err, resp = self.get_auth_token()
		if err:
			print("Unable to get auth token.  Error: " + str(resp))
		else:
			self.auth_token = resp

	def api_call(self, url, verb, data=None, additional_header=None):
		if self.auth_token is None:
			print("Auth Token is Unavailable")
			return {"response": {'errorCode': 'AUTH_TOKEN', 'message': "Missing Auth Token", 'detail': "A valid auth token was not found" }}
		headers = {"X-Auth-Token": self.auth_token}
		if (additional_header):
			if type(additional_header) is dict:
				headers.update(additional_header)
				
		if (data):
			if type(data) is dict:
				data = json.dumps(data)
				
		try:
			if verb == self.GET:
				resp = requests.get(url, proxies=self.PROXIES, headers=headers, verify=False)
			if verb == self.PUT:
				headers['Content-Type'] = 'application/json'
				resp = requests.put(url, proxies=self.PROXIES, headers=headers, data=data, verify=False)
			if verb == self.POST:
				headers['Content-Type'] = 'application/json'
				resp = requests.post(url, proxies=self.PROXIES, headers=headers, data=data, verify=False)
			if verb == self.DELETE:
				resp = requests.delete(url, proxies=self.PROXIES, headers=headers, verify=False)
		except Exception as e:
			return {"response": {'errorCode': 'Error Executing API Call', 'message': str(e), 'detail': None }}
		
		if resp is None:
			return {"response": {'errorCode': 'No Response', 'message': "No Response was recieved from the API", 'detail': None }}
		
		try:
			resp_dict = json.loads(resp.text)
		except Exception as e:
			return {"response": {'errorCode': 'Error Parsing Response', 'message': str(e), 'detail': None }}
		
		return resp_dict
		
	def get_auth_token(self):
		auth_url = self.AUTH_API + "auth/token"
		try:
			resp = requests.post(auth_url, auth=(self.username, self.password), proxies=self.PROXIES, verify=False)
		except Exception as e:
			return True, str(e)
				
		if not resp:
			return True, "No Response or Timeout"
		if resp.status_code != 200:
			return True, "Unexpected Return Code: " + resp.status_code
			
		try:
			resp_dict = json.loads(resp.text)
		except Exception as e:
			return True, str(e)
			
		if 'Token' in resp_dict:
			return False, resp_dict['Token']
		
		return True, "Unknown error"

	def error_check(self, response, exit_on_error=False):
		if 'response' in response:
			if 'errorCode' in response['response']:
				err = response['response']
				if err['errorCode'] is not None:
					# print(err)
					if ('message' in err) and ('detail' in err):
						print('Error: ' + err['errorCode'] + ' - ' + err['message'] + ' - ' + err['detail'])
					else:
						print('Error: ' + err['errorCode'])
					if exit_on_error:
						sys.exit()
					return None
			return response['response']
		if 'exp' in response:
			print('Error: ' + response['exp'])
			if exit_on_error:
				sys.exit()
			return None
		if 'error' in response:
			print('Error: ' + response['exp'])
			if exit_on_error:
				sys.exit()
			return None
		print('Unknown Error')
		print('Return Data: ' + str(response))
		if exit_on_error:
			sys.exit()
		return None
		
	
	def get_task_from_response(self, response):
		task = self.error_check(response)
		if task:
			if ('url' in task) and ('taskId' in task):
				return task

		print('Unexpected Task Returned: ')
		print(task)
		return None

	def get_job_id_from_task(self, task, timeout=30):
		REPEAT_TIMER = 3
		loop_counter = 0
		while(loop_counter < timeout/REPEAT_TIMER):
			time.sleep(REPEAT_TIMER)
			r = self.get_task_status(task)
			response = self.error_check(r)
			if(response):
				if 'endTime' in response:
					if response['isError'] is not True:
						print(task['name'] + ' has been created.')
						task['job_id'] = response['progress']
						return task
				print('Unable to complete task')
				print(response)
				return None
			loop_counter += 1
		print('Timeout waiting for Task Status.')
		return None
	
	def get_discovered_devices_from_job(self, task, timeout=180):
		REPEAT_TIMER = 3
		loop_counter = 0
		while(loop_counter < timeout/REPEAT_TIMER):
			time.sleep(REPEAT_TIMER)
			r = self.get_discovery_job_by_id(task['job_id'])
			response = self.error_check(r, True)
			if(response):
				if response['discoveryCondition'] == 'Complete':
					if 'deviceIds' in response:
						task['device_ids'] = response['deviceIds'].split(',')
						print(task['name'] + ' has completed.')
						return task
					else:
						print('No Devices found in Discovery Job')
						return None
		print('Timeout waiting for Discovery Status.')
		return None
	
	def get_task_status(self, task):
		url = self.API + 'task/' + task['taskId']
		return self.api_call(url, self.GET)
		
	def get_network_devices(self):
		url = self.API + "network-device/"
		return self.api_call(url, self.GET)
	
	def get_network_device_by_ip(self, ip):
		url = self.API + "network-device/ip-address/" + ip
		return self.api_call(url, self.GET)
	
	def get_network_device_count(self):
		url = self.API + "network-device/count"
		return self.api_call(url, self.GET)

	def get_network_device_by_serial(self, serial):
		url = self.API + "network-device/serial-number/" + serial
		return self.api_call(url, self.GET)
		
	def get_network_device_by_id(self, id):
		url = self.API + "network-device/" + id
		return self.api_call(url, self.GET)

	def get_network_device_location_by_id(self, id):
		url = self.API + "network-device/" + id + "/location"
		return self.api_call(url, self.GET)

	def get_discovery_jobs(self):
		url = self.API + "discovery"
		return self.api_call(url, self.GET)
		
	def create_discovery_job(self, job_details):
		url = self.API + "discovery/"
		return self.api_call(url, self.POST, data=job_details)
		
	def get_discovery_job_by_ip(self, ip):
		url = self.API + "discovery/job/?ipAddress=" + ip
		return self.api_call(url, self.GET)

	def get_discovery_job_by_id(self, id):
		url = self.API + "discovery/" + id
		return self.api_call(url, self.GET)

		
def main():
	discovery_job = {
		"ipAddressList": "192.168.1.1-192.168.1.2",
		"name": "API Discovery Job",
		"discoveryType": "Range",
		"protocolOrder": "ssh",
		"timeOut": 5,
		"retryCount": 3,
		"globalCredentialIdList": [
			CLI_CREDENTIAL_GUID,
			SNMP_CREDENTIAL_GUID
		]
	}

	instance = INSTANCE_IP
	dna = DNAC(instance, USERNAME, PASSWORD)
	r = dna.create_discovery_job(discovery_job)
	task = dna.get_task_from_response(r)
	task['name'] = discovery_job['name']
	print(task['name'] + ' has been requested.')
	timeout = 10

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
		
			
	for device in task['device_ids']:
		r = dna.get_network_device_by_id(device)
		response = dna.error_check(r, True)
		if (response):
			if response['managementIpAddress'] is not None and response['hostname'] is not None:
				print(response['hostname'] + ' (' + response['managementIpAddress'] + ') found.')
			elif response['hostname'] is not None:
				print(response['hostname'] + ' (Unknown IP) found.')
			else:
				print(str(device) + ' found, but unable to determinen hostname or IP.')

			
if __name__ == "__main__":
	main()
