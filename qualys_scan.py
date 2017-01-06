import requests
import shutil
import xml.etree.ElementTree as ET
import time
import datetime
import sys

def login(s, username, password):
    payload = {
           'action':'login',
           'username':username,
           'password':password
          }
    
    r = s.post('https://qualysapi.qualys.com/api/2.0/fo/session/', data=payload)
    xmlreturn = ET.fromstring(r.text)
    for elem in xmlreturn.findall('.//TEXT'):
        print(elem.text)

    print("Cookie: QualysSession =", r.cookies['QualysSession'])
   
def logout(s):
    payload = {
             'action':'logout'
            }
    
    r = s.post('https://qualysapi.qualys.com/api/2.0/fo/session/', data=payload)
    xmlreturn = ET.fromstring(r.text)
    for elem in xmlreturn.findall('.//TEXT'):
        print(elem.text)

def add_IP(s, target_IP):
    #set up host authentication
    payload = {
               'action':'add',
               'ips':target_IP,
               'enable_vm':1,
               'enable_pc':0,
               }

    r = s.post('https://qualysapi.qualys.com/api/2.0/fo/asset/ip/', data=payload)
    xmlreturn = ET.fromstring(r.text)
    for elem in xmlreturn.findall('.//TEXT'):
    	if "action has invalid value" in elem.text:
    		print("You do not have permissions do add IP(s)")
    	else:
    		print(elem.text)

def setup_auth(s, target_IP, username, password, title):
    #set up host authentication
    status = "Success"
    payload = {
               'action':'create',
               'title':title+'_'+target_IP,
               'ips':target_IP,
               'username':username,
               'password':password,
               }

    r = s.post('https://qualysapi.qualys.com/api/2.0/fo/auth/unix/', data=payload)
    xmlreturn = ET.fromstring(r.text)
    for elem in xmlreturn.findall('.//TEXT'):
    	if "action has invalid value" in elem.text:
    		print("You do not have permissions do add authentication records")
    	else:
    		print("Authentication Record", elem.text)

    	if "existing scan auth record has the specified title" in elem.text:
			#delete the auth record
			payload = {
			           'action':'list',
			           'title':target_IP
			           }
			r = s.post('https://qualysapi.qualys.com/api/2.0/fo/auth/unix/', data=payload)
			xmlreturn = ET.fromstring(r.text)
			for elem in xmlreturn.findall('.//AUTH_UNIX'):
				title_id = elem[0].text

			payload = {
			           'action':'delete',
			           'ids':title_id,
			           }
			r = s.post('https://qualysapi.qualys.com/api/2.0/fo/auth/unix/', data=payload)
			xmlreturn = ET.fromstring(r.text)
			for elem in xmlreturn.findall('.//TEXT'):
			    status = elem.text
			    print("Authentication Record", status)
			    setup_auth(s, target_IP, username, password, title)
        elif "one or more of the specified IPs" in elem.text:
        	#delete the auth record
        	status = "Failure"
        	print("---\nPlease note:\nIP exists in another authentication record\nQualys doesn't support multiple authentication record of same type for any IP\nPlease delete the existing authentication record manually to proceed.\n---")
    return status

def launch_scan(s, target_IP, scan_option_id):
    # launching the scan
    scan_ref = ""
    payload = {
               'action':'launch',
               'ip':target_IP,
               'iscanner_name':'is_vmwar_as',
               'option_id':scan_option_id, #'797901',
               'scan_title':target_IP,
               }

    r = s.post('https://qualysapi.qualys.com/api/2.0/fo/scan/', data=payload)
    xmlreturn = ET.fromstring(r.text)
    for elem in xmlreturn.findall('.//ITEM'):
        if (elem[0].text == 'REFERENCE'): 
            scan_ref = elem[1].text

    for elem in xmlreturn.findall('.//TEXT'):
        if "none of the specified IPs are eligible" in elem.text:
    		print("You do not have permissions do run scans on IP", target_IP)
    	else:
    		print(elem.text)
    
    if "scan" in scan_ref:
    	print("Scan Reference Number:", scan_ref)
    else:
    	scan_ref = "SCAN_NOT_STARTED"
    return scan_ref

def check_scan(s, scan_ref):
    # checks the status of the scan
    state = "Default"
    payload = {
               'action':'list',
               'scan_ref':scan_ref,
               }
    r = s.post('https://qualysapi.qualys.com/api/2.0/fo/scan/', data=payload)
    xmlreturn = ET.fromstring(r.text)
    code = xmlreturn.find('.//CODE')
    status = xmlreturn.find('.//STATUS')
    text = xmlreturn.find('.//TEXT')

    if status != None:
    	state = status[0].text

    if code != None:
    	if text != None:
    		print("Error Text:", text.text)
    	
    print("Scan status:", state)
    return state

def launch_report(s, scan_ref, report_type, target_IP, report_template_id):
    # launching report 
    report_ID = "" 
    payload = {
               'action':'launch',
               'report_type':'Scan',
               'template_id':report_template_id,#'991466',
               'output_format':report_type,
               'report_refs':scan_ref,
               'report_title':target_IP,
               }

    r = s.post('https://qualysapi.qualys.com/api/2.0/fo/report/', data=payload)
    xmlreturn = ET.fromstring(r.text)
    for elem in xmlreturn.findall('.//ITEM'):
        if (elem[0].text == 'ID'):
            report_ID = elem[1].text
    
    print("Report ID:", report_ID)
    return report_ID
    
def check_report(s, report_ID):
    # check reports
    status = ""
    payload = {
               'action':'list',
               'id':report_ID,
               }
    r = s.post('https://qualysapi.qualys.com/api/2.0/fo/report/', data=payload)
    xmlreturn = ET.fromstring(r.text)
    for elem in xmlreturn.findall('.//STATUS'):
        status = elem[0].text
    
    return status

def download_report(s, report_ID, target_IP):
    # downloading the reports
    ts = time.time()
    dt = datetime.datetime.fromtimestamp(ts).strftime('%Y%m%dT%H%M%S')
    #file format: report folder, IP, date-time stamp
    filename = "reports\qualys_scan_report_"+target_IP+"_"+dt+".pdf"
    payload = {
               'action':'fetch',
               'id':report_ID,
               }
    
    r = s.post('https://qualysapi.qualys.com/api/2.0/fo/report/', data=payload, stream=True)
    if r.status_code == 200:
    	with open(filename, 'wb') as f:
            r.raw.decode_content = True
            shutil.copyfileobj(r.raw, f)
            print("report downloaded")
    else:
    	print("report failed to download with status code:", r1.status_code)

    #this is another way to save report
    #if the above method fails to save report correctly, use the below method
    '''
    time.sleep(10)
    ts = time.time()
    dt = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%dT%H:%M:%S')
    filename2 = target_IP+"_"+dt+".pdf"
    
    r2 = s.post('https://qualysapi.qualys.com/api/2.0/fo/report/', data=payload, stream=True)
    if r2.status_code == 200:
    	with open(filename2, 'wb') as f:
            r2.raw.decode_content = True
            shutil.copyfileobj(r2.raw, f)
            print("report downloaded")
    else:
    	print("report failed to download with status code:", r1.status_code)
    '''

def quick_scan(s, target_IP, username, password, title, scan_option_id, report_template_id):
	print("Quick Scan:", target_IP)
	#add IPs
	add_IP(s, target_IP)

	#add authentication record
	status = setup_auth(s, target_IP, username, password, title).lower()
	if status == "failure":
		return

	#start the scan
	scan_ref = launch_scan(s, target_IP, scan_option_id)
	if scan_ref == "SCAN_NOT_STARTED":
		print("Scan has not started for IP:", target_IP)
		return

	#check the scan status after every 100 seconds
	#add a new if statement for various check_scan return value that is discovered
	while 1:
		#waiting for 5 mins = 300
		time.sleep(300)
		status = check_scan(s, scan_ref).lower()
		if status == "finished":
			break
		elif status == "queued" or status == "loading" or status == "running":
			continue
		else:
			return

	#generate report after scan has completed
	report_type = 'pdf'
	report_ID = launch_report(s, scan_ref, report_type, target_IP, report_template_id)

	#waiting for report generation; then download report
	time.sleep(25)
	download_report(s, report_ID, target_IP)

def main():
    try:
		#read data from config file
		tree = ET.parse('config-nonadmin.xml')
		root = tree.getroot()
		username = root[0][0].text
		password = root[0][1].text

		#setup connection
		s = requests.Session()
		s.headers.update({'X-Requested-With':'Qualys Vuln Api Scan'})
		login(s, username, password)
        
        #scan each host
		for host in root.iter('host'):
			quick_scan(s, host[0].text, host[1].text, host[2].text, host[3].text, host[4].text, host[5].text)
    except:
        print("Unexpected error:", sys.exc_info()[0])
        print("sys.exc_info(): ", sys.exc_info())
    finally:
    	#always log out and close the session
    	logout(s)
    	s.close()

if __name__ == "__main__":main()
