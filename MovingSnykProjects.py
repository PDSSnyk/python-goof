import json
import re
import requests
#https://snyk.docs.apiary.io/#reference/projects/all-projects/list-all-projects
#https://snyk.docs.apiary.io/#reference/projects/move-project/move-project-to-a-different-organization
payload = json.dumps({
  "targetOrgId": "90d3247f-739c-4663-bf87-2068bb96c603" #Target Destination
})

org_id= "722a9dd0-a5e9-444e-82f3-d83c04711392" #ORG id where projects should move from
#Obtaining Project Ids under specific project below
url = f"https://snyk.io/api/v1/org/{org_id}/projects"

headers = {
  'Authorization': 'token dfec3e16-68d0-420c-9f56-05037886f405',
  'Content-Type': 'application/json'
}
response = requests.request("POST", url, headers=headers)

results= response.text
parse = re.findall('(id":"........-....-....-....-............)', results)
print(results)
print(parse)
projectIDs = re.findall('........-....-....-....-............',str(parse))
print(projectIDs)
print(projectIDs[1])
counter = 1
#Moving projects from originating Org to Destination Org below
url = f"https://snyk.io/api/v1/org/{org_id}/project/{projectIDs[counter]}/move"

for i in projectIDs:
  response = requests.request("POST", url, headers=headers, data=payload)
  print(url)
  print(response.text)
  counter+=1