#!/usr/bin/python3

import sys
import requests
import json
import os
import re

readme = open("README.md", "r").read() #.replace('\n', '\\n').replace('"','\\"')
user = "chris2511"

if len(sys.argv) < 2:
  print("Usage: " + sys.argv[0] + " <VERSION> full-path-binaries ... ")
  exit(1)

version = sys.argv[1]
url = 'https://api.github.com/repos/' + user + '/xca/releases'
data = {
  "tag_name" : "RELEASE." + version,
  "target_commitish": "master",
  "name": "XCA " + version,
  "body": readme,
  "draft": True,
  "prerelease": True
}

passwd = input("Github Password for " + user + ": ")
r = []

response = requests.post(url, json=data, auth=(user, passwd))
r.append(response.json())
upload_url = response.json().get('upload_url')

print(upload_url)

headers = {'Content-Type': 'text/plain'}

for file in sys.argv[2:]:
  name = re.sub(".*/", "", file)
  url = upload_url.replace("{?name,label}", "?name=" + name)
  print("Upload", file)
  response = requests.post(url, headers=headers, data=open(file, 'rb'), auth=(user, passwd))
  r.append(response.json())

print(r)
