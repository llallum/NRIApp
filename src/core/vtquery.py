import requests, json




def vtquery(hash):
    headers =   {"X-Tool" :"vt-ui-main",
                 "content-type" : "application/json",
                 "accept":   "application/json",
                "Accept-Ianguage":"en-US,en;q=0.9,es;q=0.8",
                "X-VT-Anti-Abuse-Header" : "placeholder", 
                "Referer": "Referer"
                
                }

    url = "https://www.virustotal.com/ui/files/" + hash

    response = requests.get(url, headers=headers, verify=False)

    return json.loads(response.text)


vtquery("cbbe22a891b04f19048155c1fbfa66a80cd33f87096f94d194e6560e90420280")