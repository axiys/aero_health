"""
This is a utility to parse the collectinfo log files and add meaningful data
in a more presentable form and also highlight major errors.

As a first step this involves parsing the health log and summary log files
Helper methods are designed accordingly

However there are patterns that are really hard to parse even using standard
Unix tools such as Awk. I have left this out as is.

Author: Pradeep Banavara
"""
from importlib import reload
import re
import json
from fastapi import FastAPI, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
import os
from fastapi_login import LoginManager
from fastapi.security import OAuth2PasswordRequestForm
from fastapi_login.exceptions import InvalidCredentialsException
from datetime import timedelta

origins = ["http://localhost:3000"]
SECRET = os.urandom(24).hex()

app = FastAPI(debug=True)
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
manager = LoginManager(SECRET, tokenUrl="/auth/token")

# Temporary user credentials use a database instaed
fake_db = {"pradeep@aerospike.com" : {'password': 'hunter2'}}


SUMMARY_FILE_NAME= "../../collectinfo_output/collect_info_20200525_092140/20200525_092140_summary.log"
HEALTH_FILE_NAME= "../../collectinfo_output/collect_info_20200525_092140/20200525_092140_health.log"


@manager.user_loader
def load_user(email: str):
    user = fake_db.get(email)
    print("User is {}".format(user))
    return user

@app.post("/auth/token")
def login(request: Request, data: OAuth2PasswordRequestForm = Depends()):
    print(request.headers)
    email = data.username
    password = data.password
    user = load_user(email)
    if not user:
        raise InvalidCredentialsException
    elif password != user['password']:
        raise InvalidCredentialsException
    access_token = manager.create_access_token(
        data = {'sub' : email}, expires=timedelta(hours=12)
    )
    return {'access_token': access_token, 'token_type': 'bearer'}

def store_data_in_aerospike(key, value):
    client = aerospike.client(config).connect()
    client.put(("test", "demo", key), value, None, None)


@app.get("/summary")
def parse_summary(user = Depends(manager)):
    search_list = ['Server Version',
                    'OS Version',
                    'Devices',
                    'Memory',
                    'Disk',
                    'Usage',
                    'Active Namespaces',
                    'Features',
                    ]
    summary_map = [] # To store the summary parameters in a map form
    with open(SUMMARY_FILE_NAME) as f:
        contents = f.read()
        for word in search_list:
            regex = summary_regex_search(word, contents)
            if regex:
                temp = {}
                key = regex[0].strip() 
                val = regex[1].strip() # from list to map
                temp["col1"] = key
                temp["col2"] = val
                summary_map.append(temp)
    return summary_map

def parse_failure_string(failure_string):
    anomalies = failure_string.replace("LIMITS", "ANOMALY")
    anomalies = anomalies.replace("OPERATIONS", "ANOMALY")
    array_of_anomalies = []
    for a in anomalies.split("ANOMALY"):
        if not a.startswith("___"):
            m = {}
            m["fails"] = a
            array_of_anomalies.append(m)
    return array_of_anomalies


@app.get("/fails")
def parse_failure():
    """
    This is required to parse the health log file line by line in order to read
    stats because it is of the form
    ~~~~~~~~~~~~FAIL~~~~~~~~~~~

    ANOMALY : .....
    Description: ....
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    """
    fail_map = {}
    with open(HEALTH_FILE_NAME) as f:
        con = f.read()
        #regex = re.compile(r"^_* FAIL(.*)_$\n*(.*)((?:\n.+)*)", re.MULTILINE)
        regex = re.compile(r"^_* FAIL(.*)_$\n*(.*)((?:.*\n)*)", re.MULTILINE)
        fails = re.search(regex, con).group()
        warnings = fails.split("WARNING")
        fail_map["failures"] = parse_failure_string(warnings[0])
        fail_map["warnings"] = parse_failure_string(warnings[1])
    return fail_map


def summary_regex_search(pattern_string, contents):
    """
    Takes in a pattern and returns a list of form version: value
    """
    new_pat = r'.+' + pattern_string + '.+'
    regex = re.compile(new_pat)
    matches = re.search(regex, contents).group().split(":")
    return matches


"""
if __name__ == "__main__":
    summary_map = parse_summary("../collectinfo_output/collect_info_20200525_092140/20200525_092140_summary.log")
    ret_map = parse_failure("../collectinfo_output/collect_info_20200525_092140/20200525_092140_health.log")
    ret_map["summary"] = summary_map
    store_data_in_aerospike("customer_id", ret_map)
    json_obj = json.dumps(ret_map)
    with open('output.json', 'w') as json_file:
        json_file.write(json_obj)
"""
