#!/usr/bin/python

import os
import sys
import string
from bs4 import BeautifulSoup

CONST_PERMIT = """
<Response>
  <Result>
    <Decision>Permit</Decision>
  </Result>
</Response>
"""

CONST_DENY = """
<Response>
  <Result>
    <Decision>Deny</Decision>
  </Result>
</Response>
"""


def parse_policy():
    try:
        with open('xacml_policy.xml', 'r') as XML:
            xml = XML.read()
    except IOError:
        print "[!] xacml_policy.xml could not be opened"
        sys.exit(1)

    soup = BeautifulSoup(xml, 'lxml-xml')

    # 0=harambe 1=password 2=whenCreated 3=smitty  6=bojak
    allowedUsers = []
    allowedUsers.append(soup.find_all('AttributeValue')[0].contents[0])
    allowedUsers.append(soup.find_all('AttributeValue')[3].contents[0])
    allowedUsers.append(soup.find_all('AttributeValue')[6].contents[0])
    for item in xrange(len(allowedUsers)):
        allowedUsers[item] = string.replace(allowedUsers[item], '\n', '')
        allowedUsers[item] = string.replace(allowedUsers[item], ' ', '')
        print allowedUsers[item]

    requirements = []
    requirements.append(soup.find_all('AttributeValue')[1].contents[0])
    requirements.append(soup.find_all('AttributeValue')[2].contents[0])
    for item in xrange(len(requirements)):
        requirements[item] = string.replace(str(requirements[item]), '\n', '')
        requirements[item] = string.replace(str(requirements[item]), ' ', '')

    # Tuples baby
    return allowedUsers, requirements

def parse_request(request):
    try:
        with open('request.xml', 'r') as XML:
            request = XML.read()
    except IOError:
        print "[!] request.xml could not be opened"
        sys.exit(1)

    soup = BeautifulSoup(request, 'lxml-xml')

    search = soup.find_all('Attribute')
    attribute_values = []
    # pip
    attribute_values.append(search[0].contents[0])
    # Password1!
    attribute_values.append(search[1].contents[0])
    # 20161128
    attribute_values.append(search[2].contents[0])
    for item in xrange(len(attribute_values)):
        attribute_values[item] = string.replace(str(attribute_values[item]), '\n', '')
        attribute_values[item] = string.replace(str(attribute_values[item]), ' ', '')
        print attribute_values[item]

    attribute_names = []
    # pip
    attribute_names.append(search[0]['AttributeId'])
    # Password
    attribute_names.append(search[1]['AttributeId'])
    # whenCreated
    attribute_names.append(search[2]['AttributeId'])
    for item in xrange(len(attribute_names)):
        attribute_names[item] = string.replace(str(attribute_names[item]), '\n', '')
        attribute_names[item] = string.replace(str(attribute_names[item]), ' ', '')
        print attribute_names[item]

    return attribute_names, attribute_values


def pip_compare(pep_attr, pip_attr):
    if pep_attr == pip_attr:
        return True
    else:
        return False


if __name__ == '__main__':
    path_to_pip = os.getcwd() + '/pdp_pip'
    path_to_pep = '/tmp/pep_pdp'
    # Pipes faster than writing to disk

    # Try/Except to prevent someone from create a pipe with the same name to DoS
    try:
        # Create a fresh pipe, deleting anything that was previously in there
        # Limit permissions so that other users can not read the pipe
        os.mkfifo(path_to_pip, 0600)
    except OSError:
        os.unlink(path_to_pip)
        os.mkfifo(path_to_pip, 0600)

    try:
        while True:
            #Read request from PEP
            with open(path_to_pep, 'r') as PIPE:
               request = PIPE.read()

            # Check request against policy
            check_one = False
            check_two = False
            req_names, req_values = parse_request(request)
            allowedUsers, attrs = parse_policy()
            # Check to see if the user exists in the policy
            for name in allowedUsers:
                if name == req_values[0]:
                    check_one = True

            # Check for proper Ids such as password and whenCreated
            if attrs[1] == req_names[0] and attrs[2] == req_names[1]:
                check_two = True

            if not (check_one and check_two):
                with open(path_to_pep, 'w') as PIPE:
                    PIPE.write(CONST_DENY)
                continue

            pip_vars = req_values[0] + "," + req_values[1] + "," + req_values[2]

            # Write request to PIP
            with open(path_to_pip, 'w') as PIPE:
                PIPE.write(pip_vars)

            with open(path_to_pip, 'r') as PIPE:
                pip_var_result = PIPE.read()

            print pip_var_result

            # function compares against what was requested from PEP
            pep_attr = "20161128"
            with open(path_to_pep, 'w') as PIPE:
                if pip_compare(pep_attr, pip_var_result):
                    PIPE.write(CONST_PERMIT)
                else:
                    PIPE.write(CONST_DENY)

    except KeyboardInterrupt:
        os.unlink(path_to_pip)
        sys.exit(0)

    except OSError as e:
        print "[!]Error: " + str(e)
        print "[!]Fix issue and restart pdp.py"
        sys.exit(1)
