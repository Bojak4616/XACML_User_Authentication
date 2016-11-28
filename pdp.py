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

    # 0=harambe 1=password 2=AccountCreationDate 3=smitty  6=bojak
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


def pip_compare(pep_attr, pip_attr):
    if pep_attr == pip_attr:
        return True
    else:
        return False


if __name__ == '__main__':
    path_to_pip = os.getcwd() + '/pdp_pip'
    path_to_pep = os.getcwd() + '/pep_pdp'
    # Pipes faster than writing to disk

    # Try/Except to prevent someone from create a pipe with the same name to DoS
    try:
        # Create a fresh pipe, deleting anything that was previously in there
        # Limit permissions so that other users can not read the pipe
        os.mkfifo(path_to_pip, 0600)
    except OSError:
        os.unlink(path_to_pip)
        os.mkfifo(path_to_pip, 0600)

        parse_policy()
        os.unlink(path_to_pip)
"""
    try:
        while True:
            # Read request from PEP
            #with open(path_to_pep, 'r') as PIPE:
            #   request = PIPE.read()

            #Compare request with parse_policy()
            # If bad then write CONST_DENY and continue to next loop
            pip_vars = "pip,Password1!,whenCreated"

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
"""