#!/usr/bin/python

import os
import sys
import hashlib
from time import sleep

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

    # This will return some PARSED xml or vars to send to the PIP for more info
    # print xml
    return str(xml)


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

    try:
        while True:
            # Read request from PEP
            with open(path_to_pep, 'r') as PIPE:
                request = PIPE.read()

            #Compare request with parse_policy()

            # If bad then write CONST_DENY and continue to next loop
            pip_vars = ""
            # Write request to PIP
            with open(path_to_pip, 'w') as PIPE:
                PIPE.write(pip_vars)

            with open(path_to_pip, 'r') as PIPE:
                pip_var_result = PIPE.read()

            # make function to compare against what was requested from PEP
            # Function should check if pip_var_result is None, if so return None

            with open(path_to_pep, 'w') as PIPE:
                # if compare function above PERMIT/DENY
                # PIPE.write(CONST_PERMIT)
                # PIPE.write(CONST_DENY)
                pass

    except KeyboardInterrupt:
        os.unlink(path_to_pip)
        sys.exit(0)

    except OSError as e:
        print "[!]Error: " + str(e)
        print "[!]Fix issue and restart pip.py"
        sys.exit(1)