#!/usr/bin/python

import ldap
import os
import sys


def parse_pdp(data):
    # parse and return vars
    searchAttribute = ""

    return searchAttribute


# searchAttribute value should be an array of variables to query ldap
def fetch_ldap(searchAttribute):
    l = ldap.initialize('ldap://ldap.auth:389')
    binddn = "cn=myUserName,ou=GenericID,dc=my,dc=company,dc=com"
    pw = "myPassword"
    basedn = "ou=UserUnits,dc=my,dc=company,dc=com"
    searchFilter = "(&(gidNumber=123456)(objectClass=posixAccount))"
    #this will scope the entire subtree under UserUnits
    searchScope = ldap.SCOPE_SUBTREE
    #Bind to the server
    try:
        l.protocol_version = ldap.VERSION3
        l.simple_bind_s(binddn, pw)
    except ldap.INVALID_CREDENTIALS:
        print "Your username or password is incorrect."
        sys.exit(0)
    except ldap.LDAPError, e:
        if type(e.message) == dict and e.message.has_key('desc'):
            print e.message['desc']
        else:
            print e
        sys.exit(0)
    try:
        ldap_result_id = l.search(basedn, searchScope, searchFilter, searchAttribute)
        result_set = []
        while True:
            result_type, result_data = l.result(ldap_result_id, 0)
            if (result_data == []):
                break
            else:
                ## if you are expecting multiple results you can append them
                ## otherwise you can just wait until the initial result and break out
                if result_type == ldap.RES_SEARCH_ENTRY:
                    result_set.append(result_data)
        l.unbind_s()
        return result_set
    except ldap.LDAPError, e:
        print e


if __name__ == '__main__':

    path_to_pdp = os.getcwd() + '/pdp_pip'

    searchAttribute = ['bojak', 'passwordHash', 'whenCreated']
    results = fetch_ldap(searchAttribute)
    for result in results:
        print result

"""
    try:
        while True:
            with open(path_to_pdp, 'r') as PIPE:
                request = PIPE.read()

            results = fetch_ldap(parse_pdp(request))

            with open(path_to_pdp, 'w') as PIPE:
                if not results:
                    PIPE.write("None")
                    continue

                #this may need to be returned as XML, not sure yet
                var_string = ""
                for var in results:
                    var_string += var + ":"

                PIPE.write(var_string)

    except KeyboardInterrupt:
        print "Done"
        sys.exit(0)
"""