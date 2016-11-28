#!/usr/bin/python

import ldap
import os
import sys


# searchAttribute value should be an array of variables to query ldap
def fetch_ldap(username, password, searchAttribute):
    result_set =[]
    searchAttr = []
    searchAttr.append(searchAttribute)
    l = ldap.initialize('ldap://ldap.auth:389')
    binddn = "cn=" + username + ",cn=Users,dc=ldap,dc=auth" 
    searchFilter = "objectClass=*"
    # this will scope the entire subtree under UserUnits
    searchScope = ldap.SCOPE_SUBTREE
    # Bind to the server
    try:
        l.protocol_version = ldap.VERSION3
        l.simple_bind_s(binddn, password)
    except ldap.INVALID_CREDENTIALS:
        return result_set
    except ldap.LDAPError:
        return result_set
    try:
        ldap_result_id = l.search(binddn, searchScope, searchFilter, searchAttr)
        result_set = []
        while True:
            result_type, result_data = l.result(ldap_result_id, 0)
            if not result_data:
                break
            else:
                ## if you are expecting multiple results you can append them
                ## otherwise you can just wait until the initial result and break out
                if result_type == ldap.RES_SEARCH_ENTRY:
                    result_set.append(result_data)
        l.unbind_s()
        return result_set
    except ldap.LDAPError:
        return result_set


if __name__ == '__main__':
    path_to_pdp = os.getcwd() + '/pdp_pip'

    try:
        while True:
            with open(path_to_pdp, 'r') as PIPE:
                request = PIPE.read()

            vars = request.split(',')
            results = fetch_ldap(vars[0], vars[1], vars[2])
            with open(path_to_pdp, 'w') as PIPE:
                if not results:
                    PIPE.write("None")
                    continue

            print results
            var_string = str(results[0][0][1]['whenCreated'])[2:10]
            PIPE.write(var_string)

    except KeyboardInterrupt:
        print "Done"
        sys.exit(0)

