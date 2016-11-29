# XACML_User_Authentication
XACML Architecture that uses a PAM Module for the PEP and user authentication

BIG Shoutout to https://github.com/chevah/simple-pam for making this easier

# Instructions
1.Create a pam config in /etc/pam.d/first_pam

```#%PAM-1.0
auth requisite first_pam.so
account requisite first_pam.so
```

2.Compile things

> ./buildPam

> ./buildTest 

3.Start up order - **important**

> pip install -r requirements.txt

> python pdp.py

> python pip.py

> ./pam_test [username]

4.Login with Password and Account Creation Date (YYYYMMDD)

## Notes

- Only the users harambe, smitty and bojak are allowed users (defined in xacml_policy.xml)

- Line https://github.com/Bojak4616/XACML_User_Authentication/blob/master/pip.py#L13 will need to be changed to your LDAP server

- Line https://github.com/Bojak4616/XACML_User_Authentication/blob/master/buildPam.sh#L3 the path may need to be changed to /lib/security depending on your distro. I used CentOS.
