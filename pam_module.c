// Skeleton thanks to https://github.com/beatgammit/simple-pam
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <conio.h>

/* expected hook */
PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	printf("Acct mgmt\n");
	return PAM_SUCCESS;
}

/* expected hook, this is where custom stuff happens */
PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv ) {
	int retval;

	const char* pUsername;
	const char* password;
	const char* whenCreated;
	const char* path_to_pdp = "/tmp/pep_pdp";
	struct pam_message msg;
	
	retval = pam_get_item(pamh, &pUsername, "Username: ");
	msg.msg_style = PAM_PROMPT_ECHO_OFF;
    	msg.msg = prompt;
    	msgp = &msg;
	retval = pam_get_item(pamh, &password, "Password: ");
	msg.msg_style = PAM_PROMPT_ECHO_ON;
	retval = pam_get_item(pamh, &whenCreated, "Account Creation Date (YYYYMMDD): ");

	sprintf(&final, "<Request><Subject><Attribute AttributeId=\"username\" \
DataType=\"http://www.w3.org/2001/XMLSchema#string\"> \
%s \
</Attribute></Subject><Resource> \
<Attribute DataType=\"http://www.w3.org/2001/XMLSchema#string\" \
AttributeId=\"password\"> \
%s \    
</Attribute></Resource><Action> \
<Attribute DataType=\"http://www.w3.org/2001/XMLSchema#string\" \
AttributeId=\"whenCreated\"> \
%s \
</Attribute></Action></Request>", &pUsername, &password, &whenCreated);

	if (retval != PAM_SUCCESS) {
		return retval;
	}
	
	*fp = FILE *fopen(path_to_pdp, 'w');
	fprintf(fp, "%s", final);
	fclose( FILE *fp );

	char* result;
	*fp = FILE *fopen(path_to_pdp, 'r');
	do
   	{
     	    fscanf(q,"%s", result);
   	}
  	while( !feof(q) );		
	
	
	if (strstr(result, "<Decision>Deny</Decision>") != NULL) {
		return PAM_AUTH_ERR;
	}
	
	unlink(path_to_pdp);
	return PAM_SUCCESS;
}
