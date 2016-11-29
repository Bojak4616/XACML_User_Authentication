/* Define which PAM interfaces we provide */
#define PAM_SM_ACCOUNT
#define PAM_SM_AUTH
#define PAM_SM_PASSWORD
#define PAM_SM_SESSION

/* Include PAM headers */
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

/* Conversation handler */
int converse(
	pam_handle_t *pamh,
	int nargs,
	struct pam_message **message,
	struct pam_response **response
		){
	int retval;
	struct pam_conv *conv;

	retval = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
	if (retval == PAM_SUCCESS) {
	  	retval = conv->conv(
	  		nargs,
	  		( const struct pam_message ** ) message,
	  		response,
	  		conv->appdata_ptr
	  		);
     	}
	return retval;
}

/* Prompt for both Password and whenCreated */
int set_auth_tok(pam_handle_t *pamh, const char* prompt, int TOK) {

	int retval;
	char *p;

	struct pam_message msg[1],*pmsg[1];
	struct pam_response *resp;

	/* set up conversation call */
	pmsg[0] = &msg[0];
	msg[0].msg_style = PAM_PROMPT_ECHO_OFF;
	msg[0].msg = prompt;
	resp = NULL;

	if ((retval = converse( pamh, 1 , pmsg, &resp )) != PAM_SUCCESS)
		return retval;

	if (resp) {
		p = resp[ 0 ].resp;

		
	  	resp[ 0 ].resp = NULL;
	} else {
		return PAM_CONV_ERR;
	}

	free(resp);
	pam_set_item(pamh, TOK, p);
	return PAM_SUCCESS;
}


/* PAM entry point for session creation */
PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return(PAM_SUCCESS);
}

/* PAM entry point for session cleanup */
PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return(PAM_SUCCESS);
}

/* PAM entry point for accounting */
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return(PAM_SUCCESS);
}

/* PAM entry point for authentication verification */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  const void *passwordData  = NULL;
  const void *whenCreated   = NULL;
  const char *user;

  //char *request = NULL;
  char path_to_pdp[] = "/tmp/pep_pdp";
  int retval;

  retval = pam_get_user(pamh, &user, NULL);
  if (user == NULL){
    printf("null username\n");
    return(PAM_AUTH_ERR);
  }

  printf("user: %s\n",user);

  retval = pam_get_item(pamh, PAM_AUTHTOK, &passwordData);

  if (retval != PAM_SUCCESS){
    printf("Failed to get password\n");
    return(retval);
  }


  if (!passwordData) {
		retval = set_auth_tok(pamh, "Password: ", PAM_OLDAUTHTOK);
		retval = pam_get_item(pamh, PAM_OLDAUTHTOK, &passwordData);
                
		retval = set_auth_tok(pamh, "Account Creation Date (YYYYMMDD): ", PAM_AUTHTOK);
		retval = pam_get_item(pamh, PAM_AUTHTOK, &whenCreated);
  }


// Trim user inputs to avoid overflows
char request[700];

if(strlen(user) > 50)
	return(PAM_AUTH_ERR);

if(strlen(passwordData) > 50)
	return(PAM_AUTH_ERR);

if(strlen(whenCreated) > 8)
	return(PAM_AUTH_ERR);

sprintf(request, "<Request><Subject><Attribute AttributeId=\"username\""
"DataType=\"http://www.w3.org/2001/XMLSchema#string\">"
"%s"
"</Attribute></Subject><Resource>"
"<Attribute DataType=\"http://www.w3.org/2001/XMLSchema#string\""
"AttributeId=\"password\">"
"%s"
"</Attribute></Resource><Action>"
"<Attribute DataType=\"http://www.w3.org/2001/XMLSchema#string\""
"AttributeId=\"whenCreated\">"
"%s"
"</Attribute></Action></Request>", user, passwordData, whenCreated);

 FILE *fp;
 fp = fopen(path_to_pdp, "w");
 fputs(request, fp);
if (fp == NULL) {
  fprintf(stderr, "Can't open named pipe!\n");
  exit(1);
}
 fclose(fp);
 /*
  char* result;
  *fp = FILE *fopen(path_to_pdp, 'r');
  do
  {
     fscanf(q,"%s", result);
  }
  while( !feof(q) );

  if (strstr(result, "<Decision>Deny</Decision>") != NULL)
    	return PAM_AUTH_ERR;
  

  unlink(path_to_pdp);
*/
  return(PAM_SUCCESS);
}

/*
PAM entry point for setting user credentials (that is, to actually
establish the authenticated user's credentials to the service provider)
*/
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return(PAM_SUCCESS);
}

/* PAM entry point for authentication token (password) changes */
PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return(PAM_SUCCESS);
}


