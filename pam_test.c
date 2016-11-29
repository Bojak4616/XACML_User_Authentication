#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <stdio.h>

const struct pam_conv conv = {
	misc_conv,
	NULL
};

int main(int argc, char *argv[]) {
	pam_handle_t* pamh = NULL;
	int retval;
	const char* user;
	
	if(argc != 2) {
		printf("Usage: app [username]\n");
		exit(1);
	}

	user = argv[1];
	
	retval = pam_start("first_pam", user, &conv, &pamh);
	
	// Did pam start ok?
	if (retval == PAM_SUCCESS) {
		printf("Process Started.\n");
	} else {
		printf("Ded.\n");
	}

	// Let the user login
	retval = pam_authenticate(pamh, 0);
	if (retval == PAM_SUCCESS) {
		printf("Credentials Accepted.\n");
	} else {
		printf("Credentials Denied.\n");
	}

	retval = pam_acct_mgmt(pamh, 0);
	// Did everything work?
	if (retval == PAM_SUCCESS) {
		printf("Authenticated\n");
	} else {
		printf("Not Authenticated\n");
	}

	// close PAM (end session)
	if (pam_end(pamh, retval) != PAM_SUCCESS) {
		pamh = NULL;
		printf("check_user: failed to release authenticator\n");
		exit(1);
	}

	return retval == PAM_SUCCESS ? 0 : 1;
}

