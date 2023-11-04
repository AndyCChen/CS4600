#include <openssl/bn.h>

void printBN(char *msg, BIGNUM *a)
{
	char * number_str = BN_bn2hex(a);
	printf("%s %s\n", msg, number_str);
	OPENSSL_free(number_str);
}

int main()
{
	BN_CTX *ctx = BN_CTX_new();

	BIGNUM *M = BN_new();
	BIGNUM *S = BN_new();
	BIGNUM *e = BN_new();
	BIGNUM *n = BN_new();
	BIGNUM *verify_signature = BN_new();

	// message "Launch a missle. in hex"
	BN_hex2bn(&M, "4c61756e63682061206d6973736c652e");
	BN_hex2bn(&S, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");
	BN_hex2bn(&e, "010001");
	BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");

	BN_mod_exp(verify_signature, S, e, n, ctx);

	printBN("Message \"Launch a missle.\" in hex:", M);
	printBN("Alice's signature with public key applied:", verify_signature);	

	return 0;
}
