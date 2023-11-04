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

	BIGNUM *plaintext = BN_new();
	BIGNUM *altered_plaintext = BN_new();
	BIGNUM *signiture = BN_new();
	BIGNUM *altered_signiture = BN_new();
	BIGNUM *n = BN_new();
	BIGNUM *e = BN_new();
	BIGNUM *d = BN_new();

	// hex encoding of "I owe you $2000."	
	BN_hex2bn(&plaintext, "49206f776520796f752024323030302e");
	// hex encoding of "I owe you $3000."
	BN_hex2bn(&altered_plaintext, "49206f776520796f752024333030302e");
	BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
	BN_hex2bn(&e, "010001");
	BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

	BN_mod_exp(signiture, plaintext, d, n, ctx);
	BN_mod_exp(altered_signiture, altered_plaintext, d, n, ctx);

	printBN("Signiture of \"I owe you $2000\"", signiture);
	printBN("Signiture of \"I owe you $3000\"", altered_signiture);	

	return 0;
}
