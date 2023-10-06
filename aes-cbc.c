#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

#define MAX_KEY_SIZE 16

char* read_plain_text(char*);

int main(int argc, char **argv)
{
	char padding[16] = "###############";
	char *plain_text = read_plain_text("plain_text.txt");

	if(!plain_text)
	{
		printf("File error!\n");
		return 0;
	}

	unsigned char output_buffer[1024 + EVP_MAX_BLOCK_LENGTH];
	int input_length, output_length, temp_length;


	FILE *file;
	file = fopen("english_word_list.txt", "r");
	if (!file)
	{
		printf("File error!\n");
		return 0;
	}

	unsigned char key[MAX_KEY_SIZE + 1];
	unsigned char temp_input_buffer[256];

	EVP_CIPHER_CTX *context;

	unsigned char iv[] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x99, 0x88,
	0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11};

	unsigned char cipher_text[] = {0x76, 0x4a, 0xa2, 0x6b, 0x55, 0xa4, 0xda,
	0x65, 0x4d, 0xf6, 0xb1, 0x9e, 0x4b, 0xce, 0x00, 0xf4, 0xed, 0x05, 0xe0,
	0x93, 0x46, 0xfb, 0x0e, 0x76, 0x25, 0x83, 0xcb, 0x7d, 0xa2, 0xac, 0x93,
	0xa2};


	while(fgets(temp_input_buffer, 256, file) && strlen(temp_input_buffer))
	{
		size_t len = strlen(temp_input_buffer);

		if(len > 0 && temp_input_buffer[len - 1] == '\n')
		{
			temp_input_buffer[--len] = '\0';
		}

		len = strlen(temp_input_buffer);
		if (len > MAX_KEY_SIZE) break;

		strcpy(key, temp_input_buffer);
		strncat(key, padding, MAX_KEY_SIZE - len);

		context = EVP_CIPHER_CTX_new();
		EVP_CipherInit_ex(context, EVP_aes_128_cbc(), NULL, NULL, NULL, 1);
		OPENSSL_assert(EVP_CIPHER_CTX_key_length(context) == MAX_KEY_SIZE);
		OPENSSL_assert(EVP_CIPHER_CTX_key_length(context) == MAX_KEY_SIZE);

		EVP_CipherInit_ex(context, EVP_aes_128_cbc(), NULL, key, iv, 1);

		if(!EVP_EncryptUpdate(context, output_buffer, &output_length, plain_text, strlen(plain_text)))
		{
			printf("Error in encrypt update!\n");
			EVP_CIPHER_CTX_free(context);
			return 0;
		}

		if(!EVP_EncryptFinal_ex(context, output_buffer +  output_length, &temp_length))
		{
			printf("Error in encrypt final!\n");
			EVP_CIPHER_CTX_free(context);
			return 0;	
		}

		printf("Plaintext length: %d, Ciphertext length: %d\n", strlen(plain_text), output_length + temp_length);
		for(int index = 0; index < output_length + temp_length; index++)
		{
			printf("%x", output_buffer[index]);
		}
		printf("\n");

		if(memcmp(cipher_text, output_buffer, 32) == 0)
		{
			printf("Cipertext matched with the key: %s\n", key);
			EVP_CIPHER_CTX_free(context);
			break;
		}
		
		EVP_CIPHER_CTX_free(context);
	}
	fclose(file);

	return 0;
}

char* read_plain_text(char *filename)
{	
	FILE *file;
	file = fopen(filename, "r");

	if (!file)
	{
		printf("Error, could not open file!\n");
		return NULL;
	}

	fseek(file, 0, SEEK_END);
	long file_size = ftell(file);
	rewind(file);

	char *plain_text = malloc(file_size + 1);
	
	fread(plain_text, file_size, 1, file);
	fclose(file);
	
	return plain_text;
}
