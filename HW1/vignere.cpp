#include <iostream>
#include <string>
#include <cctype>

// ascii value of character 'a'
#define ASCII_A 97
#define MAX_ALPHABET 26
#define ASCII_OFFSET 97

using namespace std;

void get_input(string&, string&);
string encrypt(string, string);
string decrypt(string, string);

int main() {
   string key;
   string plain_text;
   
   get_input(key, plain_text);

   string encrypted_result = encrypt(key, plain_text);
   string decrypted_result = decrypt(key, encrypted_result);

   cout << "Encrypted result: " << encrypted_result << endl;
   cout << "Decrypted result: " << decrypted_result << endl;

   return 0;
}

void get_input(string& key, string& plain_text) {
   while (true)
   {
      cout << "Enter a key: ";
      getline(cin, key);

      if (key.find_first_of("\t ") != string::npos)
      {
         cout << "No spaces allowed in key!" << endl;
         continue;
      }
      else if (key.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") != string::npos)
      {
         cout << "English letters only in the key!" << endl;
         continue;
      }

      break;
   };

   cout << "Enter a string to encrypt: ";
   getline(cin, plain_text);
   cout << endl;
}

// only handles lowercase letters
string encrypt(string key, string plain_text) {
   string cipher_text = "";
   
   size_t k_index = 0;
   for (size_t index = 0; index < plain_text.length(); index++)
   {
      // skip current iteration if space is encountered
      if (plain_text[index] == ' '){
         cipher_text += ' ';
         continue;
      }

      // wrap back to head of key if end is reached
      size_t key_index = k_index % key.length();
      ++k_index;
       /* 
         subtract ascii value of character at current 
         key index from ascii value of 'a' which is 97
         to get the number of positions to shift the plaintext character
         at current index 
       */
      int shift_value = tolower(key[key_index]) - ASCII_A;
      /*
         -add shift value to ascii value of current plaintext char to shift the char.
         -subtract with offset so values can be modulo by 26 for characters 
          that get shifted beyond z which will wrap back to a
      */
      int offseted_cipher_char = ((tolower(plain_text[index]) + shift_value) - ASCII_OFFSET) % MAX_ALPHABET;
      /*
         -add back offset that was previously subtracted to get the proper ascii values
          for our letters
      */
      char cipher_char = offseted_cipher_char + ASCII_OFFSET;

      cipher_text += cipher_char;
   }
   
   return cipher_text;
}

string decrypt(string key, string cipher_text) {
   string plain_text = "";

   size_t k_index = 0;
   for (size_t index = 0; index < cipher_text.length(); index++) {
      // ignore space
      if (cipher_text[index] == ' ') {
         plain_text += ' ';
         continue;
      }

      size_t key_index = k_index % key.length();
      ++k_index;

      int shift_value = tolower(key[key_index]) - ASCII_A;

      int offseted_cipher_char = ((tolower(cipher_text[index]) - ASCII_OFFSET) + (MAX_ALPHABET - shift_value)) % MAX_ALPHABET;

      char cipher_char = offseted_cipher_char + ASCII_OFFSET;

      plain_text += cipher_char;
   }

   return plain_text;
}

