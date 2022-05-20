#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int hex_to_int(char c)
{                                     // hex to int will come with parameter value c which is passed from main function, line 53
    int first = c / 16 - 3;           // if c is say 70 then 5-3 = 2 will be in the first variable value
    int second = c % 16;              // 70 % 16 = 6 will be in the second variable value
    int result = first * 10 + second; // result will contain 2*10=20+6 = 26
    if (result > 9)                   // if result is greater then 9 then result -- so result will be 25
        result--;
    return result; // return the result
}

int hex_to_ascii(char c, char d)
{                                  // hex to ascci will bring with two parameteres , assume c = 70 , d=5
    int high = hex_to_int(c) * 16; // 70 * 16 will be passed to above function and store the high variable
    int low = hex_to_int(d);       // 5 will be pass to above function and return value will be store in low
    return high + low;             // return the total of both
}

int main(int arc, char *argv[])
{
    unsigned char outbuf[1024];  // output buffer for storing output string
    unsigned char cipher[1024];  // cipher buffer array will store encrypted strings
    unsigned char temp, key[16]; // key array will store key for this encryption , temp variable for temp storage
    int outlen, tmplen, l, i, length, count, found = 0, k = 0;
    size_t nread, len;
    FILE *in;             // file operation for input
    unsigned char iv[17]; // initialization vector

    for (i = 0; i < 17; i++) // this loop will fill null byte on all 17 IV values
        iv[i] = 0;
    iv[16] = '\0';

    char intext[] = "This is a top secret.";                                        // plain text
    char st[] = "8d20e5056a8d24d0462ce74e4904c1b513e10d1df4a2ef2ad4540fae1ca0aaf9"; // SHA2-256 hexadecimal key of 64bit
    i = 0;
    while (i < 64) // this loop will convert small alphabatic to capital character
    {
        if (st[i] >= 'a' && st[i] <= 'z')
            st[i] = st[i] - 32;
        i++;
    }

    length = strlen(st); // this will find the length of st array and store in length variable
    char buf = 0;        // character type variable buf

    for (i = 0; i < length; i++) // this loop will run until the length over which we measure above
    {
        if (i % 2 != 0) // if value of i modulo 2 is not equal to zero then pass that value of st[i] array to hex_to_ascii function which we created above
        {
            cipher[k] = hex_to_ascii(buf, st[i]); // value will be pass with buf=0 and possition value of st[i]
            k++;                                  // k variable is initialized with 0 above that will be increment by 1 now
        }
        else
        {
            buf = st[i]; // if value of i is equal to 0 then insert null in the cipher[k] array position
        }
    }
    cipher[k] = '\0';
    in = fopen("/home/seed/Desktop/english_wrd_list.txt", "r"); // open the file in read mode
    if (in == NULL)                                             // if path is wrong then in value will be null that means an error occured or file not found or path not found or may not have read rights
    {
        printf("\n cannot open file"); // error will be thrown
        exit(1);                       // and exit from the program
    }

    EVP_CIPHER_CTX ctx;
    ctx = EVP_CIPHER_CTX_new();        // declared the libraray data type variable ctx
    EVP_CIPHER_CTX_init(&ctx); // storing address of ctx for reference with memory allocation initialization

    while (fgets(key, sizeof(key), in) != NULL) // key[16] is not NULL this loop will continue
    {
        l = 0;
        if (strlen(key) < 16) // if the key length is lessthan 16
        {
            l = strlen(key) - 1; // substract 1 from key length and store in variable l ie if key size is 13 then l will contain 12
            while (l < 16)       // if l is less than 16
            {
                key[l] = ' '; // put space in the key array with possition of l
                l++;          // increment l with 1 , declared above
            }
            key[l] = '\0'; // else insert null byte in the key array
        }
        else
            key[16] = '\0'; // else insert null byte at the end of key array at possition 16 last  position of array

        EVP_EncryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, key, iv); // this is openssl library you can see the reference here https://www.openssl.org/docs/man1.1.0/man3/EVP_CipherInit_ex.html

        if (!EVP_EncryptUpdate(&ctx, outbuf, &outlen, intext, strlen(intext))) // if this parameteres are not passed then return with 0
        {
            return 0;
        }

        if (!EVP_EncryptFinal_ex(&ctx, outbuf + outlen, &tmplen)) // if this parameteres are nt passed then return with 0
        {
            return 0;
        }
        outlen += tmplen;             // outlen = outlen + tmplen
        EVP_CIPHER_CTX_cleanup(&ctx); // openssl cleanup api to clear the ctx address values

        count = 0;
        for (i = 0; i < 32; i++) // this loop will copy the encrypted outbuf to cipher buffer array
        {
            if (cipher[i] == outbuf[i])
                count++;
        }

        if (count == 32)
        {
            printf("\nplain text...................%s\n", intext); // plaint text display
            printf("\ncipher text to be compared...\n%s", cipher); // cipher text display
            printf("\niv...........................%s", iv);       // initialization vector
            printf("\n....key found....\n");
            printf("\n key.........................%s", key);        // key display
            printf("\n actual cipher text..........\n%s", cipher);   // encrypted chipher
            printf("\n formed cipher text..........\n%s\n", outbuf); // output buffer stored text
            found = 1;                                               // if it found properly values then set found to 1
            break;
        }
    }
    fclose(in);     // close the file in variable
    if (found == 0) // if variable found equal to zero
    {
        printf("\niv...........................%s", iv);                // print initialization vector value
        printf("\nplain text...................%s\n", intext);          // plaint text
        printf("cipher text..........%s\n", cipher);                    // encrypted cipher text
        printf("cipher text in hex...%s\n", st);                        // st array value
        printf("\n\n key cannot be found for the above cipher text\n"); // key not found message as found status is set to 0
    }
    return 0;
}