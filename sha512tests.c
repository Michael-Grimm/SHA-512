#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sha512.h"
#include "sha512tests.h"



/**
 * Unit tests for the sha256 algorithm  (message padding, preprocessing, working variables, hash functions, hash computation)
 * Some tests use examples from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf
 * and test vectors from: https://di-mgt.com.au/sha_testvectors.html
 */


/**
 * Prints all functions starting with 'void test' of the importing file. 
 * Can be used to update a function that calls all the test cases.
 */
#define PRINT_TEST_FUNCTIONS  \
     char command[] = "cat " __FILE__ " | grep '^void test' | sed -e 's/void//' -e 's/{/;/'"; \
     FILE *f = popen(command, "w"); \
     pclose(f); 

/**
 * Tests two strings for equality.
 */
#define TEST_STRING_EQUALS(expected, actual) \
	if(strcmp(expected, actual) != 0){ \
		printf("%s, line %d: Expected %s, but was %s\n", __FUNCTION__, __LINE__, expected, actual); \
		failed_tests += 1; \
	}else{ \
		passed_tests += 1; \
	}

/**
 * Tests two integers for equality.
 */
#define TEST_INT_EQUALS(expected, actual) \
	if(expected != actual){ \
		printf("%s, line %d: Expected %d (0x%llx), but was %d (0x%llx)\n", __FUNCTION__, __LINE__, expected, expected, actual, actual); \
		failed_tests += 1; \
	}else{ \
		passed_tests += 1; \
	}
/**
 * Within a loop: Tests two integers for equality.
 */
#define TEST_INT_EQUALS_LOOP(i, expected, actual) \
	if(expected != actual){ \
		printf("%s, line %d, Index %d: Expected %d (0x%llx), but was %d (0x%llx)\n", __FUNCTION__, __LINE__, i, expected, expected, actual, actual); \
		failed_tests += 1; \
	}else{ \
		passed_tests += 1; \
	}

 

/**
 * Tests two long long integers for equality.
 */
#define TEST_LONGLONG_EQUALS(expected, actual) \
	if(expected != actual){ \
		printf("%s, line %d: Expected 0x%llx, but was 0x%llx\n", __FUNCTION__, __LINE__, expected, actual); \
		failed_tests += 1; \
	}else{ \
		passed_tests += 1; \
	}
	
	

/**
 * Last command in the function that calls the test functions.
 * Prints the results.
 */
#define PRINT_TEST_RESULTS \
	printf("\nResults of testing %s: \nPassed tests: %lld\nFailed tests: %lld\n", __FILE__, passed_tests, failed_tests); \
    passed_tests = 0; \
    failed_tests = 0;
   

  volatile int passed_tests = 0; 
  volatile int failed_tests = 0;


void test_sha512_message_with_0_bits(){
     long long int message[] = {};
     long long int message_length = 0;
     long long  int expected[] = {0xcf83e1357eefb8bd ,0xf1542850d66d8007 ,0xd620e4050b5715dc ,0x83f4a921d36ce9ce ,0x47d0d13c5d85f2b0 ,0xff8318d2877eec2f ,0x63b931bd47417a81 ,0xa538327af927da3e};
      long long int actual[]={0,0,0,0,0,0,0,0}; //Hash buffer
     sha512(message, message_length, actual) ;
     for(int i = 0; i < 8; i++){
          TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
     }
}

void test_sha512_message_with_24_bits(){
  //"abc"
     long long int message[] = {0x6162630000000000};
      long long int message_length = 24;
      long long int expected[] = {0xddaf35a193617aba,0xcc417349ae204131 ,0x12e6fa4e89a97ea2 ,0x0a9eeee64b55d39a ,0x2192992a274fc1a8 ,0x36ba3c23a3feebbd ,0x454d4423643ce80e ,0x2a9ac94fa54ca49f};
      long long int actual[]={0,0,0,0,0,0,0,0}; //Hash buffer
     sha512(message, message_length, actual) ;
     for(int i = 0; i < 8; i++){
          TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
     }
}

void test_sha512_message_with_1176_bits(){
// "Im Anfang erschuf Gott Himmel und Erde. Die Erde war wuest und wirr und Finsternis lag ueber der Urflut und Gottes Geist schwebte ueber dem Wasser." 
  long long int message[] = \
 {0x496d20416e66616e ,0x6720657273636875 ,0x6620476f74742048 ,0x696d6d656c20756e , \
  0x6420457264652e20 ,0x4469652045726465 ,0x2077617220777565 ,0x737420756e642077 , \
  0x69727220756e6420 ,0x46696e737465726e ,0x6973206c61672075 ,0x6562657220646572 , \
  0x205572666c757420 ,0x756e6420476f7474 ,0x6573204765697374 ,0x2073636877656274 , \
  0x6520756562657220 ,0x64656d2057617373 ,0x65722e0000000000}; 
  
     long long int message_length = 1176;
     long long int expected[] = {0x2ca8775e263363c0,0x5e5f62b48963206e,0xeee8142c2e954cb6,0x77010e8e26f79cc7,0xd652fda5d74ed1c8,0xe881ff076dd53809,0x65567756616f603a,0x39e673129ef18d79};
     long long int actual[]={0,0,0,0,0,0,0,0}; //Hash buffer
     sha512(message, message_length, actual) ;
     for(int i = 0; i < 8; i++){
          TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
     }
}



void test_sha512_message_with_448_bits(){
// "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" 
     long long int message[] = {0x6162636462636465, 0x6364656664656667, 0x6566676866676869, 0x6768696A68696A6B, 0x696A6B6C6A6B6C6D, 0x6B6C6D6E6C6D6E6F, 0x6D6E6F706E6F7071}; 
     long long int message_length = 448;
     long long int expected[] = {0x0204a8fc6dda82f0a , 0x0ced7beb8e08a416 , 0x57c16ef468b228a8 , 0x279be331a703c335 , 0x96fd15c13b1b07f9 , 0xaa1d3bea57789ca0 , 0x31ad85c7a71dd703 , 0x54ec631238ca3445};
     long long int actual[]={0,0,0,0,0,0,0,0}; //Hash buffer
     sha512(message, message_length, actual) ;
     for(int i = 0; i < 8; i++){
          TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
     }
}

void test_sha512_message_with_8_Million_bits(){
//Testvector from https://di-mgt.com.au/sha_testvectors.html - Message is 1 Million times the character 'a' (dec 97, hex 61)
     long long int oneM = 125000; //1 million 'a'-bytes! For u64 divide by 8 -> 125000 u64-ints
     long long int message_length = 8000000; //bits
     long long int message[oneM];
     for(long long int i = 0; i < oneM; i++){
          message[i] = 0x6161616161616161;
     }
     long long int expected[] = {0xe718483d0ce76964,0x4e2e42c7bc15b463,0x8e1f98b13b204428,0x5632a803afa973eb,0xde0ff244877ea60a,0x4cb0432ce577c31b,0xeb009c5c2c49aa2e,0x4eadb217ad8cc09b};
      long long int actual[]={0,0,0,0,0,0,0,0};  
     sha512(message, message_length, actual) ;
     for(int i = 0; i < 8; i++){
          TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
     }
}
	


void test_calculate_values_from_messagelength_1(){
       long long int actual[]={0,0,0,0,0};
       long long int messagelength = 101376;//1 Block, no free space
       long long int expected[] = {99, 0, 0,0,0};//blocks, blockremainder, words, wordremainder, freespace
     calculate_values_from_messagelength(actual, messagelength); 
     for(int i = 0; i < 5; i++){
     //     printf("%d:exp %d actual %d\n", i, expected[i], actual[i]);
          TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
     }      
}

void test_calculate_values_from_messagelength_2(){
       long long int actual[]={0,0,0,0,0};
       long long int messagelength = 1025;//1 Block, 1 residual bit,  no words, enough free space for padding
       long long int expected[] = {1, 1, 0,1,1};//blocks, blockremainder, words, wordremainder, freespace
     calculate_values_from_messagelength(actual, messagelength); 
     for(int i = 0; i < 5; i++){
     //     printf("%d:exp %d actual %d\n", i, expected[i], actual[i]);
          TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
     }      
}


void test_calculate_values_from_messagelength_3(){
       long long int actual[]={0,0,0,0,0};
       long long int messagelength = 100001;
       long long int expected[] = {97, 673, 10, 33, 1};//blocks, blockremainder, words, wordremainder, freespace
     calculate_values_from_messagelength(actual, messagelength); 
     for(int i = 0; i < 5; i++){
     //     printf("%d:exp %d actual %d\n", i, expected[i], actual[i]);
          TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
     }      
}

void test_calculate_values_from_messagelength_4(){
       long long int actual[]={0,0,0,0,0};
       long long int messagelength = 1153; //freespace 129 bits
        long long int expected[] = {1, 129, 2, 1, 1};//blocks, blockremainder, words, wordremainder, freespace
     calculate_values_from_messagelength(actual, messagelength); 
     for(long long int i = 0; i < 5; i++){
       //  printf("%d:exp %d actual %d\n", i, expected[i], actual[i]);
          TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
     }      
}

void test_calculate_values_from_messagelength_5(){
       long long int actual[]={0,0,0,0,0};
       long long int messagelength = 896; //freespace only 128 bits -> second block necessary
        long long int expected[] = {0, 896, 14, 0, 2};//blocks, blockremainder, words, wordremainder, freespace
     calculate_values_from_messagelength(actual, messagelength); 
     for(int i = 0; i < 5; i++){
       //  printf("%d:exp %d actual %d\n", i, expected[i], actual[i]);
          TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
     }      
}

void test_calculate_values_from_messagelength_6(){
       long long int actual[]={0,0,0,0,0};
       long long int messagelength = 1000000; 
        long long int expected[] = {976, 576, 9, 0, 1};//blocks, blockremainder, words, wordremainder, freespace
     calculate_values_from_messagelength(actual, messagelength); 
     for(int i = 0; i < 5; i++){
       //  printf("%d:exp %d actual %d\n", i, expected[i], actual[i]);
          TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
     }      
}

void test_calculate_values_from_messagelength_7(){
       long long int actual[]={0,0,0,0,0};
       long long int messagelength = 1023; //1 free bit for padding, length in new block
        long long int expected[] = {0, 1023, 15, 63, 2};//blocks, blockremainder, words, wordremainder, freespace
     calculate_values_from_messagelength(actual, messagelength); 
     for(long long int i = 0; i < 5; i++){
       //  printf("%d:exp %d actual %d\n", i, expected[i], actual[i]);
          TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
     }      
}

void test_calculate_values_from_messagelength_8(){
       long long int actual[]={0,0,0,0,0};
       long long int messagelength = 0; 
        long long int expected[] = {0, 0, 0, 0, 0};//blocks, blockremainder, words, wordremainder, freespace
     calculate_values_from_messagelength(actual, messagelength); 
     for(int i = 0; i < 5; i++){
       //  printf("%d:exp %d actual %d\n", i, expected[i], actual[i]);
          TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
     }      
}




void test_set_residual_bits_3(){

       long long int message[] ={}; 
        long long int messagelength = 0;

       long long int expected[] = {0x8000000000000000,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0};
       long long int actual[] =   {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0};
     set_residual_bits(message,messagelength,actual);
         for(int i = 0; i<32; i++){
         //   printf("%d:exp %x actual %x\n", i, expected[i], actual[i]);
	      TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
          }
}


void test_set_residual_bits_4(){
       long long int x = 32;        //2 Blocks     
       long long int message[x]; 
       for(long long int i = 0; i < x; i++){
             message[i] = i;
       }
        long long int messagelength = 2048;

       long long int expected[] = {0x8000000000000000,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,2048, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0};
       long long int actual[] =   {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0};
     set_residual_bits(message,messagelength,actual);
         for(int i = 0; i<32; i++){
         //   printf("%d:exp %x actual %x\n", i, expected[i], actual[i]);
	      TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
          }
}



void test_set_residual_bits_5(){
       long long int x = 524287;             
       long long int message[x]; 
       for(long long int i = 0; i < x; i++){
             message[i] = i%16;
       }
        long long int messagelength = 33554368;

       long long int expected[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,0x8000000000000000, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,33554368};
       long long int actual[] =   {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0};
     set_residual_bits(message,messagelength,actual);
         for(int i = 0; i<32; i++){
         //   printf("%d:exp %x actual %x\n", i, expected[i], actual[i]);
	      TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
          }
}

void test_set_residual_bits_6(){
       long long int x = 65536;             
       long long int message[x]; 
       for(long long int i = 0; i < x; i++){
             message[i] = i;
       }
        long long int messagelength = 4194304;

       long long int expected[] = {0x8000000000000000,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,4194304, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0};
       long long int actual[] =   {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0};
     set_residual_bits(message,messagelength,actual);
         for(int i = 0; i<32; i++){
         //   printf("%d:exp %x actual %x\n", i, expected[i], actual[i]);
	      TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
          }
}

void test_set_residual_bits_7(){
       //                      |1 u64, 1 nibble mit
       long long int message[] ={0xcafebabedeadbeef, 0x8000000000000000}; //b|1000| mit padding: b|1100| = 0xc
       long long int messagelength = 65;
       long long int expected[] = {0xcafebabedeadbeef, 0xc000000000000000,0,0,0,0,0,0, 0,0,0,0,0,0,0,0x0000000041, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0};
       long long int actual[] =   {0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0};
     set_residual_bits(message,messagelength,actual);
         for(int i = 0; i<32; i++){
      //  printf("%d:exp %x actual %x\n", i, expected[i], actual[i]);
	      TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
          }
}

void test_set_residual_bits_8(){
       // "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqabcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"  14 u64-ints
       long long int message[] = {0x6162636462636465, 0x6364656664656667, 0x6566676866676869, 0x6768696A68696A6B, 0x696A6B6C6A6B6C6D, 0x6B6C6D6E6C6D6E6F, 0x6D6E6F706E6F7071, 0x6162636462636465, 0x6364656664656667, 0x6566676866676869, 0x6768696A68696A6B, 0x696A6B6C6A6B6C6D, 0x6B6C6D6E6C6D6E6F, 0x6D6E6F706E6F7071}; 
       long long int messagelength = 896;
       long long int expected[] = {0x6162636462636465, 0x6364656664656667, 0x6566676866676869, 0x6768696A68696A6B, 0x696A6B6C6A6B6C6D, 0x6B6C6D6E6C6D6E6F, 0x6D6E6F706E6F7071, 0x6162636462636465, 0x6364656664656667, 0x6566676866676869, 0x6768696A68696A6B, 0x696A6B6C6A6B6C6D, 0x6B6C6D6E6C6D6E6F, 0x6D6E6F706E6F7071,0x8000000000000000, 0,   0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0x0000000000000380 }; 

       long long int actual[] =   {0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0};
       set_residual_bits(message,messagelength,actual);
         for(int i = 0; i<32; i++){
    //    printf("%d:exp %x actual %x\n", i, expected[i], actual[i]);
	      TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
          }
}

void test_set_residual_bits_9(){
       long long int message[] =  {0x6520756562657220 ,0x64656d2057617373 ,0x6572280000000000}; //2 x 64 + 2x8 + 4+ 1 nibble 0x4 
       long long int messagelength = 149;
       long long int expected[] = {0x6520756562657220 ,0x64656d2057617373 ,0x65722c0000000000, 0,0,0,0,0,0,0,0,0,0,0, 0,149, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0}; 

       long long int actual[] =   {0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0};
       set_residual_bits(message,messagelength,actual);
         for(int i = 0; i<32; i++){
    //    printf("%d:exp %x actual %x\n", i, expected[i], actual[i]);
	      TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
          }
}

void test_set_residual_bits_10(){
  long long int message[] = \
 {0x496d20416e66616e ,0x6720657273636875 ,0x6620476f74742048 ,0x696d6d656c20756e , \
  0x6420457264652e20 ,0x4469652045726465 ,0x2077617220777565 ,0x737420756e642077 , \
  0x69727220756e6420 ,0x46696e737465726e ,0x6973206c61672075 ,0x6562657220646572 , \
  0x205572666c757420 ,0x756e6420476f7474 ,0x6573204765697374 ,0x2073636877656274 , \
  0x6520756562657220 ,0x64656d2057617373 ,0x65722e0000000000}; // 1 Block,2 u64-ints, 2Bytes, 1 nibble (0x2), 3 bits (0xe) Padding changes 0xe to 0xf
  
     long long int messagelength = 1175; 
       long long int expected[] = {0x6520756562657220 ,0x64656d2057617373 ,0x65722f0000000000,0,0,0,0,0,0,0,0,0,0,0,0,1175, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0}; 
       long long int actual[] =   {0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0};
       set_residual_bits(message,messagelength,actual);
         for(int i = 0; i<32; i++){
    //    printf("%d:exp %x actual %x\n", i, expected[i], actual[i]);
	      TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
          }
}

int main(void){
/**
 *  To print a list of all test functions, uncomment
 */
//PRINT_TEST_FUNCTIONS

 printf("\nTesting SHA-256 functions.\n");

 test_sha512_message_with_0_bits();
 test_sha512_message_with_24_bits();
 test_sha512_message_with_1176_bits();
 test_sha512_message_with_448_bits();
 test_sha512_message_with_8_Million_bits();
 test_calculate_values_from_messagelength_1();
 test_calculate_values_from_messagelength_2();
 test_calculate_values_from_messagelength_3();
 test_calculate_values_from_messagelength_4();
 test_calculate_values_from_messagelength_5();
 test_calculate_values_from_messagelength_6();
 test_calculate_values_from_messagelength_7();
 test_calculate_values_from_messagelength_8();
 test_set_residual_bits_3();
 test_set_residual_bits_4();
 test_set_residual_bits_5();
 test_set_residual_bits_6();
 test_set_residual_bits_7();
 test_set_residual_bits_8();
 test_set_residual_bits_9();
 test_set_residual_bits_10();


   PRINT_TEST_RESULTS
}
