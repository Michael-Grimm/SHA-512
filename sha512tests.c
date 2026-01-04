#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sha512.h"
#include "sha512tests.h"



/**
 * Unit tests for the sha256 algorithm  (message padding, preprocessing, working variables, hash functions, hash computation)
 * Some tests use examples from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf
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

/**
 * Test vectors from: https://di-mgt.com.au/sha_testvectors.html
 */

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
	

void test_Sigma1_1(){
      long long int input = 1;
      long long int expected = 0x420008000000000;
      long long int actual = test_Sigma1(input);
     TEST_INT_EQUALS(expected, actual)
}

void test_Sigma1_2(){
      long long int input = 0xcafebabe;
      long long int expected = 0xd3affa58;
      long long int actual = test_Sigma1(input);
     TEST_INT_EQUALS(expected, actual)
}	

void test_Sigma0_1(){
      long long int input = 1;
      long long int expected = 0x4008040000000000;
      long long int actual = test_Sigma0(input);
     TEST_INT_EQUALS(expected, actual)
}

void test_Sigma0_2(){
      long long int input = 0xcafebabe;
      long long int expected = 0x9da30271;
      long long int actual = test_Sigma0(input);
     TEST_INT_EQUALS(expected, actual)
}

void test_sig0_1(){
      long long int input = 8;
      long long int expected = 0x10020001;
      long long int actual = test_sig0(input);
     TEST_INT_EQUALS(expected, actual)
}

void test_sig0_2(){
      long long int input = 2;
      long long int expected = 0x4008000;
      long long int actual = test_sig0(input);
     TEST_INT_EQUALS(expected, actual)
}


void test_sig1_1(){
      long long int input = 2048;
      long long int expected = 0x5000002;
      long long int actual = test_sig1(input);
     TEST_INT_EQUALS(expected, actual)
}

void test_sig1_2(){
      long long int input = 15;
      long long int expected = 0x66000;
      long long int actual = test_sig1(input);
     TEST_INT_EQUALS(expected, actual)
}



void test_Ch_1(){
      long long int x = 1;
      long long int y = 3;
      long long int z = 4;
      long long int expected = 5;
      long long int actual = test_Ch(x, y, z);
     TEST_INT_EQUALS(expected, actual)
}

//~ void test_Ch_2(){
      //~ long long int x = 0xcafeb1b1;
      //~ long long int y = 0xd0d0d1d0;
      //~ long long int z = 0xdeaf1234;
      //~ long long int expected = 0xd4d19394;
      //~ long long int actual = test_Ch(x, y, z);
     //~ TEST_INT_EQUALS(expected, actual)
//~ }

//~ void test_Ch_3(){
      //~ long long int x = 0xcafebabe;
      //~ long long int y = 0xd0d0d1d0;
      //~ long long int z = 0xdeaf1234;
      //~ long long int expected = 0xd4d19090;
      //~ long long int actual = test_Ch(x, y, z);
     //~ TEST_INT_EQUALS(expected, actual)
//~ }

//~ void test_Maj_1(){
      //~ long long int x = 0xcafebabe;
      //~ long long int y = 0xd0d0dead;
      //~ long long int z = 0xf1faabba; 
      //~ long long int expected = 0xd0fababe;
      //~ long long int actual = test_Maj(x, y, z);
     //~ TEST_INT_EQUALS(expected, actual)
//~ }

void test_Maj_2(){
      int x = 1;
      int y = 2;
      int z = 3; 
      int expected = 3;
      int actual = test_Maj(x, y, z);
     TEST_INT_EQUALS(expected, actual)
}

//~ /**
 //~ *  T1 = h          + Sigma1(e)          + Ch(e,f,g)                            + K          + W
 //~ *  T1 = 0x12345678 + Sigma1(0xcafebabe) + Ch(0xcafebabe,0xd0d0d1d0,0xdeaf1234) + 0x428a2f98 + 0xf00badad 
 //~ *  T1 = 0x12345678 +    0xd3affa58      +           0xd4d19090                 + 0x428a2f98 + 0xf00badad  
 //~ *  T1 = 0xed4bbea5     
 //~ */
//~ void test_set_t1_1(){
      //~ long long int h = 0x12345678;
      //~ long long int e = 0xcafebabe;
      //~ long long int f = 0xd0d0d1d0;
      //~ long long int g = 0xdeaf1234;
      //~ long long int k = 0x428a2f98;
      //~ long long int w = 0xf00badad;
      //~ long long int expected = 0xed4bbea5;
      //~ long long int actual = test_setT1(h,e,f,g,k,w);
     //~ TEST_INT_EQUALS(expected, actual)
//~ }

//~ /**
 //~ *  T1 = h          + Sigma1(e)          + Ch(e,f,g)                            + K          + W
 //~ *  with overflow:
 //~ *  T1 = 0xffffffff + Sigma1(0xcafebabe) + Ch(0xcafebabe,0xd0d0d1d0,0xdeaf1234) + 0xffffffff + 0xffffffff 
 //~ *  T1 = 0xffffffff +    0xd3affa58      +           0xd4d19090                 + 0xffffffff + 0xffffffff  
 //~ *  T1 = 0xa8818ae5   (= 0x4a8818ae5 modulo 2^32)
 //~ */
//~ void test_set_t1_2(){
      //~ long long int h = 0xffffffff;
      //~ long long int e = 0xcafebabe;
      //~ long long int f = 0xd0d0d1d0;
      //~ long long int g = 0xdeaf1234;
      //~ long long int k = 0xffffffff;
      //~ long long int w = 0xffffffff;
      //~ long long int expected = 0xa8818ae5;
      //~ long long int actual = test_setT1(h,e,f,g,k,w);
     //~ TEST_INT_EQUALS(expected, actual)
//~ }

//~ void test_set_t2_1(){
      //~ long long int a = 0xcafebabe;
      //~ long long int b = 0xd0d0dead;
      //~ long long int c = 0xf1faabba;
      //~ long long int expected = 0x6e9dbd2f;
      //~ long long int actual = test_setT2(a,b,c);
     //~ TEST_INT_EQUALS(expected, actual)
//~ }

void test_prepare_first_16_schedules(){
      long long int block[] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
      long long int expected[] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
      long long int actual[]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};  
     prepare_first_16_schedules(block, actual) ;
     for(int i = 0; i < 16; i++){
	//  printf("%d: %x %x\n", i, expected[i], actual[i]);
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


void test_clear_schedules(){
       long long int actual[80];
       for(int i = 1; i<81; i++){
            actual[i] = i;
       }
       long long int expected[80]; 
              for(int i = 0; i<80; i++){
            expected[i] = 0;
       }
 
     clear_schedules(actual); 
     for(int i = 0; i<80; i++){
         // printf("%d:exp %x actual %x\n", i, expected[i], actual[i]);
          TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
     }      
}

void test_prepare_17th_schedule(){
       long long int values[16] = {1,2,3,4,5,6,7,8, 9,10,11,12,13,14,15,16}; 
       long long int actual[17] = {0xfe,0xfa,0xba,0xbe,0xd0,0xde,0xe1,0xd1,0xca,0xfe,0xa1,0xd1,0xf0,0xd0,0x1d,0xab,0xba};
       long long int expected[17] = {1,2,3,4,5,6,7,8, 9,10,11,12,13,14,15,16, 0x406e00b};
      long long int value17 = prepare_17th_schedule(values, actual);
     //printf("exp %x actual %x\n", 0x406e00b, value17);
     TEST_INT_EQUALS(0x406e00b, value17)
     for(int i = 0; i<17; i++){
       // printf("%d:exp %x actual %x\n", i, expected[i], actual[i]);
          TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
     }      
}




//~ void test_set_working_variables_1(){
      //~ long long int firstWorkingSchedule = 0x61626380; //"abc"    
     //~ //variables after first round
       //~ long long int expected[] = {0x5d6aebcd, 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xfa2a4622, 0x510e527f, 0x9b05688c, 0x1f83d9ab};
       //~ long long int actual[] = {0,0,0,0,0,0,0,0}; 
     //~ set_working_variables_once(firstWorkingSchedule, actual); 
          //~ for(int i = 0; i<8; i++){
	 //~ // printf("%d:exp %x actual %x\n", i, expected[i], actual[i]);
	  //~ TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
          //~ }
//~ }

//~ void test_set_working_variables_2(){
      //~ long long int firstWorkingSchedule = 0x61626364; //"abcd"    
     //~ //variables after first round
       //~ long long int expected[] = {0x5d6aebb1, 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xfa2a4606, 0x510e527f, 0x9b05688c, 0x1f83d9ab};
       //~ long long int actual[] = {0,0,0,0,0,0,0,0}; 
     //~ set_working_variables_once(firstWorkingSchedule, actual); 
          //~ for(int i = 0; i<8; i++){
	//~ //  printf("%d:exp %x actual %x\n", i, expected[i], actual[i]);
	  //~ TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
          //~ }
//~ }

//~ void test_set_working_variables_16times_1(){
     //~ //variables after 16 rounds (t=15)
       //~ long long int expected[] = {0xb0fa238e, 0xc0645fde, 0xd932eb16, 0x87912990, 0x07590dcd, 0x0B92f20c, 0x745a48de, 0x1e578218};
       //~ long long int schedule[] = {0x61626380,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x00000018}; //padded block for message "abc"
       //~ long long int actual[] = {0,0,0,0,0,0,0,0}; 
     //~ set_working_variables_16_times(schedule, actual); 
          //~ for(int i = 0; i<8; i++){
	 //~ // printf("%d:exp %x actual %x\n", i, expected[i], actual[i]);
	  //~ TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
          //~ }
//~ }



//~ void test_set_working_variables_16times_2(){
     //~ //variables after 16 rounds (t=15)
       //~ long long int expected[] = {0xc3486194, 0xdd16cbb3, 0xd68e6457, 0x101a4861, 0x1496a54f, 0x9162aded, 0x9243f8af, 0x839a0fc9};
       //~ long long int schedule[] = {0x61626364,0x62636465,0x63646566,0x64656667,0x65666768,0x66676869,0x6768696a,0x68696a6b,0x696a6b6c,0x6a6b6c6d,0x6b6c6d6e,0x6c6d6e6f,0x6d6e6f70,0x6e6f7071,0x80000000,0}; 
                                //~ //first padded block of message "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
       //~ long long int actual[] = {0,0,0,0,0,0,0,0}; 
     //~ set_working_variables_16_times(schedule, actual); 
          //~ for(int i = 0; i<8; i++){
	 //~ // printf("%d:exp %x actual %x\n", i, expected[i], actual[i]);
	  //~ TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
          //~ }
//~ }

//~ void test_set_working_variables_64times(){
     //~ //variables after 64 rounds (t=63)
       //~ long long int expected[] = {0x1BDC6F6F, 0x86126910, 0xF6F443F8, 0xBCFCE922, 0x25D2430A, 0x2FC08F85, 0xACC75916, 0x962D8621};
     //~ //first block of message "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
       //~ long long int schedule[] = {0x61626364,0x62636465,0x63646566,0x64656667,0x65666768,0x66676869,0x6768696a,0x68696a6b,0x696a6b6c,0x6a6b6c6d,0x6b6c6d6e,0x6c6d6e6f,0x6d6e6f70,0x6e6f7071,0x80000000,0}; 
                                
       //~ long long int actual[] = {0,0,0,0,0,0,0,0}; 
     //~ set_working_variables_64_times(schedule, actual); 
          //~ for(int i = 0; i<8; i++){
	//~ //  printf("%d:exp %x actual %x\n", i, expected[i], actual[i]);
	  //~ TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
          //~ }
//~ }

//~ void test_compute_intermediate_hash_value(){
       //~ long long int expected[] = {0x85E655D6, 0x417A1795, 0x3363376A, 0x624CDE5C, 0x76E09589, 0xCAC5F811, 0xCC4B32C1, 0xF20E533A};
     //~ //first block of message "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
       //~ long long int schedule[] = {0x61626364,0x62636465,0x63646566,0x64656667,0x65666768,0x66676869,0x6768696a,0x68696a6b,0x696a6b6c,0x6a6b6c6d,0x6b6c6d6e,0x6c6d6e6f,0x6d6e6f70,0x6e6f7071,0x80000000,0}; 
       //~ long long int actual[] = {0,0,0,0,0,0,0,0}; 
     //~ compute_intermediate_hash_value(schedule, actual);
          //~ for(int i = 0; i<8; i++){
         //~ //   printf("%d:exp %x actual %x\n", i, expected[i], actual[i]);
	      //~ TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
          //~ }

//~ }

//~ void test_compute_intermediate_hash_value_2(){
       //~ long long int expected[] = {0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223, 0xb00361a3, 0x96177a9c, 0xb410ff61, 0xf20015ad};
     //~ //message "abc", padded first block:
       //~ long long int schedule[] = {0x61626380,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x00000018}; 
       //~ long long int actual[] = {0,0,0,0,0,0,0,0}; 
     //~ compute_intermediate_hash_value(schedule, actual);
          //~ for(int i = 0; i<8; i++){
         //~ //   printf("%d:exp %x actual %x\n", i, expected[i], actual[i]);
	      //~ TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
          //~ }

//~ }

//~ void test_compute_intermediate_hash_value_3(){ //e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c a495991b 7852b855
       //~ long long int expected[] = {0xe3b0c442, 0x98fc1c14, 0x9afbf4c8, 0x996fb924, 0x27ae41e4, 0x649b934c, 0xa495991b, 0x7852b855};
     //~ //empty message "", padded first and only block:
       //~ long long int schedule[] = {0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}; 
       //~ long long int actual[] = {0,0,0,0,0,0,0,0}; 
     //~ compute_intermediate_hash_value(schedule, actual);
          //~ for(int i = 0; i<8; i++){
         //~ //   printf("%d:exp %x actual %x\n", i, expected[i], actual[i]);
	      //~ TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
          //~ }

//~ }

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
 //~ test_Sigma1_1();
 //~ test_Sigma1_2();
 //~ test_Sigma0_1();
 //~ test_Sigma0_2();
 //~ test_sig0_1();
 //~ test_sig0_2();
 //~ test_sig1_1();
 //~ test_sig1_2();
 //~ test_Ch_1();
 //~ test_Ch_2();
 //~ test_Ch_3();
 //test_Maj_1();
 test_Maj_2();
 //~ test_set_t1_1();
 //~ test_set_t1_2();
 //~ test_set_t2_1();
 //~ test_prepare_first_16_schedules();
 test_calculate_values_from_messagelength_1();
 test_calculate_values_from_messagelength_2();
 test_calculate_values_from_messagelength_3();
 test_calculate_values_from_messagelength_4();
 test_calculate_values_from_messagelength_5();
 test_calculate_values_from_messagelength_6();
 test_calculate_values_from_messagelength_7();
 test_calculate_values_from_messagelength_8();
 //~ test_clear_schedules();
 //~ test_prepare_17th_schedule();
 //~ test_set_working_variables_1();
 //~ test_set_working_variables_2();
 //~ test_set_working_variables_16times_1();
 //~ test_set_working_variables_16times_2();
 //~ test_set_working_variables_64times();
 //~ test_compute_intermediate_hash_value();
 //~ test_compute_intermediate_hash_value_2();
 //~ test_compute_intermediate_hash_value_3();  


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
