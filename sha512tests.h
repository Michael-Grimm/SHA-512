/**
 *  Tests functions for 4.1.2 SHA-512 functions.
 */
 long long int test_Sigma0(long long int);
  long long int test_Sigma1(long long  int);
  long long int test_sig0(long long  int);
  long long int test_sig1(long long  int);
  long long int test_Ch(long long  int x, long long  int y, long long  int z);
  long long int test_Maj(long long  int x, long long  int y,long long   int z);
  long long int  test_setT1( long long int h,  long long int e,  long long int f,  long long int g,  long long int k,  long long int w);
 long long int  test_setT2( long long int a,  long long int b,  long long int c);
void prepare_first_16_schedules( long long int *block,  long long int *workingschedule);
void calculate_values_from_messagelength(  long long int *actual,   long long int messagelength); 
void clear_schedules(  long long int *values);
 long long int prepare_17th_schedule(  long long int *values,   long long int *actual); 
void prepare_schedule(  long long int *values,   long long int *actual);
void set_working_variables_once( long long int firstWorkingschedule,   long long int *actual);
void set_working_variables_16_times(  long long int *schedule,   long long int *actual);
void set_working_variables_64_times(  long long int *schedule,   long long int *actual);
void compute_intermediate_hash_value(  long long int *schedule,   long long int *actual);
void set_residual_bits(long long int *message, long long int messagelength,   long long int *residualbits);
