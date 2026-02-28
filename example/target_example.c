/**
 * Example target program for symbolic execution testing
 * 
 * Compile with:
 *   gcc -o target_example target_example.c -O0
 *   gcc -o target_example_no_pic target_example.c -O0 -no-pie -fno-pic
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Simple password check with multiple branches
int check_secret(uint32_t input) {
    // First check: must be greater than 1000
    if (input <= 1000) {
        return 0;
    }
    
    // Second check: specific bit pattern
    if ((input & 0xFF) != 0x42) {
        return 0;
    }
    
    // Third check: division result
    if ((input / 256) != 0x12) {
        return 0;
    }
    
    return 1;
}

// Function with arithmetic constraints
int check_math(int a, int b, int c) {
    if (a + b != 100) {
        return 0;
    }
    
    if (a - b != 20) {
        return 0;
    }
    
    if (b * c != 240) {
        return 0;
    }
    
    if (c < 0) {
        return -1;
    }
    
    return 1;
}

// Array access with bounds checking
int check_array(const uint8_t* arr, size_t len) {
    if (len < 4) {
        return 0;
    }
    
    if (arr[0] != 0xDE) {
        return 1;
    }
    
    if (arr[1] != 0xAD) {
        return 2;
    }
    
    if (arr[2] != 0xBE) {
        return 3;
    }
    
    if (arr[3] != 0xEF) {
        return 4;
    }
    
    return 0xdeadbeef;
}

// Nested conditions
int nested_check(int x, int y) {
    if (x > 0) {
        if (y > 0) {
            if (x + y > 50) {
                return 1;  // Path 1: x>0, y>0, x+y>50
            } else {
                return 2;  // Path 2: x>0, y>0, x+y<=50
            }
        } else {
            if (x - y > 30) {
                return 3;  // Path 3: x>0, y<=0, x-y>30
            } else {
                return 4;  // Path 4: x>0, y<=0, x-y<=30
            }
        }
    } else {
        if (y > 0) {
            return 5;  // Path 5: x<=0, y>0
        } else {
            return 6;  // Path 6: x<=0, y<=0
        }
    }
}

// Loop with symbolic bound
int loop_check(int n) {
    int sum = 0;
    
    if (n < 0 || n > 100) {
        return -1;
    }
    
    for (int i = 0; i < n; i++) {
        sum += i;
    }
    
    // Check if sum equals expected value for specific n
    if (sum == 45) {
        return 100;  // n = 10
    } else if (sum == 55) {
        return 200;  // n = 11 (actually sum 0..10)
    } else if (sum == 66) {
        return 300;  // n = 12 (actually sum 0..11)
    }
    
    return sum;
}

// Switch-like pattern
int switch_check(int op) {
    switch (op) {
        case 1:
            return 100;
        case 2:
            return 200;
        case 3:
            return 300;
        case 4:
            return 400;
        default:
            return -1;
    }
}

// Main entry point for testing
int main(int argc, char* argv[]) {
    printf("=== Symbolic Execution Test Program ===\n\n");
    
    if (argc < 2) {
        printf("Usage: %s <test_num> [args...]\n", argv[0]);
        printf("Tests:\n");
        printf("  1 <input>        - check_secret (find: 0x1242)\n");
        printf("  2 <a> <b> <c>    - check_math (find: a=60, b=40, c=6)\n");
        printf("  3 <hex_bytes>    - check_array (find: DEADBEEF)\n");
        printf("  4 <x> <y>        - nested_check (6 different paths)\n");
        printf("  5 <n>            - loop_check (find: n=10,11,12)\n");
        printf("  6 <op>           - switch_check (ops 1-4)\n");
        printf("  7                - run all tests with demo values\n");
        return 1;
    }
    
    int test_num = atoi(argv[1]);
    int result;
    
    switch (test_num) {
        case 1:  // check_secret
            if (argc < 3) {
                printf("Need input value\n");
                return 1;
            }
            result = check_secret((uint32_t)atoi(argv[2]));
            printf("check_secret(%d) = %d\n", atoi(argv[2]), result);
            if (result == 1) {
                printf("SUCCESS: Found valid input!\n");
            }
            break;
            
        case 2:  // check_math
            if (argc < 5) {
                printf("Need three values: a b c\n");
                return 1;
            }
            result = check_math(atoi(argv[2]), atoi(argv[3]), atoi(argv[4]));
            printf("check_math(%d, %d, %d) = %d\n", 
                   atoi(argv[2]), atoi(argv[3]), atoi(argv[4]), result);
            if (result == 1) {
                printf("SUCCESS: Found valid inputs!\n");
            }
            break;
            
        case 3:  // check_array
            if (argc < 3) {
                printf("Need hex bytes (e.g., DEADBEEF)\n");
                return 1;
            }
            {
                uint32_t val = (uint32_t)strtoul(argv[2], NULL, 16);
                uint8_t arr[4] = {
                    (val >> 24) & 0xFF,
                    (val >> 16) & 0xFF,
                    (val >> 8) & 0xFF,
                    val & 0xFF
                };
                result = check_array(arr, 4);
                printf("check_array(0x%08X) = %d\n", val, result);
                if (result == 0xdeadbeef) {
                    printf("SUCCESS: Found valid bytes!\n");
                }
            }
            break;
            
        case 4:  // nested_check
            if (argc < 4) {
                printf("Need two values: x y\n");
                return 1;
            }
            result = nested_check(atoi(argv[2]), atoi(argv[3]));
            printf("nested_check(%d, %d) = %d (path %d)\n", 
                   atoi(argv[2]), atoi(argv[3]), result, result);
            break;
            
        case 5:  // loop_check
            if (argc < 3) {
                printf("Need value: n\n");
                return 1;
            }
            result = loop_check(atoi(argv[2]));
            printf("loop_check(%d) = %d\n", atoi(argv[2]), result);
            if (result >= 100) {
                printf("SUCCESS: Found special value!\n");
            }
            break;
            
        case 6:  // switch_check
            if (argc < 3) {
                printf("Need operation: op\n");
                return 1;
            }
            result = switch_check(atoi(argv[2]));
            printf("switch_check(%d) = %d\n", atoi(argv[2]), result);
            if (result > 0) {
                printf("SUCCESS: Valid operation!\n");
            }
            break;
            
        case 7:  // Run all demos
            printf("Running demo tests...\n\n");
            
            printf("Test 1: check_secret(0x1242) = %d\n", 
                   check_secret(0x1242));
            
            printf("Test 2: check_math(60, 40, 6) = %d\n", 
                   check_math(60, 40, 6));
            
            {
                uint8_t arr[] = {0xDE, 0xAD, 0xBE, 0xEF};
                printf("Test 3: check_array(DEADBEEF) = 0x%X\n", 
                       check_array(arr, 4));
            }
            
            printf("Test 4: nested_check(40, 20) = %d\n", 
                   nested_check(40, 20));
            
            printf("Test 5: loop_check(10) = %d\n", 
                   loop_check(10));
            
            printf("Test 6: switch_check(3) = %d\n", 
                   switch_check(3));
            
            printf("\nAll demo tests completed.\n");
            break;
            
        default:
            printf("Unknown test: %d\n", test_num);
            return 1;
    }
    
    return 0;
}
