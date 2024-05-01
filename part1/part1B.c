/*
 * Address Space Layout Randomization
 * Part 1B: Prefetch
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <time.h>
#include <mmintrin.h>
#include <xmmintrin.h>
#include <fcntl.h>
#include <errno.h>
#include <stdbool.h>
#include <x86intrin.h>
#include "lab.h"

/*
 * Part 1
 * Find and return the single mapped address within the range [low_bound, upper_bound).
 */
uint64_t measure_prefetch_time(void* address) {
    unsigned int timer;  // Init a timer to store timestamp outputs
    uint64_t startTime, endTime;  // Variables to hold the timestamps before and after the prefetch
    // Important: Add _mm_mfence() to ensure all memory OPs before are finished to accurately measure time
    _mm_mfence(); // Ensure all previous instructions have been executed
    startTime = __rdtscp(&timer); // Read time stamp before executing prefetch
    _mm_lfence(); // Prevent reordering of the instructions
    _mm_prefetch(address, _MM_HINT_T0); // Prefetch the address into the cache
    _mm_lfence(); // Ensure the prefetch instruction has been executed
    endTime = __rdtscp(&timer); // Read time stamp counter after executing prefetch
    return endTime - startTime; // Return total time consumed
}

uint64_t find_address(uint64_t low_bound, uint64_t high_bound) {
    uint64_t time_threshold = UINT64_MAX;  // Get Threshold for timing, checking purpose
    uint64_t mapped_address = 0;  // Init mapped_addr to 0, return this
    for (uint64_t addr = low_bound; addr < high_bound; addr += PAGE_SIZE) {
        // TODO: Figure out if "addr" is the correct address or not.
        uint64_t time_taken = measure_prefetch_time((void*)addr); // Get time and compare
        if (time_taken < time_threshold) {
            time_threshold = time_taken;
            mapped_address = addr;
        }
    }
    return mapped_address;  // Return min fetch time addr
}