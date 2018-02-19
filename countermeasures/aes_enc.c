/* 
 * Modified AES encryption using a mask protection against SCA attacks
 * Protection type : RSM - Rotating Sbox Masking
 * Code from the Chipwisperer software
 * Orifinal file : aes_enc.c, author Daniel Otte
*/

 // unfinished and non-functionnal

#include <stdint.h>
#include <string.h>
#include "aes.h"
#include "gf256mul.h"
#include "aes_sbox.h"
#include "aes_enc.h"
#include <avr/pgmspace.h>
#include <sboxes_rsm.h>
#include <stdlib.h>

void aes_shiftcol(void* data, uint8_t shift){
	uint8_t tmp[4];
	tmp[0] = ((uint8_t*)data)[ 0];
	tmp[1] = ((uint8_t*)data)[ 4];
	tmp[2] = ((uint8_t*)data)[ 8];
	tmp[3] = ((uint8_t*)data)[12];

	((uint8_t*)data)[ 0] = tmp[(shift+0)&3];
	((uint8_t*)data)[ 4] = tmp[(shift+1)&3];
	((uint8_t*)data)[ 8] = tmp[(shift+2)&3];
	((uint8_t*)data)[12] = tmp[(shift+3)&3];
}

#define GF256MUL_1(a) (a)
#define GF256MUL_2(a) (gf256mul(2, (a), 0x1b))
#define GF256MUL_3(a) (gf256mul(3, (a), 0x1b))

// Order of execution of the 16 substitution SBoxes
uint8_t index_order[]={0,2,4,6,8,10,12,14,1,3,5,7,9,11,13,15};

static void aes_enc_round(aes_cipher_state_t* state, const aes_roundkey_t* k, uint8_t init){
	uint8_t tmp[16], t;
	uint8_t i;
	int index;

	/* subBytes */
	for(i=0; i<16; ++i){
		// init substitution sbox randomly chosen
		// i current bit
		// modulo 16 because there are 16 Sboxes
		// *256 since all boxes are stored in the same array, and each sbox is of size 256
		index = (((init + index_order[i]) % 16) * 256); 		// => Selection of the Sbox to be read
		tmp[index_order[i]] = pgm_read_byte(mbox + (index + (state->s[index_order[i]])));
	}

	/* shiftRows */
	aes_shiftcol(tmp+1, 1);
	aes_shiftcol(tmp+2, 2);
	aes_shiftcol(tmp+3, 3);

	/* mixColums */
	for(i=0; i<4; ++i){
		t = tmp[4*i+0] ^ tmp[4*i+1] ^ tmp[4*i+2] ^ tmp[4*i+3];
		state->s[4*i+0] = GF256MUL_2(tmp[4*i+0]^tmp[4*i+1]) ^ tmp[4*i+0] ^ t;
		state->s[4*i+1] = GF256MUL_2(tmp[4*i+1]^tmp[4*i+2]) ^ tmp[4*i+1] ^ t;
		state->s[4*i+2] = GF256MUL_2(tmp[4*i+2]^tmp[4*i+3]) ^ tmp[4*i+2] ^ t;
		state->s[4*i+3] = GF256MUL_2(tmp[4*i+3]^tmp[4*i+0]) ^ tmp[4*i+3] ^ t;
	}

	/* addKey */
	for(i=0; i<16; ++i){
		// apply mask compensation to recover standard aes cypher
		tmp[i] = pgm_read_byte(mask_compensation + ((((init+1)%16)*16) + i));
		state->s[i] ^= ((k->ks[i])^tmp[i]);
	}
}

static void aes_enc_lastround(aes_cipher_state_t* state,const aes_roundkey_t* k, uint8_t init){
	uint8_t i;
	int index;
	uint8_t tmp;

	/* subBytes */
	for(i=0; i<16; ++i){
		index = (((init + i) % 16) * 256);
		state->s[i] = pgm_read_byte(mbox + (index + (state->s[i])));
	}

	/* shiftRows */
	aes_shiftcol(state->s+1, 1);
	aes_shiftcol(state->s+2, 2);
	aes_shiftcol(state->s+3, 3);

	for(i=0; i<16; ++i){
        tmp =  pgm_read_byte( mask_compensation + (256 + (((init+1)%16)*16) + i));
        state->s[i] ^= tmp ;
	}

	/* keyAdd */
	for(i=0; i<16; ++i){
		state->s[i] ^= k->ks[i];
	}
}


void aes_encrypt_core(aes_cipher_state_t* state, const aes_genctx_t* ks, uint8_t rounds){
	uint8_t i;
	uint8_t init;	// random initial substitution Sbox offset

	// we use the address of the var init to initialise the seed
	// (could not include the .h files for time() or getpid())	
	srand((intptr_t)&init);
	init = rand() % 16;

	// plaintext xored to a mask and then to the key
	for(i = 0; i < 16; i++){
		state->s[i] ^= pgm_read_byte(m0+((init + i) % 16));
        	state->s[i] ^= ks->key[0].ks[i]; //
	}

	for(i = 1; rounds > 1; rounds--){
		aes_enc_round(state, &(ks->key[i]), init);
		i++;

		init = (init + 1) % 16; // calculate the offset for the next sbox
	}
	
	aes_enc_lastround(state, &(ks->key[i]), init);
	//init = (init + 1) % 16;
}