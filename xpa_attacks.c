#define AES_KEY_SIZE 16
#define AES_KEY_RANGE 256

#include <stdint.h>
#include <xpa_attacks.h>


void dpa_2(container *data){

    uint8_t i, j, k, l;
    uint8_t key[AES_KEY_SIZE];

    double ref_curve[AES_KEY_RANGE] = { 0 };

    double average[data->nb_probes];
    double *group[2];
    uint8_t size[2] = { 0 };

    double group[0] = calloc(sizeof(double)*data->nb_datapoints);
    double group[1] = calloc(sizeof(double)*data->nb_datapoints);

    /**
     * For every byte of the AES key
     */
    for (i = 0 ; i < AES_KEY_SIZE ; i++){

        /**
         * For every possible value of the current byte of the AES key
         */
        for (key[i] = 0 ; key[i] < AES_KEY_RANGE ; key[i]++){

            /**
             * Go through all the probes, and add up the datapoints
             */
            for (j = 0 ; j < data->nb_probes ; j++) {

                // 1. Discriminator / Oracle
                // Take most significant bit of first sbox after SubBytes as group discriminator of current trace
                k = Sbox[key[i] ^ data->t_plaintexts[j][i]] >> 7;

                // 2. Add up
                // Add up all the datapoints of the entire trace
                for (l = 0; l < data->nb_datapoints; l++) {
                    group[k] += data->t_traces[j][l];
                }
                size[k]++;
            }

            // 3. Statistics
            // Compute average for every group and record the difference
            for (j = 0 ; j < data->nb_probes ; j++){
                average[j] = fabs( group[0][j]/counter[0] - group[1][j]/counter[1]);
            }

            // 4. Get the maxium value
            max = average[0];
            for (j = 1 ; j < data->nb_probes ; j++){
                if (average[j] > max){
                    max = average[j];
                }
            }

            // 5. Insert it in reference curve
            ref_curve[ key[i] ] = max;

            // Clean up memory
            memset(group[0], 0, sizeof(double)*data->nb_datapoints);
            memset(group[1], 0, sizeof(double)*data->nb_datapoints);
        }

        // 6. Get the outstanding/maximum value out of the reference curve for that byte
        // This should be our key byte
        k = 0;
        for ( j = 1 ; j < AES_KEY_RANGE ; j++){
            if (ref_curve[j] >= ref_curve[k]){
                k = j;
            }
        }

        key[i] = k;

        // Clean up memory
        memset(ref_curve, 0, AES_KEY_RANGE*sizeof(double));
    }

    printf("Recovered AES key :\n[ ");
    for (i = 0 ; i < AES_KEY_SIZE ; i++){
        print(" %d ", key[i]);
    }
    printf("]\n");

    // Clean up memory and quit
    memset(key, 0, AES_KEY_SIZE);

    free(group[0]);
    free(group[1]);
}

#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <math.h>

#define SAMPLES 1500    // number of samples in a trace
#define NB_TRACES 1000
#define LENGTH_KEY 16

char t_plaintexts[NB_TRACES][3];    // plaintext is an int of value max 256 => max 3 char
float t_traces[NB_TRACES][SAMPLES];
char r_sbox[NB_TRACES]; // get result of the first SBox
char* filename = "aes_traces.csv";

unsigned char SBOX[256][4] = 
 {
    "0x63", "0x7C", "0x77", "0x7B", "0xF2", "0x6B", "0x6F", "0xC5", "0x30", "0x01", "0x67", "0x2B", "0xFE", "0xD7", "0xAB", "0x76",
    "0xCA", "0x82", "0xC9", "0x7D", "0xFA", "0x59", "0x47", "0xF0", "0xAD", "0xD4", "0xA2", "0xAF", "0x9C", "0xA4", "0x72", "0xC0",
    "0xB7", "0xFD", "0x93", "0x26", "0x36", "0x3F", "0xF7", "0xCC", "0x34", "0xA5", "0xE5", "0xF1", "0x71", "0xD8", "0x31", "0x15",
    "0x04", "0xC7", "0x23", "0xC3", "0x18", "0x96", "0x05", "0x9A", "0x07", "0x12", "0x80", "0xE2", "0xEB", "0x27", "0xB2", "0x75",
    "0x09", "0x83", "0x2C", "0x1A", "0x1B", "0x6E", "0x5A", "0xA0", "0x52", "0x3B", "0xD6", "0xB3", "0x29", "0xE3", "0x2F", "0x84",
    "0x53", "0xD1", "0x00", "0xED", "0x20", "0xFC", "0xB1", "0x5B", "0x6A", "0xCB", "0xBE", "0x39", "0x4A", "0x4C", "0x58", "0xCF",
    "0xD0", "0xEF", "0xAA", "0xFB", "0x43", "0x4D", "0x33", "0x85", "0x45", "0xF9", "0x02", "0x7F", "0x50", "0x3C", "0x9F", "0xA8",
    "0x51", "0xA3", "0x40", "0x8F", "0x92", "0x9D", "0x38", "0xF5", "0xBC", "0xB6", "0xDA", "0x21", "0x10", "0xFF", "0xF3", "0xD2",
    "0xCD", "0x0C", "0x13", "0xEC", "0x5F", "0x97", "0x44", "0x17", "0xC4", "0xA7", "0x7E", "0x3D", "0x64", "0x5D", "0x19", "0x73",
    "0x60", "0x81", "0x4F", "0xDC", "0x22", "0x2A", "0x90", "0x88", "0x46", "0xEE", "0xB8", "0x14", "0xDE", "0x5E", "0x0B", "0xDB",
    "0xE0", "0x32", "0x3A", "0x0A", "0x49", "0x06", "0x24", "0x5C", "0xC2", "0xD3", "0xAC", "0x62", "0x91", "0x95", "0xE4", "0x79",
    "0xE7", "0xC8", "0x37", "0x6D", "0x8D", "0xD5", "0x4E", "0xA9", "0x6C", "0x56", "0xF4", "0xEA", "0x65", "0x7A", "0xAE", "0x08",
    "0xBA", "0x78", "0x25", "0x2E", "0x1C", "0xA6", "0xB4", "0xC6", "0xE8", "0xDD", "0x74", "0x1F", "0x4B", "0xBD", "0x8B", "0x8A",
    "0x70", "0x3E", "0xB5", "0x66", "0x48", "0x03", "0xF6", "0x0E", "0x61", "0x35", "0x57", "0xB9", "0x86", "0xC1", "0x1D", "0x9E",
    "0xE1", "0xF8", "0x98", "0x11", "0x69", "0xD9", "0x8E", "0x94", "0x9B", "0x1E", "0x87", "0xE9", "0xCE", "0x55", "0x28", "0xDF",
    "0x8C", "0xA1", "0x89", "0x0D", "0xBF", "0xE6", "0x42", "0x68", "0x41", "0x99", "0x2D", "0x0F", "0xB0", "0x54", "0xBB", "0x16"
 };

// explicit declaration of functions used
void dpa();
void read_data_from_source(char* file);
int oracle(int plaintext, int key);

int oracle(int plaintext, int key){
    /*
    XOR key and plaintext and make the first SubBytes
    Returns the first bit value of the result of the SubBytes
    */
    int input, output, bit;
    // XOR key
    input = plaintext ^ key;
    // get output
    output = (int)strtol(SBOX[input],NULL,16);
    bit =  output & 1;
    return bit;
}

void dpa(){
    int key[LENGTH_KEY];
    // for each byte
    for(int x = 0; x < LENGTH_KEY; x++){
        // initialize max amplitude value
        float max = 0;

        for(int y; y < 256; y++){

            // calculate the estimated value of the bit after encryption and
            // sort out the traces in 2 tabs depending on the fist bit value
            // group_A : group of 1's
            // group_B : group of 0's
            int group_A[NB_TRACES], group_B[NB_TRACES];
            float medium_group_A[256][SAMPLES], medium_group_B[256][SAMPLES], amplitude[256][SAMPLES];
            int len_a = 0, len_b = 0;
            int bit;
            for(int i = 0; i < NB_TRACES; i++){
                // get the value of the plaintext for this trace
                char plaintext[3];
                for(int ln = 0; ln < 3; ln++){
                    plaintext[ln] = t_plaintexts[i][ln];
                }
                int plain = strtol(plaintext,NULL,10);
                
                bit = oracle(plain, y); // get value of the first bit

                if(bit == 0){
                    group_A[len_a] = i;
                    len_a++;
                }
                else{
                    group_B[len_b] = i;
                    len_b++;
                }
            }

            // calculate the medium value for each sample of each group
            for(int i = 0; i < SAMPLES; i++){
                for(int j = 0; j < len_a; j++){
                    medium_group_A[y][i] += t_traces[group_A[j]][i];
                }
                for(int j = 0; j < len_a; j++){
                    medium_group_A[y][i] /= len_a;
                }
                for(int j = 0; j < len_b; j++){
                    medium_group_B[y][i] += t_traces[group_B[j]][i];
                }
                for(int j = 0; j < len_b; j++){
                    medium_group_B[y][i] /= len_b;
                }
            }

            // search of max amplitude of store the key value with got the max amplitude
            for(int i = 0;i < SAMPLES;i++){
                // fabsf compute abolute value of a float
                amplitude[y][i] = fabsf(fabsf(medium_group_A[y][i]) - fabsf(medium_group_B[y][i]));
                // stores the max value
                if(amplitude[y][i] > max){
                    max = amplitude[y][i];
                    key[x] = y;
                }
                medium_group_A[y][i] = 0;
                medium_group_B[y][i] = 0;
            }
        }

    }
    printf("DPA - Found key : %d\n", key);
    
}

void read_data_from_source(char* file){
    printf("reading the file\n");
}

int main(){
    read_data_from_source(filename);
    dpa();
}
