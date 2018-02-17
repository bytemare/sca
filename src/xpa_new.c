#include "xpa_new.h"
#include <math.h>
#include <memory.h>


uint8_t xpa_sbox_oracle(uint8_t key_byte, uint8_t plain_byte){
    return Sbox[key_byte ^ plain_byte];
}


/**
 * Update reference curve with key index with DPA attack value
 * @param i
 * @param key
 * @param ref_curve
 * @param data
 */
void dpa_core(uint8_t i, uint8_t *key, double *ref_curve, container *data){

    uint8_t k;
    uint32_t j, l;

    double max;
    double *average = calloc((size_t)data->nb_probes, sizeof(double));

    double *group[2];
    uint8_t size[2] = { 0 };

    group[0] = calloc((size_t)data->nb_datapoints, sizeof(double));
    group[1] = calloc((size_t)data->nb_datapoints, sizeof(double));

    /**
     * Go through all the probes, and add up the datapoints
     */
    for (j = 0 ; j < data->nb_probes ; j++) {

        // 1. Discriminator / Oracle
        // Take most significant bit of first sbox after SubBytes as group discriminator of current trace
        k = xpa_sbox_oracle(key[i], data->t_plaintexts[j][i]) >> 7;

        // 2. Add up
        // Add up all the datapoints of the entire trace
        for (l = 0; l < data->nb_datapoints; l++) {
            group[k][l] += data->t_traces[j][l];
        }
        size[k]++;
    }

    // 3. Statistics
    // Compute average for every group and record the difference
    for (j = 0 ; j < data->nb_probes ; j++){
        average[j] = fabs( group[0][j]/size[0] - group[1][j]/size[1]);
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

    //printf("dpa rc : %.10g", max);

    free(group[0]);
    free(group[1]);
    free(average);
}


/**
 * Compute Hamming weight of a byte
 * i.e. number of bits different from zero
 * @param k
 * @return
 */
uint8_t xpa_hamming_weight(uint8_t k){
    uint8_t i, h_w = 0;

    for (i = 0 ; i < 8 ; i++){
        h_w += k&1;
        k >>= 1;
    }

    return h_w;
}


/**
 * Update reference curve with key index with CPA attack value
 * @param i
 * @param key
 * @param ref_curve
 * @param data
 */
void cpa_core(uint8_t i, uint8_t *key, double *ref_curve, container *data){

    uint8_t k = 0;
    uint32_t j;

    double *hamming = calloc((size_t)data->nb_probes, sizeof(double));

    for (j = 0; j < data->nb_probes; j++) {

        // 1. Discriminator / Oracle
        k = xpa_sbox_oracle(key[i], data->t_plaintexts[j][i]);

        // 2. Compute Hamming Weight (i.e. number of bits different from zero in byte k)
        hamming[j] = xpa_hamming_weight(k);
    }

    // 3. Build a reference curve with the maximum correlation coefficients
    ref_curve[ key[i] ] = 0;
    for(j = 0; j < data->nb_datapoints; j++){
        // use the absolute value (-1 and 1 are the values at which the correlation is the strongest)
        //k = fabsf(correlationCoefficient(data->t_traces[a], hamming));
        if (k > ref_curve[ key[i] ]){
            ref_curve[ key[i] ] = k;
        }
    }

    free(hamming);
}


/**
 * Wrapper function for dpa and cpa
 * Mode is chosen by specifying "dpa" or "cpa" in mode parameter
 * @param data
 * @param mode
 */
void xpa(container *data, char xpa_mode[4]){

    uint8_t i, mode;
    uint16_t k, j;
    uint8_t key[AES_KEY_SIZE];

    double ref_curve[AES_KEY_RANGE] = {0};

    /**
     * Determine the mode : dpa or cpa
     */
    if ( !strncmp(xpa_mode, "dpa", 3)){
        mode = 0;
    } else {
        if (!strncmp(xpa_mode, "cpa", 3)) {
            mode = 1;
        } else {
            printf("[ERROR] xpa mode not recognised. (chose 'dpa' or 'cpa')\n");
            return;
        }
    }

    /**
     * For every byte of the AES key
     */
    for (i = 0; i < AES_KEY_SIZE; i++) {

        /**
         * For every possible value of the current byte of the AES key
         */
        for (key[i] = 0; key[i] < AES_KEY_RANGE; key[i]++) {

            if (mode == 0) {
                dpa_core(i, key, ref_curve, data);
            } else {
                cpa_core(i, key, ref_curve, data);
            }

            if ( key[i] == 255 ){
                break;
            }
        }

        // Get the outstanding/maximum value out of the reference curve for that byte
        // This should be our key byte
        k = 0;
        for (j = 1; j < AES_KEY_RANGE; j++) {
            if (ref_curve[j] >= ref_curve[k]) {
                k = j;
            }
        }

        key[i] = (uint8_t)k;
        printf("\n[i] Key[%d] : 0x%2.2x\n", i, key[i]);

        // Clean up memory
        memset(ref_curve, 0, AES_KEY_RANGE * sizeof(double));
    }
    printf("\n");

    printf("[i] Recovered AES key :\n");
    for (i = 0 ; i < AES_KEY_SIZE ; i++) {
        printf(" %d ", key[i]);
    }

    // Clean up memory and quit
    memset(key, 0, AES_KEY_SIZE);
}