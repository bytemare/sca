//
// Created by dan on 11/02/18.
//

#include "xpa_new.h"

/**
 * Update reference curve with key index with CPA attack value
 * @param i
 * @param ref_curve
 * @param data
 */
void cpa_core(uint8_t i, double *ref_curve, container *data){

    uint8_t j;
    double hamming[data->nb_probes] = {0};

    for (j = 0; j < data->nb_probes; j++) {

        // 1. Discriminator / Oracle
        k = Sbox[key[i] ^ data->t_plaintexts[j][i]];

        // 2. Compute Hamming Weight (i.e. number of bits different from zero in byte k)
        hamming[j] = hamming_weight(k);
    }

    // 3. Build a reference curve with the maximum correlation coefficients
    ref_curve[ key[i] ] = 0;
    for(j = 0; j < NB_SAMPLES; j++){
        // use the absolute value (-1 and 1 are the values at which the correlation is the strongest)
        k = fabsf(correlationCoefficient(data->t_traces[a], hamming));
        if (k > ref_curve[ key[i] ]){
            ref_curve[ key[i] ] = k;
        }
    }
}





/**
 * Wrapper function for dpa and cpa
 * Mode is chosen by specifying "dpa" or "cpa" in mode parameter
 * @param data
 * @param mode
 */
void xpa(container *data, char xpa_mode[4]){

    uint8_t i, j, k, mode;
    uint8_t key[AES_KEY_SIZE];

    double ref_curve[AES_KEY_RANGE] = {0};


    /**
     * Variables used exclusively by DPA
     */
    double average[data->nb_probes];
    double *group[2];
    uint8_t size[2] = { 0 };

    double group[0] = calloc(sizeof(double)*data->nb_datapoints);
    double group[1] = calloc(sizeof(double)*data->nb_datapoints);


    /**
     * Variables used exclusively by CPA
     */

    // double hamming[AES_KEY_RANGE] = {0};



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

            if (mode == 0){
                dpa_core();
            }
            else{
                cpa_core();
            }


        }