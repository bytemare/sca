#include <unistd.h>
#include <stdint.h>
#include <math.h>
#include <xpa_attacks.h>
#include <memory.h>

uint8_t sbox_oracle(uint8_t key_byte, uint8_t plain_byte){
    return Sbox[key_byte ^ plain_byte];
}

/**
 * DPA attack on given dataset
 * @param data
 */
void dpa(container *data){

    uint8_t i, k = 0;
    uint32_t j, l;
    uint8_t key[AES_KEY_SIZE];

    double ref_curve[AES_KEY_RANGE] = { 0 };

    double max;
    double average[data->nb_probes];

    double *group[2];
    uint8_t size[2] = { 0 };

    group[0] = calloc((size_t)data->nb_datapoints, sizeof(double));
    group[1] = calloc((size_t)data->nb_datapoints, sizeof(double));

    // uint64_t f = 0;
    // uint64_t f_max = (uint64_t)(AES_KEY_SIZE*AES_KEY_RANGE*((data->nb_probes*data->nb_datapoints + 2*data->nb_probes) + AES_KEY_RANGE));

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
                k = sbox_oracle(key[i], data->t_plaintexts[j][i]) >> 7;

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

            // Clean up memory
            memset(group[0], 0, sizeof(double)*data->nb_datapoints);
            memset(group[1], 0, sizeof(double)*data->nb_datapoints);

            if ( key[i] == 255 ){
                break;
            }
        }

        // 6. Get the outstanding/maximum value out of the reference curve for that byte
        // This should be our key byte
        k = 0;
        for ( j = 1 ; j < AES_KEY_RANGE ; j++){
            if (ref_curve[j] >= ref_curve[k]){
                k = (uint8_t )j;
            }
        }

        key[i] = k;

        // Clean up memory
        memset(ref_curve, 0, AES_KEY_RANGE*sizeof(double));
    }

    printf("[i] Recovered AES key :\n");
    for (i = 0 ; i < AES_KEY_SIZE ; i++) {
        printf(" %d ", key[i]);
    }
    // Clean up memory and quit
    memset(key, 0, AES_KEY_SIZE);

    printf("g 0 : %p\n", group[1]);
    if (group[1]){
        printf("x\n");
    }
    else{
        printf("not x\n");
    }

    free(group[0]);
    free(group[1]);
}

/**
 * Compute Hamming weight of a byte
 * i.e. number of bits different from zero
 * @param k
 * @return
 */
uint8_t hamming_weight(uint8_t k){
    uint8_t i, h_w = 0;

    for (i = 0 ; i < 8 ; i++){
        h_w += k&1;
        k >>= 1;
    }

    return h_w;
}


/**
 * CPA attack on given dataset
 * @param data
 */
void cpa(container *data) {

    uint8_t i, k = 0, l, max;
    uint32_t j;
    uint8_t key[AES_KEY_SIZE];

    double ref_curve[AES_KEY_RANGE] = {0};

    double *hamming = calloc((size_t)data->nb_probes, sizeof(double));


    /**
     * For every byte of the AES key
     */
    for (i = 0; i < AES_KEY_SIZE; i++) {

        /**
         * For every possible value of the current byte of the AES key
         */
        for (key[i] = 0; key[i] < AES_KEY_RANGE; key[i]++) {

            for (j = 0; j < data->nb_probes; j++) {

                // 1. Discriminator / Oracle
                k = Sbox[key[i] ^ data->t_plaintexts[j][i]];

                // 2. Compute Hamming Weight (i.e. number of bits different from zero in byte k)
                hamming[j] = hamming_weight(k);
            }

            // 3. Build a reference curve with correlation coefficients
            //ref_curve[key[i]] = correlationCoefficient(data->t_traces[?], hamming);


            // 3.b Store all the correlation coefficients of the samples
            ref_curve[ key[i] ] = 0;
            for(j = 0; j < data->nb_datapoints; j++){
                // use the absolute value (-1 and 1 are the values at which the correlation is the strongest)
                //k = fabsf(correlationCoefficient(data->t_traces[a], hamming));
                if (k > ref_curve[ key[i] ]){
                    ref_curve[ key[i] ] = k;
                }
            }
        }

        // 4. Get the outstanding/maximum value out of the reference curve for that byte
        // This should be our key byte
        max = 0;
        for (l = 1; l < AES_KEY_RANGE; l++) {
            if (ref_curve[l] >= ref_curve[max]) {
                max = l;
            }
        }

        key[i] = max;

        // Clean up memory
        memset(ref_curve, 0, AES_KEY_RANGE * sizeof(double));
        memset(hamming, 0, AES_KEY_RANGE * sizeof(double));
    }

    // Clean up memory and quit
    memset(key, 0, AES_KEY_SIZE);
    free(hamming);
}

















