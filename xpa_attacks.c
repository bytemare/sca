#define AES_KEY_SIZE 16
#define AES_KEY_RANGE 256

#include <stdint.h>
#include <xpa_attacks.h>


void dpa(container *data){

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

/**
 * Compute Hamming weight of a byte
 * i.e. number of bits different from zero
 * @param k
 * @return
 */
uint8_t hamming_weight(uint8_t k){
    uint8_t i = h_w = 0;

    for (; i < 8 ; i++){
        h_w += k&1;
        k >>= 1;
    }

    return h_w;
}

void cpa(container *data) {

    uint8_t i, j, k;
    uint8_t key[AES_KEY_SIZE];

    double hamming[AES_KEY_RANGE] = {0};
    double ref_curve[AES_KEY_RANGE] = {0};


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
            ref_curve[key[i]] = correlationCoefficient(data->t_traces[?], hamming);
        }

        k = 0;
        for (j = 1; j < AES_KEY_RANGE; j++) {
            if (ref_curve[j] >= ref_curve[k]) {
                k = j;
            }
        }

        key[i] = k;

        // Clean up memory
        memset(ref_curve, 0, AES_KEY_RANGE * sizeof(double));
        memset(hamming, 0, AES_KEY_RANGE * sizeof(double));
    }

    // Clean up memory and quit
    memset(key, 0, AES_KEY_SIZE);
}