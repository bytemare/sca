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
    }

    printf("Recovered AES key :\n[ ");
    for (i = 0 ; i < AES_KEY_SIZE ; i++){
        print(" %d ", key[i]);
    }
    printf("]\n");
}