#include <unistd.h>
#include <stdint.h>
#include <math.h>
#include <xpa_attacks.h>
#include <memory.h>
#include <correlation.h>
#include <constants.h>

uint8_t sbox_oracle(uint8_t key_byte, uint8_t plain_byte){
    return Sbox[key_byte ^ plain_byte];
}


void print_percentage(int32_t step, int32_t top){
    printf("%d %%\r", (int)floor(100*(step + 1)/top));
    fflush(stdout);
}

void dpa(container * data){

    uint8_t i, k, key[AES_KEY_SIZE];
    uint32_t j, l;

    double max;
    double ref_curve[AES_KEY_RANGE] = {0};
    double *average = calloc((size_t)data->nb_datapoints, sizeof(double));

    double *group[2];
    int size[2] = {0};

    group[0] = calloc((size_t)data->nb_datapoints, sizeof(double));
    group[1] = calloc((size_t)data->nb_datapoints, sizeof(double));

    /**
     * For every byte of the AES key
     */
    for ( i = 0 ; i < AES_KEY_SIZE ; i++ ){

        /**
         * For every possible value of the current byte of the AES key
         */
        for( key[i] = 0 ; key[i] < AES_KEY_RANGE ; key[i]++){

            /**
             * Go through all the probes, and add up the datapoints
             */
            for( j = 0 ; j < data->nb_probes ; j++){

                // 1. Discriminator / Oracle
                k = sbox_oracle(key[i], data->t_plaintexts[j][i]) >> 7;

                // 2. Add up
                // Add up all the datapoints of the entire trace
                for( l = 0 ; l < data->nb_datapoints ; l++){
                    group[k][l] += data->t_traces[j][l];
                }
                size[k]++;
            }

            // 3. Statistics
            // Compute average for every group and record the difference
            for (j = 0 ; j < data->nb_datapoints ; j++){
                average[j] = fabs( group[0][j]/size[0] - group[1][j]/size[1]);
            }

            // 4. Get the maxium value
            max = average[0];
            for (j = 1 ; j < data->nb_datapoints ; j++){
                if (average[j] > max){
                    max = average[j];
                }
            }

            // 5. Insert it in reference curve
            ref_curve[key[i]] = max;

            // Clean up memory
            memset(group[0], 0, sizeof(double) * data->nb_datapoints);
            memset(group[1], 0, sizeof(double) * data->nb_datapoints);
            size[0] = 0;
            size[1] = 0;

            // Print something for operator to get feedback ( can I haz coffee ? )
            print_percentage(key[i], AES_KEY_RANGE);

            // uint8_t overflows in this loop, so this is trap to quit last round
            if ( key[i] == AES_KEY_RANGE - 1 ){
                break;
            }

        }

        // 6. Get the outstanding/maximum value out of the reference curve for that byte
        // This should be our key byte
        k = 0;
        for ( j = 1 ; j < AES_KEY_RANGE ; j++){
            if (ref_curve[j] >= ref_curve[k]){
                k = (uint8_t)j;
            }
        }

        key[i] = k;

        printf("[i] Key[%d] : 0x%2.2x\n", i, key[i]);

        // Clean up memory
        memset(ref_curve, 0, sizeof(ref_curve));
    }


    printf("[i] Recovered AES key :\n");
    for (i = 0 ; i < AES_KEY_SIZE ; i++) {
        printf(" %2.2x ", key[i]);
    }


    // Clean up memory and quit
    memset(key, 0, AES_KEY_SIZE);

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
void cpa(container *data, FILE *output_file) {

    uint8_t i, k, key[AES_KEY_SIZE];
    uint32_t j, max, line_length = 23, block_length = (AES_KEY_RANGE + 2) * line_length;

    double ref_curve[AES_KEY_RANGE] = {0};

    char *block = calloc((size_t) block_length, sizeof(char));
    char *line_buffer = calloc((size_t) block_length, sizeof(char));
    char point_buffer[16] = {0};
    double *hamming = calloc((size_t) data->nb_probes, sizeof(double));


    /**
     * Transposing the matrix would allow faster memory access
     */
    double **transpose_datapoints = transpose_datapoint_matrix(data);

    /**
     * For every byte of the AES key
     */
    for (i = 0; i < AES_KEY_SIZE; i++) {

        // Keep track of vectors in memory, to avoid disk I/O
        sprintf(line_buffer, "Vectors for key[%d]\n", i);
        strncat(block, line_buffer, strlen(line_buffer) + 1);

        /**
         * For every possible value of the current byte of the AES key
         */
        for (key[i] = 0; key[i] < AES_KEY_RANGE; key[i]++) {

            for (j = 0; j < data->nb_probes; j++) {

                // 1. Discriminator / Oracle
                k = sbox_oracle(key[i], data->t_plaintexts[j][i]);

                // 2. Compute Hamming Weight (i.e. number of bits different from zero in byte k)
                hamming[j] = hamming_weight(k);
            }

            // 3. Build a reference curve with correlation coefficients
            //ref_curve[ key[i] ] = compute_highest_correlation_coefficient(data, transpose_datapoints, hamming);

            double *pearson_vector = compute_pearson_vector(data, transpose_datapoints, hamming);

            // Keep track of vectors in memory, to avoid disk I/O
            sprintf(line_buffer, "%d  :", key[i]);
            for (j = 0; j < data->nb_datapoints; j++) {
                sprintf(point_buffer, " %.10g ", pearson_vector[j]);
                strncat(line_buffer, point_buffer, strlen(point_buffer));
            }
            strncat(line_buffer, "\n", strlen("\n"));
            strncat(block, line_buffer, strlen(line_buffer) + 1);

            ref_curve[key[i]] = get_max_correlation(pearson_vector, data->nb_datapoints);
            free(pearson_vector);

            // Print something for operator to get feedback ( can I haz coffee ? )
            print_percentage(key[i], AES_KEY_RANGE);

            // uint8_t overflows in this loop, so this is trap to quit last round
            if (key[i] == AES_KEY_RANGE - 1) {
                break;
            }
        }

        // 4. Get the outstanding/maximum value out of the reference curve for that byte
        // This should be our key byte
        max = 0;
        for (j = 1; j < AES_KEY_RANGE; j++) {
            if (ref_curve[j] >= ref_curve[max]) {
                max = j;
            }
        }

        key[i] = (uint8_t) max;

        printf("[i] Key[%d] : 0x%2.2x\n", i, key[i]);

        // Keep track of vectors on disk
        if (!fputs(block, output_file) || !fputs("\n\n", output_file)) {
            printf("[ERROR] Writing to file failed for block %d\n", i);
        }

        // Clean up memory
        //memset(ref_curve, 0, sizeof(ref_curve));
        //memset(hamming, 0, (size_t)data->nb_probes * sizeof(double));
        memset(block, 0, (size_t) block_length * sizeof(char));
        memset(line_buffer, 0, (size_t) block_length * sizeof(char));
    }

    printf("[i] Recovered AES key :\n");
    for (i = 0; i < AES_KEY_SIZE; i++) {
        printf(" %2.2x ", key[i]);
    }

    // Clean up memory and quit
    memset(key, 0, AES_KEY_SIZE);
    free(hamming);
}