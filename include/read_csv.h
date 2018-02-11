//
// Created by dan on 11/02/18.
//

#ifndef SCA_2_READ_CSV_H
#define SCA_2_READ_CSV_H

#define MAX_LINE_LENGTH 96*(12+1+1)
#define NB_PLAINTEXT_BYTES 16
#define NB_DATA_POINTS 96
#define NB_CHAR_REPR 3
#define CSV_DELIMITER ','

#define FILENAME "./aes_traces.csv"

typedef struct {
    unsigned char **t_plaintexts;
    float **t_traces;
    int nb_datapoints;
    int nb_probes;
} container;

/**
 * Initialises container data
 * @param lines
 * @param data
 * @return
 */
container* initialise_data_memory(int lines);

/**
 * Frees the memory of input data
 * @param unsigned char **
 * @return void
 */
void free_data_memory(container *data);

/**
 * Given a path to filename, reads the file and returns an appropriate buffer containing its content
 * @param filename
 * @param length
 * @return
 */
container* read_data_from_source (const char *filename);

/**
 * Checks if file is a regular and tries to open a stream on it.
 * @param filename
 */
FILE* check_and_open_file(const char *filename);

#endif /*SCA_2_READ_CSV_H*/
