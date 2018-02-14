#ifndef SCA_2_READ_CSV_H
#define SCA_2_READ_CSV_H

#define MAX_LINE_LENGTH 2000000 //(1992*(12+1+1))
#define NB_PLAINTEXT_BYTES 16
#define NB_DATA_POINTS 2200
#define CSV_DELIMITER ','

typedef struct {
    uint8_t **t_plaintexts;
    double **t_traces;
    uint32_t nb_datapoints;
    uint32_t nb_probes;
} container;

void print_traces(container *data);


/**
 * Initialises container data
 * @param lines
 * @param data
 * @return
 */
container* initialise_data_memory(uint32_t lines, uint32_t datapoints);

/**
 * Frees the memory of input data
 * @param unsigned char **
 * @return void
 */
void free_data_memory(container *data);

/**
 * Given a path to filename, reads the file and returns an appropriate buffer containing its content
 * @param file
 * @return
 */
container* read_data_from_source (FILE *file);

/**
 * Checks if file is a regular and tries to open a stream on it.
 * @param filename
 */
FILE* check_and_open_file(const char *filename);

#endif /*SCA_2_READ_CSV_H*/
