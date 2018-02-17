#ifndef SCA_2_READ_CSV_H
#define SCA_2_READ_CSV_H

#include <constants.h>

void print_traces(container *data);

/**
 * Checks if file is a regular and tries to open a stream on it.
 * @param filename
 */
FILE* check_and_open_file(const char *filename);

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
