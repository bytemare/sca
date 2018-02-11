#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <memory.h>

#include <read_csv.h>

#define MAX_LINE_LENGTH 96*(12+1+1)
#define NB_PLAINTEXT_BYTES 16
#define NB_DATA_POINTS 96
#define NB_CHAR_REPR 3

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
container* initialise_data_memory(int lines){

    container *data = malloc(sizeof(container));

    if (data == NULL ){
        perror("[ERROR] Could not allocate data structure.");
        return NULL;
    }

    uint8_t nb_probes = lines / 2;
    data->nb_probes = nb_probes;

    data->t_plaintexts = calloc((size_t) nb_probes, sizeof(char *));
    if (data->t_plaintexts == NULL){
        perror("[ERROR] Could not allocate memory for data->t_plaintexts");
        free(data);
        return NULL;
    }

    data->t_traces = calloc((size_t) nb_probes, sizeof(float *));
    if (data->t_traces == NULL){
        perror("[ERROR] Could not allocate memory for data->t_plaintexts");
        free(data->t_plaintexts);
        free(data);
        return NULL;
    }

    return data;
}


/**
 * Frees the memory of input data
 * @param unsigned char **
 * @return void
 */
void free_data_memory(container *data){
    int i;

    for( i = 0 ; i < data->nb_probes ; ++i){
        free(data->t_plaintexts[i]);
    }
    free(data->t_plaintexts);

    for( i = 0 ; i < data->nb_probes ; ++i){
        free(data->t_traces[i]);
    }
    free(data->t_traces);

    free(data);
}

/**
 * Checks if file is a regular and tries to open a stream on it.
 * @param filename
 */
FILE* check_and_open_file(const char *filename){
    FILE* file;
    struct stat file_info;
    int fd;

    fd = open(filename, O_RDONLY);

    if ( fd == -1 ){
        perror("[ERROR] Could not open file.");
        return NULL;
    }

    fstat(fd, &file_info);

    if (!S_ISREG(file_info.st_mode)) {
        perror("[ERROR] File is not a regular file !");
        close(fd);
        return NULL;
    }

    file = fdopen(fd, "r");

    if(file == NULL){
        perror("[ERROR] Could not open file stream.");
        close(fd);
        return NULL;
    }

    return file;
}


/**
 * Count the number of lines in file
 * @param buffer
 * @param file
 * @return
 */
int count_lines(FILE *file){
    int lines = 0;
    char buffer[MAX_LINE_LENGTH];
    while (fgets(buffer, sizeof(buffer), file)) {
        if( strlen(buffer) == 1)
            continue;
        lines++;
    }
    rewind(file); /* Reset the pointer to beginning of file */

    return lines;
}

/**
 * Reads a line from file and inserts it into buffer.
 * Buffer must be freed after final use
 * @param buffer
 * @param file
 */
int get_line(char *buffer, FILE *file){

    size_t line_length;

    /* Get the line */
    fgets(buffer, MAX_LINE_LENGTH, file);
    if( strlen(buffer) == 1)
        return -1;

    line_length = strlen(buffer);

    if (line_length >= MAX_LINE_LENGTH){
        printf("Potential overflow of line length. Please increase MAX_LINE_LENGTH.\n");
    }
    buffer[MAX_LINE_LENGTH-1] = '\0';

    return 0;
}

/**
 * Read a line in file supposedly corresponding to a plaintext line, parses and stores it
 * @param buffer
 * @param file
 * @param data
 * @param delimiter
 */
int read_plaintext_line(int i, FILE *file, unsigned char **t_plaintexts, unsigned char delimiter){

    char *token;
    char buffer[MAX_LINE_LENGTH];
    unsigned char tmp[NB_CHAR_REPR];

    /* Get the line */
    if ( get_line(buffer, file) < 0 ){
        return -1;
    }

    t_plaintexts[i] = (unsigned char *)calloc(strlen(buffer), sizeof(char));
    if (t_plaintexts[i] == NULL){
        perror("Could not allocate memory for t_plaintexts[i].");
        return -2;
    }

    strncat((char *) t_plaintexts[i], buffer, strlen(buffer)-1);

    /* get the first token */
    //token = strtok(buffer, &delimiter);

    /* walk through other tokens in the rest of the line */
    /*while( token != NULL ) {

        printf("token : '%s'\n", token);

        snprintf((char *) tmp, NB_CHAR_REPR, "%x", atoi(token));

        printf("tmp : '%s'\n", tmp);

        strncat((char *) t_plaintexts[i], (const char *) tmp, NB_CHAR_REPR);

        if(i == -1){
            printf("here\n");
            printf("t %s\n", tmp);
            printf("s %s\n", token);
            printf("f %s\n", t_plaintexts[i]);
        }

        token = strtok(NULL, &delimiter);
    }*/
}

/**
 * Read a line in file supposedly corresponding to a datapoint line, parses it and converts it to float before storing
 * @param buffer
 * @param file
 * @param data
 * @param delimiter
 */
int read_datapoints_line(int i, FILE *file, float **t_traces, unsigned char delimiter){

    int j;
    char *token;
    char buffer[MAX_LINE_LENGTH];

    /* Get the line */
    if ( get_line(buffer, file) < 0){
        return -1;
    }

    t_traces[i] = calloc(NB_DATA_POINTS, sizeof(float));

    /* get the first token */
    token = strtok(buffer, &delimiter);

    /* walk through other tokens */
    j = 0;
    while( token != NULL ) {

        if (strlen(token) == 1){
            /* Read next token */
            token = strtok(NULL, &delimiter);
            continue;
        }

        if (j >= NB_DATA_POINTS) {
            printf("Error : overflowed data points parsing on line %d.\n", i);
            break;
        }

        /* Convert token to string */
        t_traces[i][j++] = strtof(token, NULL);

        /* Read next token */
        token = strtok(NULL, &delimiter);
    }
}




/**
 * Given a path to filename, reads the file and returns an appropriate buffer containing its content
 * @param filename
 * @param length
 * @return
 */
container* read_data_from_source (FILE *file){

    int i, ret;
    int lines;
    container *data;
    unsigned char delimiter = CSV_DELIMITER;

    /**
     * Count the number of lines
     */
    lines = count_lines(file);

    if ( lines % 2 != 0 ){
        printf("Error : uneven number of lines ! Found : %d.\n", lines);
        fclose(file);
        return NULL;
    }

    printf("[i] Found %d entries.\n", lines);

    /**
     * Allocate memory for our data structures
     */
    data = initialise_data_memory(lines);
    if ( data == NULL ){
        fclose(file);
        return NULL;
    }

    // printf("Initialised memory buffers.\n");

    /**
     * Go through file, read and parse lines, and fill data container
     */

    for(i = 0 ; i < data->nb_probes ; ++i ){

        /*
         * Read plaintext and datapoints lines
         */
        ret = read_plaintext_line(i, file, data->t_plaintexts, delimiter);

        switch (ret){
            case -1:
                continue;

            case -2:
                free_data_memory(data);
                fclose(file);
                return NULL;
        }

        ret = read_datapoints_line(i, file, data->t_traces, delimiter);

        switch (ret){
            case -1:
                continue;

            case -2:
                free_data_memory(data);
                fclose(file);
                return NULL;
        }

    }

    printf("[i] Read file and loaded data.\n");

    // printf("Line 2 :\n- '%s'\n- '%.20f'\n", data->t_plaintexts[2], data->t_traces[2][1]);

    fclose(file);

    return data;
}