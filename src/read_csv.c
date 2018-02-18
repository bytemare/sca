#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <memory.h>
#include <read_csv.h>
#include <constants.h>


/**
 * Initialises container data
 * @param lines
 * @param data
 * @return
 */
container* initialise_data_memory(uint32_t lines, uint32_t datapoints){

    container *data = malloc(sizeof(container*));

    if (data == NULL ){
        perror("[ERROR] Could not allocate data structure.");
        return NULL;
    }

    uint nb_probes = lines / 2;
    data->nb_probes = nb_probes;
    data->nb_datapoints = datapoints;

    data->t_plaintexts = malloc( nb_probes * sizeof(uint8_t *));
    if (data->t_plaintexts == NULL){
        perror("[ERROR] Could not allocate memory for data->t_plaintexts");
        free(data);
        return NULL;
    }

    data->t_traces = malloc( nb_probes * sizeof(double *));
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
        if(data->t_plaintexts[i]) {
            free(data->t_plaintexts[i]);
        }
    }
    free(data->t_plaintexts);

    for( i = 0 ; i < data->nb_probes ; ++i){
        if (data->t_traces[i]){
            free(data->t_traces[i]);
        }
    }
    free(data->t_traces);

    free(data);
}

/**
 * Debug Function to print read data
 * @param data
 */
void print_traces(container *data){
    int i, j;

    printf("traces : %d\n", data->nb_probes);
    for( i = 0 ; i < data->nb_probes ; ++i){
        for ( j = 0 ; j < data->nb_probes; j++){
            printf("%d ", data->t_plaintexts[i][j]);
        }
        printf("\n");
    }
    printf("\n");

    printf("points : %d\n", data->nb_datapoints);
    for( i = 0 ; i < data->nb_probes ; ++i){
        for ( j = 0 ; j < data->nb_datapoints; j++){
            printf("[%d][%d] : %.10g,  ", i, j, data->t_traces[i][j]);
        }
        printf("\n");
    }
    printf("\n");

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
uint32_t count_lines(FILE *file){
    uint32_t lines = 0;
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
 * Counts the number of
 * @param line
 * @return
 */
uint32_t count_datapoints(FILE *file, const unsigned char *delimiter){

    uint32_t i = 0;
    char *s, *buffer = NULL;

    size_t len;

    for ( i = 0 ; i < 2 ; i++){
        if ( getline(&buffer, &len, file) == -1){
            perror("[ERROR] in reading line.");
            buffer ? free(buffer): NULL;
            return 0;
        }
    }

    s = strchr(buffer,*delimiter);
    while (s!=NULL)
    {
        i++;
        s = strchr( s + 1, *delimiter);
    }
    i++;

    rewind(file);
    free(buffer);

    return i;
}

/**
 * Read a line in file supposedly corresponding to a plaintext line, parses and stores it
 * @param buffer
 * @param file
 * @param data
 * @param delimiter
 */
int read_plaintext_line(int i, FILE *file, container *data){

    int j;
    uint16_t p;
    char *token;
    //char buffer[MAX_LINE_LENGTH];
    char *buffer = NULL;

    size_t len;

    if ( getline(&buffer, &len, file) == -1){
        perror("[ERROR] in reading line.");
        buffer ? free(buffer): NULL;
        return -2;
    }



    // check for error here

    /* Get the line */
    /*if ( get_line(buffer, file) < 0 ){
        return -1;
    }*/

    data->t_plaintexts[i] = calloc((size_t)NB_PLAINTEXT_BYTES, sizeof(uint8_t));
    if (data->t_plaintexts[i] == NULL){
        perror("[ERROR] Could not allocate memory for t_plaintexts[i].");
        free(buffer);
        return -2;
    }

    p = (uint16_t) strtol(buffer, &token, 10);
    for ( j = 0 ; j < NB_PLAINTEXT_BYTES && p != 0 ; j++){

        if ( p > 255 ){
            printf("[ERROR] Invalid value for plaintext entry on line %d : '%d'\n", i, p);
            free(buffer);
            return -2;
        }

        data->t_plaintexts[i][j] = (uint8_t) p;
        //printf("[%d][%d] : %d\n", i, j, data->t_plaintexts[i][j]);

        p = (uint16_t) strtol(token+1, &token, 10);
    }

    free(buffer);
}

/**
 * Read a line in file supposedly corresponding to a datapoint line, parses it and converts it to float before storing
 * @param buffer
 * @param file
 * @param data
 * @param delimiter
 */
int read_datapoints_line(int i, FILE *file, container *data, const unsigned char *delimiter){

    int j;
    char *token;
    //char buffer[MAX_LINE_LENGTH];

    char *buffer = NULL;

    size_t len;

    if ( getline(&buffer, &len, file) == -1){
        perror("[ERROR] in reading line.");
        buffer ? free(buffer): NULL;
        return -2;
    }

    /* Get the line */
    //if ( get_line(buffer, file) < 0){
    //    return -1;
    //}

    data->t_traces[i] = calloc(data->nb_datapoints, sizeof(double));

    /* get the first token */
    token = strtok(buffer, (const char*)delimiter);
    //printf("%s \n", token);

    /* walk through other tokens */
    j = 0;
    while( token != NULL ) {

        if (strlen(token) == 1){
            /* Read next token */
            token = strtok(NULL, (const char*)delimiter);
            continue;
        }

        if (j >= data->nb_datapoints) {
            printf("[ERROR] : overflowed data points. Probe %d has too many datapoints (should be %d).\n", i, data->nb_datapoints);
            buffer ? free(buffer): NULL;
            return -2;
        }

        /* Convert token to string */
        data->t_traces[i][j++] = (double)strtof(token, NULL);

        /* Read next token */
        token = strtok(NULL, (const char*)delimiter);
        //printf("%s \n", token);
    }

    buffer ? free(buffer): NULL;
}




/**
 * Given a path to filename, reads the file and returns an appropriate buffer containing its content
 * @param file
 * @return
 */
container* read_data_from_source (FILE *file){

    int i, ret;
    uint32_t lines, datapoints;
    container *data = NULL;
    const unsigned char delimiter = CSV_DELIMITER;

    /**
     * Count the number of lines and datapoints
     */
    lines = count_lines(file);

    if ( lines % 2 != 0 ){
        printf("[ERROR] Uneven number of lines ! Found : %d.\n", lines);
        free_data_memory(data);
        fclose(file);
        return NULL;
    }

    printf("[i] Found %d traces.\n", lines/2);

    datapoints = count_datapoints(file, &delimiter);
    if( datapoints == 0 ){
        printf("[ERROR] Could not get number of datapoints.\n");
        free_data_memory(data);
        fclose(file);
        return NULL;
    }

    printf("[i] Found %d datapoints.\n", datapoints);

    /**
     * Allocate memory for our data structures
     */
    data = initialise_data_memory(lines, datapoints);
    if ( data == NULL ){
        fclose(file);
        return NULL;
    }

    /**
     * Go through file, read and parse lines, and fill data container
     */
    //int j, k;
    for(i = 0 ; i < data->nb_probes ; i++ ){

        /*
         * Read plaintext and datapoints lines
         */
        ret = read_plaintext_line(i, file, data);
        /*for( k = 0 ; k < i ; ++k){
            for ( j = 0 ; j < data->nb_probes; j++){
                printf("%d ", data->t_plaintexts[k][j]);
            }
            printf("\n");
        }
        printf("\n");*/

        switch (ret){
            case -1:
                continue;

            case -2:
                free_data_memory(data);
                fclose(file);
                return NULL;

            default:;
        }

        ret = read_datapoints_line(i, file, data, &delimiter);
        /*for( k = 0 ; k <= i ; ++k){
            for ( j = 0 ; j < data->nb_datapoints; j++){
                printf("%.10g ", data->t_traces[k][j]);
            }
            printf("\n");
        }
        printf("\n");*/

        switch (ret){
            case -1:
                continue;

            case -2:
                free_data_memory(data);
                fclose(file);
                return NULL;
            default:;
        }

    }

    fclose(file);

    return data;
}