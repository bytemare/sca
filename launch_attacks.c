#include <xpa_attacks.h>


int main(int argc, char *argv[]){


    /**
     * Verify file before handling
     */
    printf("[i] Checking file...\n");
    FILE* file = check_and_open_file(argv[1]);
    if (file == NULL){
        exit(1);
    }

    printf("File %s checked and opened.\n", argv[1]);

    /**
     * Load Traces ...
     */
    printf("[i] Loading Traces ...\n");
    container *data = read_data_from_source(argv[1]);

    printf("[i] Completed.\n\n");

    /**
     * Launch DPA attack
     */
    dpa_2(data);


    /**
     * Job is done.
     */
    free_data_memory(data);
    exit(0);
}