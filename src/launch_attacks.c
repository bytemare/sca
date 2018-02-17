#include <xpa_attacks.h>
#include <read_csv.h>
#include <xpa_new.h>


int main(int argc, char *argv[]){

    if(argc<2){
        printf("[ERROR] Usage : %s [trces.csv]\n\n", argv[0]);
        exit(0);
    }


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
    container *data = read_data_from_source(file);
    if( data == NULL){
        printf("[ERROR] Could not load traces. Aborting.\n");
        exit(1);
    }
    printf("[i] Loading completed.\n\n");

    /**
     * Launch DPA attack
     */
    printf("[i] Launching DPA on dataset...\n");
    dpa(data);
    printf("\n[i] DPA completed.\n\n");

    /**
     * Launch CPA attack
     */
    printf("[i] Launching CPA on dataset...\n");
    cpa(data);
    printf("\n[i] CPA completed.\n\n");






    free_data_memory(data);

    printf("[i] Testing factorised code ...\n");

    /**
     * Verify file before handling
     */
    printf("[i] Checking file...\n");
    file = check_and_open_file(argv[1]);
    if (file == NULL){
        exit(1);
    }

    printf("File %s checked and opened.\n", argv[1]);

    /**
     * Load Traces ...
     */
    printf("[i] Loading Traces ...\n");
    data = read_data_from_source(file);
    if( data == NULL){
        printf("[ERROR] Could not load traces. Aborting.\n");
        exit(1);
    }
    printf("[i] Loading completed.\n\n");


    /**
     * Launch DPA attack
     */
    printf("[i] Launching DPA on dataset...\n");
    xpa(data, "dpa");
    printf("\n[i] DPA completed.\n\n");

    /**
     * Launch CPA attack
     */
    printf("[i] Launching CPA on dataset...\n");
    xpa(data, "cpa");
    printf("\n[i] CPA completed.\n\n");


    /**
     * Job is done.
     */
    free_data_memory(data);
    exit(0);
}