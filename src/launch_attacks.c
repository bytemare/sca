#include <xpa_attacks.h>
#include <read_csv.h>
#include <time.h>


int main(int argc, char *argv[]){

    if(argc<2){
        printf("[ERROR] Usage : %s [trces.csv]\n\n", argv[0]);
        exit(0);
    }

    clock_t start,end;

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
    start = clock();
    dpa(data);
    end = clock();
    printf("\n[i] DPA completed (%.2f sec.)\n\n", (double)(end - start) / CLOCKS_PER_SEC);

    /**
     * Launch CPA attack
     */
    printf("[i] Launching CPA on dataset...\n");
    start = clock();
    cpa(data);
    end = clock();
    printf("\n[i] CPA completed (%.2f sec.)\n\n", (double)(end - start) / CLOCKS_PER_SEC);

    /**
     * Job is done.
     */
    free_data_memory(data);
    exit(0);
}