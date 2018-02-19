#include <xpa_attacks.h>
#include <read_csv.h>
#include <fcntl.h>
#include <time.h>


int main(int argc, char *argv[]){

    if(argc<2){
        printf("[ERROR] Usage : %s [trces.csv]\n\n", argv[0]);
        exit(0);
    }

    printf("[i] If it is not already the case, consider compiling with gcc option -O2,"
                   "which will drastically shorten execution time.\n");

    clock_t start,end;

    /**
     * Verify file before handling
     */
    printf("[i] Checking files...\n");
    FILE* file = check_and_open_file(argv[1], O_RDONLY);
    if (file == NULL){
        exit(1);
    }

    printf("[i] File %s checked and opened for reading.\n", argv[1]);

    FILE* ouput_file = check_and_open_file(argv[2], O_WRONLY);
    if (ouput_file == NULL){
        fclose(file);
        exit(1);
    }

    printf("[i] File %s checked and opened for writing.\n", argv[2]);

    /**
     * Load Traces ...
     */
    printf("[i] Loading Traces ...\n");
    container *data = read_data_from_source(file);
    if( data == NULL){
        printf("[ERROR] Could not load traces. Aborting.\n");
        exit(1);
    }
    fclose(file);
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
    cpa(data, ouput_file);
    fclose(ouput_file);
    end = clock();
    printf("\n[i] CPA completed (%.2f sec.)\n\n", (double)(end - start) / CLOCKS_PER_SEC);

    /**
     * Job is done.
     */
    free_data_memory(data);
    exit(0);
}