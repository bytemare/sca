#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>

#define NB_POINTS 1500
#define NB_TRACES 1000
#define NB_TRACES_CPA 1000 //990 avec aes_traces.csv et 1000 avec trace_dpa.csv

char t_plaintexts[NB_TRACES][32];
float t_traces[NB_TRACES][NB_POINTS];
float courbe_moyenne_z[256][NB_POINTS];
float courbe_moyenne_o[256][NB_POINTS];
float courbe_amplitude[256][NB_POINTS];

// Récupération des traces 
void getTraces(int nbtraces){
    printf("%d traces de %d Points",nbtraces, NB_POINTS);
    FILE *f;
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    
    if((f = fopen("aes_traces.csv","r")) == NULL){
        fprintf(stderr,"Impossible d'ouvrir le fichier\n");
        exit(1);
    }
    int i = 0;
    i = 1; 
    while((read = getline(&line,&len,f)) != -1 && i <= nbtraces * 2){
        if(i % 2 == 0){
            char *token;
            int h = 0;
            while((token = strsep(&line,","))){
                t_traces[i/2-1][h] = atof(token);
                h++;
            }   
        }
        else{           
            strcpy(t_plaintexts[(i-1)/2], line);
        }
        i++;
    }
}

// Retourne la valeur de sortie de la 1ère Sbox 
int Sbox(int key, int p){ 
    const char s[256][5] =
    {
    "0x63", "0x7C", "0x77", "0x7B", "0xF2", "0x6B", "0x6F", "0xC5", "0x30", "0x01", "0x67", "0x2B", "0xFE", "0xD7", "0xAB", "0x76",
    "0xCA", "0x82", "0xC9", "0x7D", "0xFA", "0x59", "0x47", "0xF0", "0xAD", "0xD4", "0xA2", "0xAF", "0x9C", "0xA4", "0x72", "0xC0",
    "0xB7", "0xFD", "0x93", "0x26", "0x36", "0x3F", "0xF7", "0xCC", "0x34", "0xA5", "0xE5", "0xF1", "0x71", "0xD8", "0x31", "0x15",
    "0x04", "0xC7", "0x23", "0xC3", "0x18", "0x96", "0x05", "0x9A", "0x07", "0x12", "0x80", "0xE2", "0xEB", "0x27", "0xB2", "0x75",
    "0x09", "0x83", "0x2C", "0x1A", "0x1B", "0x6E", "0x5A", "0xA0", "0x52", "0x3B", "0xD6", "0xB3", "0x29", "0xE3", "0x2F", "0x84",
    "0x53", "0xD1", "0x00", "0xED", "0x20", "0xFC", "0xB1", "0x5B", "0x6A", "0xCB", "0xBE", "0x39", "0x4A", "0x4C", "0x58", "0xCF",
    "0xD0", "0xEF", "0xAA", "0xFB", "0x43", "0x4D", "0x33", "0x85", "0x45", "0xF9", "0x02", "0x7F", "0x50", "0x3C", "0x9F", "0xA8",
    "0x51", "0xA3", "0x40", "0x8F", "0x92", "0x9D", "0x38", "0xF5", "0xBC", "0xB6", "0xDA", "0x21", "0x10", "0xFF", "0xF3", "0xD2",
    "0xCD", "0x0C", "0x13", "0xEC", "0x5F", "0x97", "0x44", "0x17", "0xC4", "0xA7", "0x7E", "0x3D", "0x64", "0x5D", "0x19", "0x73",
    "0x60", "0x81", "0x4F", "0xDC", "0x22", "0x2A", "0x90", "0x88", "0x46", "0xEE", "0xB8", "0x14", "0xDE", "0x5E", "0x0B", "0xDB",
    "0xE0", "0x32", "0x3A", "0x0A", "0x49", "0x06", "0x24", "0x5C", "0xC2", "0xD3", "0xAC", "0x62", "0x91", "0x95", "0xE4", "0x79",
    "0xE7", "0xC8", "0x37", "0x6D", "0x8D", "0xD5", "0x4E", "0xA9", "0x6C", "0x56", "0xF4", "0xEA", "0x65", "0x7A", "0xAE", "0x08",
    "0xBA", "0x78", "0x25", "0x2E", "0x1C", "0xA6", "0xB4", "0xC6", "0xE8", "0xDD", "0x74", "0x1F", "0x4B", "0xBD", "0x8B", "0x8A",
    "0x70", "0x3E", "0xB5", "0x66", "0x48", "0x03", "0xF6", "0x0E", "0x61", "0x35", "0x57", "0xB9", "0x86", "0xC1", "0x1D", "0x9E",
    "0xE1", "0xF8", "0x98", "0x11", "0x69", "0xD9", "0x8E", "0x94", "0x9B", "0x1E", "0x87", "0xE9", "0xCE", "0x55", "0x28", "0xDF",
    "0x8C", "0xA1", "0x89", "0x0D", "0xBF", "0xE6", "0x42", "0x68", "0x41", "0x99", "0x2D", "0x0F", "0xB0", "0x54", "0xBB", "0x16"
    };
    return (int)strtol(s[key^p],NULL,16); // convertit de string vers int
}

void DPA(){
    printf("Récupération des Traces ... ");
    getTraces(NB_TRACES);
    printf(" -> OK\n\n");
    int i, j, k,l,m;
    int ones[NB_TRACES], zeros[NB_TRACES];
    int z = 0, o = 0;
    int key[16];
    float max = 0;
    printf("*************Attaque DPA*************\n\n");
    printf("Clé : ");
    // Pour chaque octet de la clé
    for(i = 0;i < 32;i += 2){
        max = 0;
        // Pour chaque valeur possible d'un octet
        for(j = 0;j < 256;j++){
            z = 0, o = 0;
            // Répartition des traces selon le 1er bit de sortie de la Sbox
            for(k = 0;k < NB_TRACES;k++){
                char octetPlainTxt[3];
                octetPlainTxt[0] = t_plaintexts[k][i];
                octetPlainTxt[1] = t_plaintexts[k][i+1];
                octetPlainTxt[2] = '\0';
                int bit = Sbox(j, (int)strtol(octetPlainTxt, NULL, 16)) & 1;
                if(bit == 0){
                   zeros[z] = k;
                    z++;
                }
                else{
                    ones[o] = k;
                    o++;
                }
            }
            
            // Calcul des courbes moyenne
            for(l = 0;l < NB_POINTS;l++){
                for(m = 0;m < z;m++){
                    courbe_moyenne_z[j][l] += t_traces[zeros[m]][l];
                    if(m == z-1){
                        courbe_moyenne_z[j][l] /= z;
                    }
                }
                for(m = 0;m < o;m++){
                    courbe_moyenne_o[j][l] += t_traces[ones[m]][l];
                    if(m == o-1){
                        courbe_moyenne_o[j][l] /= o;
                    }
                } 
            }
            // Calcul de l'amplitude
            for(l = 0;l < NB_POINTS;l++){
                // fabsf compute abolute value of a float
                courbe_amplitude[j][l] = fabsf(fabsf(courbe_moyenne_z[j][l]) - fabsf(courbe_moyenne_o[j][l]));
                courbe_moyenne_z[j][l] = 0;
                courbe_moyenne_o[j][l] = 0;
                // Recherche de l'amplitude maximale
                if(courbe_amplitude[j][l] > max){
                    max = courbe_amplitude[j][l];
                    key[i/2] = j;
                }
            }
        }
        printf(" %02X ",key[i/2]);   
    }
    printf("\n\n");
}

static unsigned int HW(int binary){
    // gets the hamming weight of a byte
    unsigned int count = 0;
    while (binary){
        ++count;
        binary &= (binary - 1);
    }
    return count;
}

void CPA(){
    printf("Récupération des Traces ... ");
    getTraces(NB_TRACES_CPA);
    printf(" -> OK\n\n");
    int i, j, k,l,m;
    int hw[256],hwTraces[NB_TRACES];
    int key[16];
    float max = 0;
    float courbe_moyenne[NB_POINTS];
    printf("*************Attaque CPA*************\n\n");
    printf("Clé : ");
    // Poids de hamming d'un octet
    for(i = 0;i < 256;i++){
        hw[i] = HW(i);
    }
    // Courbe moyenne des traces
    for(i = 0;i < NB_TRACES;i++){
        for(j = 0;j < NB_POINTS;j++){
            courbe_moyenne[j] += t_traces[i][j];
            if(i == NB_TRACES - 1){
                courbe_moyenne[j] /= NB_TRACES;
            }
        }
    }
    // Pour chaque octet de la clé  
    for(i = 0;i < 32;i += 2){
        max = 0;
        int index = 0;
        float coeffCorr[256] = {0};
        // Pour chaque valeur possible d'un octet
        for(j = 0;j < 256;j++){
            // Poids de Hamming de sortie de la Sbox pour chaque trace
            for(k = 0;k < NB_TRACES;k++){
                
                char octetPlainTxt[3];
                octetPlainTxt[0] = t_plaintexts[k][i];
                octetPlainTxt[1] = t_plaintexts[k][i+1];
                octetPlainTxt[2] = '\0';
                hwTraces[k] = hw[(Sbox(j, (int)strtol(octetPlainTxt, NULL, 16)))];
            }
            
            // Poids de hamming moyen
            float hwMoy = 0;
            for(l = 0;l < NB_TRACES;l++){
                hwMoy += hwTraces[l];  
            }
            hwMoy /= NB_TRACES;
            
            // Calcul du coeff de correlation
            float hwdiff = 0,XY[NB_POINTS] = {0},XX = 0,YY[NB_POINTS] = {0};
            float coeffTmp = 0;           
            for(l = 0;l < NB_TRACES;l++){
                float tracediff[NB_POINTS]={0}; 
                hwdiff = hwTraces[l] - hwMoy;
                for(m = 0; m < NB_POINTS; m++){
                    tracediff[m] = t_traces[l][m] - courbe_moyenne[m];
                }
                XX += hwdiff*hwdiff;
                for(m = 0; m < NB_POINTS; m++){
                   XY[m] += hwdiff * tracediff[m];
                   YY[m] += tracediff[m] * tracediff[m];
                }
            }
            // Coeff max sur tous les points
            for(l = 0;l < NB_POINTS;l++){
                if((coeffTmp = fabsf(XY[l] / sqrt(XX * YY[l]))) > coeffCorr[j]){
                    coeffCorr[j] = coeffTmp;
                }
            }
            // Coeff max final pour un octet de la clé
            if(coeffCorr[j] > max){
                
                max = coeffCorr[j];
                index = j;
            }
        }
        key[i/2] = index;
        printf(" %02X ",key[i/2]);   
    }
    printf("\n\n");
}

int main(){
    clock_t start,end;
    start = clock();
    DPA();
    end = clock();
    printf("Exec Time = %.2f s\n",(double)(end - start) / CLOCKS_PER_SEC);
    start = clock();
    CPA();
    end = clock();
    printf("Exec Time = %.2f s\n\n",(double)(end - start) / CLOCKS_PER_SEC);
    return 0;
}

