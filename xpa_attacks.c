//
// Created by dan on 10/02/18.
//

#define AES_KEY_SIZE 16
#define AES_KEY_RANGE 256

#include <stdint.h>


void dpa_1(container *data){

    uint8_t i, j;
    uint8_t key[AES_KEY_SIZE];

    /**
     * On parcourt l'ensemble des datapoints de toutes les traces
     */
    for (i = 0 ; i < data->nb_datapoints ; i++){

        /**
         * Pour un datapoint, on prend la même position dans chaque trace
         */
        for ( j = 0 ; j < data->nb_probes ; j++){

            /**
             * On essaie de deviner sa valeur par un oracle
             */
            prediction = oracle(data->traces[j][i]);



        }









    }











}

void dpa_2(container *data){

    uint8_t i, j;
    uint8_t key[AES_KEY_SIZE];

    for (i = 0 ; i < AES_KEY_SIZE ; i++){

        /**
         * On effectue des essais sur l'ensemble des possibilités de valeurs
         * sur l'octet
         */
        for (key[i] = 0 ; key[i] < AES_KEY_RANGE ; key[i]++){



            /**
             * On parcourt l'ensemble des mesures
             */
            for (j = 0 ; j < data->nb_probes ; j++){

                // 1 : Selection du bit
                // Bit de poids fort de la première sbox
                // (i.e. Sbox [ key[i] ^ plaintext[i]

                // 2
                // Pour l'ensemble des

                // 3



            }



        }




    }






}