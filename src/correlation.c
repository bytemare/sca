#include <stdint.h>
#include <constants.h>
#include <math.h>
#include <stdlib.h>


/**
 * Real Kitchen of computation
 * Computes the pearson's correlation coefficient for the given set (one can see the vectors as curves)
 * @param datapoints
 * @param Y
 * @param nb_probes
 * @return
 */
double correlationCoefficient(double *datapoints, double *Y, uint32_t nb_probes){

    uint32_t i;
    double EX = 0, EY = 0; // Mean
    double EXY = 0; // Sum of product of vectors
    double EXX = 0, EYY = 0; // Sum of squares of vectors

    // Pile up for given trace/measure for all probes
    for ( i = 0 ; i < nb_probes ; i++){
        EXY += datapoints[i] * Y[i];
        EX += datapoints[i];
        EY += Y[i];
        EXX += pow(datapoints[i], 2);
        EYY += pow(Y[i], 2);
    }

    EXY *= nb_probes;
    EXX *= nb_probes;
    EYY *= nb_probes;

    // Finally compute the correlation coefficient
    double coefficient = fabs(EXY - EX*EY) /
            ( ( pow(EX, 2) - EXX) * ( pow(EY, 2) - EYY) );

    return coefficient;
}


/**
 * Computes the vector of pearson's correlation coefficients for the given datapoints and the hamming weight vector
 * @param data
 * @param datapoints
 * @param hamming
 * @return
 */
double* compute_pearson_vector(container *data, double **datapoints, double *hamming){

    uint32_t i;
    double *pearson_vector = calloc( data->nb_datapoints, sizeof(double));

    /*
     * Populate vector/array of pearson correlation values
     */
    for ( i = 0 ;  i < data->nb_datapoints ; i++ ){
        pearson_vector[i] = correlationCoefficient(datapoints[i], hamming, data->nb_probes);
    }

    return pearson_vector;
}

/**
 * From a set of pearson coefficients, gets the highest
 * @param pearson_vector
 * @param size
 * @return
 */
double get_max_correlation(double *pearson_vector, uint32_t size){

    uint32_t i;
    double max = pearson_vector[0];

    for ( i = 0 ; i < size ; i++){
        if( fabs(pearson_vector[i]) > max){
            max = fabs(pearson_vector[i]);
        }
    }

    return max;
}

/**
 * When traces are made, the datapoints are stored in an array. But the correlation
 * function above goes through every row for a specific index, thus not caching next
 * elements and being very slow.
 * By transposing the matrix for this use, the desired data would be sequentially
 * kept in cache, thus accessing memory much faster.
 * @param data
 * @return
 */
double** transpose_datapoint_matrix(container *data){

    uint32_t i, j;
    double **transpose = calloc((size_t)data->nb_datapoints, sizeof(double *));

    for ( i = 0 ; i < data-> nb_datapoints ; i++){
        transpose[i] = calloc((size_t)data->nb_probes, sizeof(double));
    }

    for ( i = 0 ; i < data->nb_datapoints ; i++){
        for( j = 0 ; j < data->nb_probes ; j++){
            transpose[i][j] = data->t_traces[j][i];
        }
    }

    return transpose;
}


/**
 * Applies precedent functions to get the pearson correlation coefficient for the given hamming weight vector
 * @param data
 * @param transpose_datapoints
 * @param hamming
 * @return
 */
double compute_highest_correlation_coefficient(container *data, double **transpose_datapoints, double *hamming){

    double *pearson_vector = compute_pearson_vector(data, transpose_datapoints, hamming);

    return get_max_correlation(pearson_vector, data->nb_datapoints);
}