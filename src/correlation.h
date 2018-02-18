//
// Created by dan on 17/02/18.
//

#ifndef SCA_CORRELATION_H
#define SCA_CORRELATION_H

#include <constants.h>

double* compute_pearson_vector(container *data, double **datapoints, double *hamming);

double get_max_correlation(double *pearson_vector, uint32_t size);


/**
 * When traces are made, the datapoints are stored in an array. But the correlation
 * function above goes through every row for a specific index, thus being very slow.
 * By transposing the matrix for this use, the desired data would be sequentially
 * kept in an array, thus executing the computation much faster.
 * @param data
 * @return
 */
double** transpose_datapoint_matrix(container *data);

/**
 * Applies precedent functions to get the pearson correlation coefficient for the given hamming weight vector
 * @param data
 * @param transpose_datapoints
 * @param hamming
 * @return
 */
double compute_highest_correlation_coefficient(container *data, double **transpose_datapoints, double *hamming);


#endif /*SCA_CORRELATION_H*/